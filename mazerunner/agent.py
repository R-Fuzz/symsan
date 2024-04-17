import copy
import logging
import math
import os
import collections
import pickle
import random

import model
from decimal import Decimal
from defs import TaintFlag
from utils import *

class ProgramState:
    def __init__(self, distance):
        self.state = (0,0,0)
        self.action = 0
        self.d = distance
        self.bid = 0

    @staticmethod
    def deserialize(s):
        state, action, d, bid = s
        ps = ProgramState(d)
        ps.state = state
        ps.action = action
        ps.bid = bid
        return ps

    @property
    def sa(self):
        return self.state + (self.action,)
    
    @property
    def reversed_sa(self):
        reversed_action = 1 if self.action == 0 else 0
        return self.state + (reversed_action, )
    
    def update(self, pc, callstack, bid, action, distance, counter):
        counter.update([(pc, callstack)])
        self.state = (pc, callstack, bucket_lookup(counter[(pc, callstack)]))
        self.action = action
        self.d = distance
        self.bid = bid
    
    def serialize(self):
        return (self.state, self.action, self.d, self.bid)


class RewardCalculator:
    def __init__(self, config, min_distance, trace, nested_cond_unsat_sas):
        self.config = config
        self.min_distance = min_distance
        self.trace = trace
        self.nested_cond_unsat_sas = nested_cond_unsat_sas

    def compute_reward(self, i):
        raise NotImplementedError("This method should be overridden by subclass")


class DistanceRewardCalculator(RewardCalculator):
    def __init__(self, config, min_distance, trace, nested_cond_unsat_sas):
        super().__init__(config, min_distance, trace, nested_cond_unsat_sas)
        self.local_min_indices = find_local_min([s.d for s in trace])

    def compute_reward(self, i):
        # Did not reach the target
        if i >= len(self.trace) and self.min_distance > 0:
                return -float('inf')
        d = self.trace[i].d
        # Reached the target
        if d == 0 or (i >= len(self.trace) and self.min_distance == 0):
            return self.config.max_distance
        # found local optimum
        if i in self.local_min_indices:
            return (1000 / d) * (1000 / d) * self.config.max_distance
        sa = self.trace[i].sa
        if sa in self.nested_cond_unsat_sas:
            return -d
        return 0


class ReachabilityRewardCalculator(RewardCalculator):
    def compute_reward(self, i):
        # Did not reach the target at the end
        if i >= len(self.trace) and self.min_distance > 0:
            return Decimal(0)
        d = self.trace[i].d
        # Reached the target
        if d == 0 or (i >= len(self.trace) and self.min_distance == 0):
            return Decimal(1)
        # Default reward
        return Decimal(0)

class MaxQLearner:
    def __init__(self, m: model.RLModel, df, lr):
        self.model = m
        self.discount_factor = df
        self.learning_rate = lr

    def learn(self, last_s, next_s, last_reward):
        last_Q = self.model.Q_lookup(last_s, last_s.action)
        last_distance = self.model.get_distance(last_s, last_s.action)
        # check for Terminal state
        if next_s.state == (0,0,0):
            updated_Q = last_Q + self.learning_rate * (last_reward - last_Q)
        else:
            curr_state_taken = self.model.Q_lookup(next_s, 1)
            curr_state_not_taken = self.model.Q_lookup(next_s, 0)
            if curr_state_taken >= curr_state_not_taken:
                chosen_Q = curr_state_taken
            else:
                chosen_Q = curr_state_not_taken
            updated_Q = (last_Q + self.learning_rate 
                * (last_reward + self.discount_factor * chosen_Q - last_Q))

        if math.isnan(updated_Q) or last_distance == float('inf'):
            if next_s.state == (0,0,0):
                last_Q = last_reward
            else:
                last_Q = (last_reward + self.discount_factor * chosen_Q) if not math.isnan(chosen_Q) else last_Q
        else:
            last_Q = updated_Q
        self.model.Q_update(last_s.sa, last_Q)

    def punish_state(self, reversed_state):
        terminal_state = ProgramState(distance=self.config.max_distance)
        self.learner.learn(reversed_state, terminal_state, -self.config.max_distance)

class AvgQLearner:
    def __init__(self, m: model.RLModel, df, lr):
        self.model = m
        self.discount_factor = df
        self.learning_rate = lr

    def learn(self, last_s, next_s, last_reward):
        last_Q = self.model.Q_lookup(last_s, last_s.action)
        last_distance = self.model.get_distance(last_s, last_s.action)
        # check for Terminal state
        if next_s.state == (0,0,0):
            updated_Q = last_Q + self.learning_rate * (last_reward - last_Q)
        else:
            curr_state_taken = self.model.Q_lookup(next_s, 1)
            curr_state_not_taken = self.model.Q_lookup(next_s, 0)
            avg_Q = (curr_state_taken + curr_state_not_taken) / 2
            updated_Q = last_Q + self.learning_rate * (self.discount_factor * avg_Q - last_Q)

        if math.isnan(updated_Q) or last_distance == float('inf'):
            if next_s.state == (0,0,0):
                last_Q = last_reward
            else:
                last_Q = avg_Q if not math.isnan(avg_Q) else last_Q
        else:
            last_Q = updated_Q
        self.model.Q_update(last_s.sa, last_Q)

    def punish_state(self, reversed_state):
        terminal_state = ProgramState(distance=self.config.max_distance)
        self.learner.learn(reversed_state, terminal_state, Decimal(0))

class Agent:
    def __init__(self, config):
        self.config = config
        # for fgtest compatibility
        if config.mazerunner_dir:
            self.my_dir = config.mazerunner_dir
            mkdir(self.my_traces)
        self.logger = logging.getLogger(self.__class__.__qualname__)
        # self.logger.setLevel(logging.DEBUG)
        self.episode = []
        self.nested_cond_unsat_sas = set()
        self.pc_counter = collections.Counter()
        self.min_distance = self.config.max_distance
        self._learner = None
        self._model = None

    @property
    def my_traces(self):
        return os.path.join(self.my_dir, "traces")

    @property
    def model(self):
        if not self._model:
            self._model = self.create_model(self.config)
        return self._model
    @model.setter
    def model(self, m):
        self._model = m
    def save_model(self):
        if self.config.mazerunner_dir and self._model:
            self._model.save()

    @property
    def learner(self):
        if self._learner:
            return self._learner
        self._learner = self.create_learner()
        return self._learner

    @staticmethod
    def create_model(config):
        if config.model_type == model.RLModelType.distance:
            return model.DistanceModel(config)
        elif config.model_type == model.RLModelType.reachability:
            return model.ReachabilityModel(config)
        else:
            raise NotImplementedError()

    def create_learner(self):
        lr = self.config.learning_rate
        df = self.config.discount_factor
        if self.config.model_type == model.RLModelType.distance:
            return MaxQLearner(self.model, df, lr)
        elif self.config.model_type == model.RLModelType.reachability:
            return AvgQLearner(self.model, Decimal(df), Decimal(lr))
        else:
            raise NotImplementedError()
    
    def create_reward_calculator(self):
        if self.config.model_type == model.RLModelType.distance:
            return DistanceRewardCalculator(self.config, self.min_distance, 
                                            self.episode, self.nested_cond_unsat_sas)
        elif self.config.model_type == model.RLModelType.reachability:
            return ReachabilityRewardCalculator(self.config, self.min_distance, 
                                                self.episode, self.nested_cond_unsat_sas)
        else:
            raise NotImplementedError()        

    def append_episode(self):
        is_state_in_small_bucket = self.curr_state.state[2] <= self.config.max_branch_num
        is_state_not_repeated = (len(self.episode) == 0 or self.episode[-1].sa != self.curr_state.sa)
        if is_state_in_small_bucket and is_state_not_repeated:
            self.episode.append(copy.copy(self.curr_state))
        if not is_state_in_small_bucket:
            # inherit the experience from the smaller state that has smaller branch number
            pc = self.curr_state.state[0]
            callstack = self.curr_state.state[1]
            inherited_state = (pc, callstack, bucket_lookup(self.config.max_branch_num))
            self.curr_state.state = inherited_state
        # self.debug_policy(self.curr_state)

    def reset(self):
        self.curr_state = ProgramState(distance=self.config.max_distance)
        self.episode.clear()
        self.pc_counter.clear()
        self.min_distance = self.config.max_distance

    def handle_new_state(self, msg, action, is_symbranch):
        pass
    
    def handle_unsat_condition(self, solving_status):
        pass

    def handle_nested_unsat_condition(self, state_deps):
        for s in state_deps:
            if s.sa == self.curr_state.sa or s.sa in self.nested_cond_unsat_sas:
                continue
            self.logger.debug(f"handle_nested_unsat_condition: {s.sa}")
            self.nested_cond_unsat_sas.add(s.sa)
        reversed_action = 1 if self.curr_state.action == 0 else 0
        reversed_state = copy.copy(self.curr_state)
        reversed_state.action = reversed_action
        self.learner.punish_state(reversed_state)

    def is_interesting_branch(self):
        return True
    
    def compute_branch_score(self):
        return ''

    def train(self):
        if not self.episode:
            self.logger.warning("No episode to train")
            return
        reward_calculator = self.create_reward_calculator()
        for i, s in enumerate(reversed(self.episode)):
            assert 0 <= self.min_distance <= s.d <= self.config.max_distance
            self.model.add_visited_sa(s.sa)
            i = len(self.episode) - i - 1
            if i >= len(self.episode) - 1:
                # the next state is terminal state
                next_s = ProgramState(distance=self.config.max_distance)
            else:
                next_s = self.episode[i+1]
            reward = reward_calculator.compute_reward(i+1)
            self.learner.learn(s, next_s, reward)
            self.logger.debug(f"SA: {s.sa}, "
                            f"reward: {reward}, "
                            f"d_static: {s.d if s.d else 'NA'}, "
                            f"d_dynamic: {self.model.get_distance(s, s.action)}")

    def replay_log(self, log_path):
        self.reset()
        d = get_distance_from_fn(log_path)
        d = self.config.max_distance if d is None else d
        self.min_distance = d
        with open(log_path, 'rb') as fd:
            self.episode = list(pickle.load(fd))
            self.train()

    def save_trace(self, fn):
        log_path = os.path.join(self.my_traces, fn)
        if os.path.exists(log_path):
            return
        with open(log_path, 'wb') as fd:
            pickle.dump(self.episode, fd, protocol=pickle.HIGHEST_PROTOCOL)

    def update_curr_state(self, msg, action):
        has_dist = True if msg.flags & TaintFlag.F_HAS_DISTANCE else False
        if has_dist:
            d = msg.local_min_dist
        else:
            d = self.curr_state.d
        self.min_distance = min([msg.global_min_dist, d, self.min_distance])
        assert 0 <= self.min_distance <= self.config.max_distance
        self.curr_state.update(msg.addr, msg.context, msg.id, action, d, self.pc_counter)

    def _make_dirs(self):
        mkdir(self.my_traces)

    def debug_policy(self, state):
        distance_taken = self.model.get_distance(state, 1)
        distance_not_taken = self.model.get_distance(state, 0)
        s = state.serialize()
        self.logger.info(f"sad={(s[0],s[1],s[2])}, "
                        f"hit_tn={self.model.visited_sa.get(state.sa, 0)}, "
                        f"d_t={distance_taken}, "
                        f"d_nt={distance_not_taken}, "
                        f"unreachale={state.reversed_sa in self.model.unreachable_sa}, "
                        f"trace_len={len(self.episode)}, "
                        f"min_d={self.min_distance}"
                        )


class RecordAgent(Agent):

    def handle_new_state(self, msg, action, is_symbranch):
        if is_symbranch:
            self.update_curr_state(msg, action)
            self.append_episode()

    def is_interesting_branch(self):
        return False


class ExploreAgent(Agent):

    def handle_new_state(self, msg, action, is_symbranch):
        if is_symbranch:
            self.update_curr_state(msg, action)
            self.model.remove_target_sa(self.curr_state.sa)
            self.append_episode()

    def is_interesting_branch(self):
        if self.curr_state.reversed_sa in self.model.unreachable_sa:
            return False
        if self.curr_state.reversed_sa in self.model.all_target_sa:
            return False
        interesting = self._greedy_policy()
        if interesting:
            self.model.add_target_sa(self.curr_state.reversed_sa)
            self.logger.debug(f"Target SA: {self.curr_state.reversed_sa}")
        return interesting

    def handle_unsat_condition(self, solving_status):
        self.model.remove_target_sa(self.curr_state.reversed_sa)
        if solving_status == solving_status.UNSOLVED_UNINTERESTING_SAT:
            return
        self.logger.debug(f"unreachable_sa={self.curr_state.reversed_sa}")
        self.model.add_unreachable_sa(self.curr_state.reversed_sa)

    def compute_branch_score(self):
        reversed_action = 1 if self.curr_state.action == 0 else 0
        d = self.model.get_distance(self.curr_state, reversed_action)
        return str(int(d))

    def _greedy_policy(self):
        d_curr = self.model.get_distance(self.curr_state, self.curr_state.action)
        reversed_action = 1 if self.curr_state.action == 0 else 0
        d_reverse = self.model.get_distance(self.curr_state, reversed_action)
        if d_curr > d_reverse:
            return True
        elif d_curr < d_reverse:
            return False
        if d_reverse == float('inf'):
            return False
        return self._curious_policy()

    def _curious_policy(self):
        return self.curr_state.reversed_sa not in self.model.visited_sa

class ExploitAgent(Agent):

    def __init__(self, config):
        super().__init__(config)
        self.all_targets = []
        self.target = (None, 0) # sa, trace_length

    def handle_new_state(self, msg, action, is_symbranch):
        if is_symbranch:
            self.update_curr_state(msg, action)
            self.append_episode()
            if self.curr_state.sa == self.target[0]:
                self.logger.debug(f"Target reached. sa={self.target[0]}, trace_length={self.target[1]}")
                self.target = (None, 0) # sa, trace_length
    
    def clear_targets(self):
        self.target = (None, 0)
        self.all_targets.clear()

    def is_interesting_branch(self):
        if self.target[0]:
            return False
        if self.curr_state.reversed_sa in self.model.unreachable_sa:
            return False
        interesting = self._greedy_policy() != self.curr_state.action
        if interesting:
            self.all_targets.append(self.curr_state.reversed_sa)
            self.target = (self.curr_state.reversed_sa, len(self.episode))
            self.logger.debug(f"target_sa={self.curr_state.reversed_sa}, trace_length={len(self.episode)}")
        return interesting

    def handle_unsat_condition(self, solving_status):
        self.logger.warning(f"handle_unsat_condition: unreachable_sa={self.target[0]}")
        self.target = (None, 0)
        self.all_targets.pop()
        if solving_status == solving_status.UNSOLVED_UNINTERESTING_SAT:
            return
        self.model.add_unreachable_sa(self.target[0])

    def _greedy_policy(self):
        d_taken = self.model.get_distance(self.curr_state, 1)
        d_not_taken = self.model.get_distance(self.curr_state, 0)
        if d_taken == float('inf') and d_not_taken == float('inf'):
            return self.curr_state.action
        if d_taken > d_not_taken:
            return 0
        elif d_taken < d_not_taken:
            return 1
        else:
            return self.curr_state.action

    # Return whether the agent should visit the filpped branch.
    def _epsilon_greedy_policy(self):
        epsilon = self.config.explore_rate
        if (self.curr_state.reversed_sa not in self.model.visited_sa
            and random.random() < epsilon):
            return True
        if (self.curr_state.reversed_sa in self.model.visited_sa
            and random.random() < (epsilon ** self.model.visited_sa[self.curr_state.reversed_sa])):
            return True
        if self._greedy_policy() != self.curr_state.action:
            return True
        else:
            return False
    
    def _weighted_probabilistic_policy(self):
        d_taken = self.model.get_distance(self.curr_state, 1)
        d_not_taken = self.model.get_distance(self.curr_state, 0)
        total = d_taken + d_not_taken
        p = random.random()
        if p < d_taken / total:
            return 1
        elif p < d_not_taken / total:
            return 0
        else:
            return self.curr_state.action

