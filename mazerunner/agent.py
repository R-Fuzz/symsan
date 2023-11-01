import logging
import os
import collections
import pickle
import random

import model
from decimal import Decimal
from defs import TaintFlag
from utils import mkdir, bucket_lookup, MAX_BUCKET_SIZE, get_distance_from_fn

class ProgramState:
    def __init__(self, distance):
        self.state = (0,0,0)
        self.action = 0
        self.d = distance
        self.pc_counter = collections.Counter()
    
    def update(self, pc, callstack, action, distance):
        self.pc_counter.update([(pc, callstack)])
        self.state = (pc, callstack, bucket_lookup(self.pc_counter[(pc, callstack)]))
        self.action = action
        self.d = distance

    def serialize(self):
        return (self.state, self.action, self.d)
    
    def compute_reversed_sa(self):
        reversed_action = 1 if self.action == 0 else 0
        return self.state + (reversed_action, )

class BasicQLearner:
    def __init__(self, m: model.RLModel, df, lr):
        self.model = m
        self.discount_factor = df
        self.learning_rate = lr

    def learn(self, last_SA, next_s, last_reward):
        last_Q = self.model.Q_lookup(last_SA)
        curr_state_taken = self.model.Q_lookup(next_s + (1,))
        curr_state_not_taken = self.model.Q_lookup(next_s + (0,))
        if curr_state_taken >= curr_state_not_taken:
            chosen_Q = curr_state_taken
        else:
            chosen_Q = curr_state_not_taken
        if next_s == ("Terminal",):
            last_Q = last_Q + self.learning_rate * (last_reward - last_Q)
        else:
            last_Q = (last_Q + self.learning_rate 
                * (last_reward + self.discount_factor * chosen_Q - last_Q))
        self.model.Q_update(last_SA, last_Q)


class Agent:
    def __init__(self, config):
        self.config = config
        if config.mazerunner_dir:
            self.my_dir = config.mazerunner_dir
            mkdir(self.my_traces)
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.episode = []
        self._learner = None
        self._model = None

    @property
    def my_traces(self):
        return os.path.join(self.my_dir, "traces")

    @property
    def model(self):
        if not self._model:
            self._model = Agent.create_model(self.config)
        return self._model
    @model.setter
    def model(self, m):
        self._model = m
    def save_model(self):
        if self.config.mazerunner_dir and self._model:
            self._model.save()

    @property
    def learner(self):
        if not self._learner:
            lr = self.config.learning_rate
            df = self.config.discount_factor
            if self.config.model_type == model.RLModelType.reachability:
                lr = Decimal(self.config.learning_rate)
                df = Decimal(self.config.discount_factor)
            self._learner = BasicQLearner(self.model, df, lr)
        return self._learner

    @staticmethod
    def create_model(config):
        if config.model_type == model.RLModelType.distance:
            return model.DistanceModel(config)
        elif config.model_type == model.RLModelType.reachability:
            return model.ReachabilityModel(config)
        else:
            raise NotImplementedError()

    def append_episode(self):
        if self.curr_state.state[2] < MAX_BUCKET_SIZE:
            self.episode.append(self.curr_state.serialize())

    def reset(self):
        self.curr_state = ProgramState(distance=self.config.max_distance)
        self.episode.clear()
        self.min_distance = self.config.max_distance

    # for fgtest
    def handle_new_state(self, msg, action):
        pass
    
    def handle_unsat_condition(self):
        pass

    # for fgtest
    def is_interesting_branch(self):
        return True

    def replay_trace(self, trace):
        assert 0 <= self.min_distance <= self.config.max_distance
        reward_calculator = self.model.create_reward_calculator(self.config, trace, self.min_distance)
        for i, (s, a, d) in enumerate(reversed(trace)):
            sa = s + (a,)
            self.model.add_visited_sa(sa)
            i = len(trace) - i - 1
            if i >= len(trace) - 1:
                next_s = ("Terminal",)
            else:
                next_s = trace[i+1][0]
            reward = reward_calculator.compute_reward(i+1)
            self.learner.learn(sa, next_s, reward)
            self.logger.debug(f"SA: {sa}, "
                            f"distance: {d if d else 'NA'}, "
                            f"reward: {reward}, "
                            f"d_sa: {self.model.get_distance(sa)}")

    def replay_log(self, log_path):
        self.reset()
        d = get_distance_from_fn(log_path)
        d = self.config.max_distance if d is None else d
        self.min_distance = d
        with open(log_path, 'rb') as fd:
            trace = list(pickle.load(fd))
            self.replay_trace(trace)

    def save_trace(self, fn):
        log_path = os.path.join(self.my_traces, fn)
        with open(log_path, 'wb') as fd:
            pickle.dump(self.episode, fd, protocol=pickle.HIGHEST_PROTOCOL)

    def update_curr_state(self, msg, action):
        has_dist = True if msg.flags & TaintFlag.F_HAS_DISTANCE else False
        if has_dist:
            d = float(msg.local_min_dist)
        else:
            # msg.local_min_dist is zero, assign the last distance available
            d = self.curr_state.d
        self.min_distance = float(msg.global_min_dist)
        assert (self.min_distance <= d <= self.config.max_distance)
        self.curr_state.update(msg.addr, msg.context, action, d)
        self.logger.debug(f"SA: {(msg.addr, msg.context, action)}, "
                        f"distance: {d if d else 'NA'}, "
                        f"min_distance: {self.min_distance} ")

    def _make_dirs(self):
        mkdir(self.my_traces)


class RecordAgent(Agent):

    def handle_new_state(self, msg, action):
        self.update_curr_state(msg, action)
        self.append_episode()

    def is_interesting_branch(self):
        return False


class ExploreAgent(Agent):

    def handle_new_state(self, msg, action):
        self.update_curr_state(msg, action)
        curr_sa = self.curr_state.state + (self.curr_state.action, )
        self.model.remove_target_sa(curr_sa)
        self.append_episode()

    def is_interesting_branch(self):
        reversed_sa = self.curr_state.compute_reversed_sa()
        if reversed_sa in self.model.unreachable_sa:
            return False
        if reversed_sa in self.model.all_target_sa:
            return False
        interesting = self._curious_policy(reversed_sa)
        if interesting:
            self.model.add_target_sa(reversed_sa)
        return interesting

    def _curious_policy(self, sa):
        return sa not in self.model.visited_sa

class ExploitAgent(Agent):

    def __init__(self, config):
        super().__init__(config)
        self.all_targets = []
        self.last_targets = []
        self.epsilon = config.explore_rate
        self.target = (None, 0) # sa, trace_length

    def handle_new_state(self, msg, action):
        self.update_curr_state(msg, action)
        self.append_episode()
        curr_sa = self.curr_state.state + (self.curr_state.action, )
        if curr_sa == self.target[0] and len(self.episode) == self.target[1]:
            self.target = (None, 0) # sa, trace_length

    def is_interesting_branch(self):
        if self.target[0]:
            return False
        reversed_sa = self.curr_state.compute_reversed_sa()
        if reversed_sa in self.model.unreachable_sa:
            self.logger.debug(f"not interesting, unreachable sa {reversed_sa}")
            return False
        interesting = self._greedy_policy() != self.curr_state.action
        if interesting:
            self.all_targets.append(reversed_sa)
            self.target = (reversed_sa, len(self.episode))
            self.logger.debug(f"Abort and restart. Target SA: {reversed_sa}")
        return interesting

    def handle_unsat_condition(self):
        self.model.add_unreachable_sa(self.target[0])
        self.target = (None, 0)

    # Return whether the agent should visit the filpped branch.
    def _epsilon_greedy_policy(self, reversed_sa):
        if (reversed_sa not in self.model.visited_sa
            and random.random() < self.epsilon):
            self.logger.debug(f"interesting, epsilon-greedy policy")
            return True
        if (reversed_sa in self.model.visited_sa
            and random.random() < (self.epsilon ** self.model.visited_sa[reversed_sa])):
            self.logger.debug(f"interesting, epsilon-greedy policy")
            return True
        if self._greedy_policy() != self.curr_state.action:
            self.logger.debug(f"interesting, greedy policy")
            return True
        else:
            self.logger.debug(f"not interesting, greedy policy")
            return False

    # Returns the greedy action according to the Q value.
    def _greedy_policy(self):
        d_taken = self.model.get_distance(self.curr_state.state + (1,))
        d_not_taken = self.model.get_distance(self.curr_state.state + (0,))
        if d_taken > d_not_taken:
            return 0
        elif d_taken < d_not_taken:
            return 1
        else:
            return self.curr_state.action
    
    def _weighted_probabilistic_policy(self):
        d_taken = self.model.get_distance(self.curr_state.state + (1,))
        d_not_taken = self.model.get_distance(self.curr_state.state + (0,))
        total = d_taken + d_not_taken
        p = random.random()
        if p < d_taken / total:
            return 1
        elif p < d_not_taken / total:
            return 0
        else:
            return self.curr_state.action

    def __debug_policy(self):
        distance_taken = self.model.get_distance(self.curr_state.state + (1,))
        distance_not_taken = self.model.get_distance(self.curr_state.state + (0,))
        self.logger.info(f"curr_sad={self.curr_state.serialize()}, "
                        f"visited_times={self.model.visited_sa.get(self.curr_state.state + (self.curr_state.action,), 0)}, "
                        f"distance_taken={distance_taken}, "
                        f"distance_not_taken={distance_not_taken}, ")
