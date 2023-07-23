import atexit
import logging
import os
import pickle
import subprocess
import utils
import random

from config import Config
from defs import TaintFlag
from model import RLModel
from utils import mkdir
from learner import BasicQLearner

class ProgramState:
    def __init__(self, distance, pc=0, callstack=0, action=0, loop_counter=0):
        self.state = (pc, callstack, loop_counter)
        self.action = action
        self.d = distance
    
    def update(self, pc, callstack, action, distance):
        self.state = (pc, callstack, self.state[2])
        self.action = action
        self.d = distance

    def serialize(self):
        return (self.state, self.action, self.d)
    
    def compute_reversed_sa(self):
        reversed_action = 1 if self.action == 0 else 0
        return self.state + (reversed_action, )

class Agent:
    def __init__(self, config: Config):
        if config.mazerunner_dir:
            self.my_dir = config.mazerunner_dir
            mkdir(self.my_traces)
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.max_distance = config.max_distance
        self.loopinfo = {}
        self.episode = []

    @property
    def my_traces(self):
        return os.path.join(self.my_dir, "traces")

    def reset(self):
        self.curr_state = ProgramState(distance=self.max_distance)
        self.episode.clear()
        self.min_distance = self.max_distance

    # for fgtest
    def handle_new_state(self, msg, action):
        pass

    # for fgtest
    def is_interesting_branch(self):
        return True

    def mark_sa_unreachable(self, sa):
        self.model.add_unreachable_sa(sa)

    def save_trace(self, log_path):
        with open(log_path, 'wb') as fd:
            pickle.dump(self.episode, fd, protocol=pickle.HIGHEST_PROTOCOL)

    def replay_trace(self, trace):
        last_SA = None
        last_reward = 0
        last_d = self.max_distance
        for (next_s, a, d) in trace:
            next_sa = next_s + (a,)
            reward = self._compute_reward(d, last_d)
            if last_SA:
                self.learner.learn(last_SA, next_s, last_reward)
            last_d = d
            last_SA = next_sa
            last_reward = reward

    def learn(self, last_state):
        if last_state:
            last_sa = last_state.state + (last_state.action, )
            reward = self._compute_reward(self.curr_state.d, last_state.d)
            self.learner.learn(last_sa, self.curr_state.state, reward)
            self.logger.debug(f"last_SA: {last_sa}, "
                              f"distance: {self.curr_state.d if self.curr_state.d else 'NA'}, "
                              f"reward: {reward}, "
                              f"Q: {self.model.Q_lookup(last_sa)}")
    
    def update_curr_state(self, msg, action):
        self.curr_state = ProgramState(distance=self.max_distance)
        has_dist = True if msg.flags & TaintFlag.F_HAS_DISTANCE else False
        if has_dist:
            d = msg.avg_dist
        else:
            d = None
        if d and d < self.min_distance:
            self.min_distance = d
        self.curr_state.update(msg.addr, msg.context, action, d)
        curr_sa = self.curr_state.state + (self.curr_state.action, )
        self.model.visited_sa.add(curr_sa)

    def _make_dirs(self):
        utils.mkdir(self.my_traces)

    def _compute_reward(self, d, last_d):
        reward = 0
        if d and last_d:
            assert (d <= self.max_distance and
                    d >= 0 and
                    last_d <= self.max_distance and
                    last_d >= 0)
            reward = last_d - d
        return reward

    def _import_loop_info(self):
        path = os.path.join(self.my_dir, "loops")
        if not os.path.isfile(path):
            program = self.cmd[0]
            loop_finder = os.path.join(os.path.dirname(__file__), 'static_anlysis.py')
            # run angr in a separate process as it overwrites logging configs
            completed_process = subprocess.run([loop_finder, program, path], stdout=subprocess.DEVNULL)
            if completed_process.returncode != 0:
                raise RuntimeError("failed to run %s" % loop_finder)
        with open(path, 'rb') as fp:
            self._loop_info = pickle.load(fp)

class RecordAgent(Agent):

    def handle_new_state(self, msg, action):
        d = msg.avg_dist
        self.curr_state.update(msg.addr, msg.context, action, d)
        self.episode.append(self.curr_state.serialize())

    def is_interesting_branch(self):
        return False

class ReplayAgent(Agent):

    def __init__(self, config: Config):
        super().__init__(config)
        # TODO: remove assertion after testing
        assert config.mazerunner_dir is not None
        self.model = RLModel(config)
        self.model.load()
        atexit.register(self.model.save)
        self.learner = BasicQLearner(self.model, config.discount_factor, config.learning_rate)

    def replay_log(self, log_dir):
        seed_traces = os.listdir(log_dir)
        for t in seed_traces:
            print(f'processing {t}', end='\r')
            f = os.path.join(log_dir, t)
            with open(f, 'rb') as fd:
                trace = list(pickle.load(fd))
                self.replay_trace(trace)

class ExploreAgent(Agent):

    def __init__(self, config: Config):
        super().__init__(config)
        # TODO: remove assertion after testing
        assert config.mazerunner_dir is not None
        self.model = RLModel(config)
        self.model.load()
        atexit.register(self.model.save)
        self.learner = BasicQLearner(self.model, config.discount_factor, config.learning_rate)

    def handle_new_state(self, msg, action):
        last_state = self.curr_state
        self.update_curr_state(msg, action)
        self.learn(last_state)

    def is_interesting_branch(self):
        reversed_sa = self.curr_state.compute_reversed_sa()
        # TODO: check if target SA can be reached (testcase, target) + target_sa set
        if reversed_sa in self.model.unreachable_sa:
            return False
        return reversed_sa not in self.model.visited_sa

class ExploitAgent(Agent):

    def __init__(self, config: Config):
        super().__init__(config)
        # TODO: remove assertion after testing
        assert config.mazerunner_dir is not None
        self.model = RLModel(config)
        self.model.load()
        atexit.register(self.model.save)
        self.target_sa = None
        self.learner = BasicQLearner(self.model, config.discount_factor, config.learning_rate)
        self.epsilon = config.explore_rate

    def handle_new_state(self, msg, action):
        self.update_curr_state(msg, action)
        self.episode.append(self.curr_state.serialize())
        curr_sa = self.curr_state.state + (self.curr_state.action, )
        if curr_sa == self.target_sa:
            self.target_sa = None
        if not self.target_sa:
            self.logger.debug(self.curr_state.serialize())

    def is_interesting_branch(self):
        if self.target_sa:
            return False
        reversed_sa = self.curr_state.compute_reversed_sa()
        if reversed_sa in self.model.unreachable_sa:
            self.logger.debug(f"not interested, unreachable sa {reversed_sa}")
            return False
        curr_sa = self.curr_state.state + (self.curr_state.action, )
        if (reversed_sa not in self.model.visited_sa
            and curr_sa not in self.model.visited_sa):
            self.logger.debug(f"not interested, unvisited state")
            return False
        return self.__epsilon_greedy_policy(reversed_sa)

    # Return whether the agent should visit the filpped branch.
    def __epsilon_greedy_policy(self, reversed_sa):
        if (reversed_sa not in self.model.visited_sa
            and random.random() < self.epsilon):
            return True
        if self.__greedy_policy() == self.curr_state.action:
            self.logger.debug(f"not interested, greedy policy")
            return False
        else:
            return True

    # Returns the greedy action according to the Q value.
    def __greedy_policy(self):
        curr_state_taken = self.model.Q_lookup(self.curr_state.state +(1,))
        curr_state_not_taken = self.model.Q_lookup(self.curr_state.state +(0,))
        if curr_state_taken > curr_state_not_taken:
            return 1
        elif curr_state_taken < curr_state_not_taken:
            return 0
        else:
            return self.curr_state.action
