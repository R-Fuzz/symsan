import logging
import os
import pickle
import subprocess
import utils

from config import Config
from model import RLModel
from utils import mkdir

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

class Agent:
    def __init__(self, config: Config, model: RLModel=None):
        if config.mazerunner_dir:
            self.my_dir = config.mazerunner_dir
            mkdir(self.my_traces)
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.max_distance = config.max_distance
        self.loopinfo = {}
        # RL related fields
        self.last_state = None
        self.curr_state = ProgramState(distance=config.max_distance)
        self.episode = []

    @property
    def my_traces(self):
        return os.path.join(self.my_dir, "traces")

    def _make_dirs(self):
        utils.mkdir(self.my_traces)

    def handle_new_state(self, msg, action):
        pass

    def is_interesting_branch(self):
        return True

    def save_trace(self, log_path):
        with open(log_path, 'wb') as fd:
            pickle.dump(self.episode, fd, protocol=pickle.HIGHEST_PROTOCOL)

    def _compute_reward(self, has_dist):
        reward = 0
        if not has_dist or self.curr_state.d > self.max_distance or self.curr_state.d < 0:
            return reward
        else:
            reward = self.last_state.d - self.curr_state.d
        return reward

    def _learn(self, has_dist):
        if self.last_state:
            last_sa = self.last_state.state + (self.last_state.action, )
            reward = self._compute_reward(has_dist)
            self.learner.learn(last_sa, self.curr_state.state, reward)
            self.logger.debug(f"last_SA: {last_sa}, "
                              f"distance: {self.curr_state.d if has_dist else 'NA'}, "
                              f"reward: {reward}, "
                              f"Q: {self.learner.Q_lookup(last_sa)}")

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
