import logging

from defs import OperationUnsupportedError
from config import Config
import q_learning

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

class RLModel:
    def __init__(self, config: Config):
        self.config = config
        self.visited_sa = set()
        self.Q_table = {}
        
    # TODO: implement save/load model
    def save_model(self, path=None):
        raise OperationUnsupportedError("save_model() not implemented")
    
    def load_model(self, path=None):
        raise OperationUnsupportedError("load_model() not implemented")

class Agent:
    def __init__(self, config: Config, model: RLModel):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.logger.setLevel(config.logging_level)
        # RL related fields
        self.last_state = None
        self.curr_state = ProgramState(distance=config.max_distance)
        self.episode = []
        self.visited = model.visited_sa
        self.learner = q_learning.BasicQLearner(model.Q_table, config.discount_factor, config.learning_rate)

    def handle_new_state(self, msg, action):
        pass

    def is_interesting_branch(self):
        return True

    def _compute_reward(self, has_dist):
        reward = 0
        if not has_dist or self.curr_state.d > self.config.max_distance or self.curr_state.d < 0:
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
