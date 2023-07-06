import collections
import logging

import q_learning

class ProgramState:
    def __init__(self):
        self.state = (0, 0, 0) # (pc, callstack, loop_counter)
        self.action = 0
        self.d = self.config.max_distance
    
    def __init__(self, pc, callstack, action, loop_counter, distance):
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
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.logger.setLevel(config.logging_level)
        # RL related fields
        self.last_state = None
        self.curr_state = ProgramState()
        self.episode = [] # we don't need to record every state with q_learner
        self.learner = q_learning.QLearner()

    def compute_reward(self, d, has_dist):
        reward = 0
        if not has_dist or d >= self.config.max_distance or d < 0:
            return reward
        else:
            reward = self.last_state.d - d
        self.last_state.d = d
        return reward

    def handle_new_state(self, state_msg, action):
        pass

    def is_interesting_branch(self):
        return True

    def learn(self, new_state, distance, has_dist):
        last_sa = self.last_state + (self.last_state.action, )
        reward = self.compute_reward(distance, has_dist)
        if last_sa:
            self.learner.learn(last_sa, new_state, reward)
            distance = distance if has_dist else "NA"
            self.logger.info(f"last_SA: {last_sa}, distance: {distance}, reward: {reward}, Q: {self.learner.Q_table[last_sa]}")
        self.last_state.update(new_state.pc, new_state.callstack, new_state.action, new_state.distance)
