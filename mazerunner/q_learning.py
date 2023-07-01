#!/usr/bin/env python3

import collections
# import logging

class QLearner:
    def __init__(self):
        self.Q_table = collections.defaultdict(float)
        # self.logger = logging.getLogger(self.__class__.__qualname__)

    def learn(self, last_SA, next_s, last_reward):
        last_Q = self.Q_table[last_SA]
        curr_state_taken = self.Q_table[next_s+(1,)]
        curr_state_not_taken = self.Q_table[next_s +(0,)]
        if curr_state_taken >= curr_state_not_taken:
            last_Q = last_Q + 0.5 * (last_reward + 1 * curr_state_taken - last_Q)
        else:
            last_Q = last_Q + 0.5 * (last_reward + 1 * curr_state_not_taken - last_Q)
        self.Q_table[last_SA] = last_Q
