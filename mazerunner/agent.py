#!/usr/bin/env python3

import collections
import logging

import q_learning
from config import *

class ProgramState:
    def __init__(self):
        self.loopinfo = collections.defaultdict(int)
        self.pc = 0
        self.callstack = 0
        self.action = 0
        self.last_d = MAX_DISTANCE

    def handle_loop_exit(self, loop_header):
        if loop_header in self.loop:
            self.loop[loop_header] = 0
    
    def handle_loop_entry(self, loop_header):
        self.loop[loop_header] += 1
        
class Agent:
    def __init__(self):
        self.state = ProgramState()
        self.history_actions = []
        self.learner = q_learning.QLearner()
        self.logger = logging.getLogger('mazerunner.agent')

    def compute_reward(self, d, has_dist):
        reward = 0
        if not has_dist or d >= MAX_DISTANCE or d < 0:
            return reward
        else:
            reward = self.state.last_d - d
        self.state.last_d = d
        return reward

    def offline_learn(self, pc, callstack, action, distance, has_dist):
        last_sa = (self.state.pc, self.state.callstack, self.state.action)
        next_s = (pc, callstack)
        reward = self.compute_reward(distance, has_dist)
        if last_sa:
            self.learner.learn(last_sa, next_s, reward)
            distance = distance if has_dist else "NA"
            self.logger.info(f"last_SA: {last_sa}, distance: {distance}, reward: {reward}, Q: {self.learner.Q_table[last_sa]}")
        self.state.pc = pc
        self.state.callstack = callstack
        self.state.action = action
    
    def decide_action(self):
        pass