#!/usr/bin/env python3

import os
import pickle
from agent import *

class ReplayAgent(Agent):
    # def __init__(self):
    #     super().__init__()

    def replay_log(self, log_dir):
        seed_traces = os.listdir(log_dir)
        for t in seed_traces:
            print(f'processing {t}', end='\r')
            f = os.path.join(log_dir, t)
            with open(f, 'rb') as fd:
                trace = list(pickle.load(fd))
                self.replay_trace(trace)

    def replay_trace(self, trace):
        last_SA = 0
        last_reward = 0
        last_d = MAX_DISTANCE
        for (next_s, a, d) in trace:
            next_sa = next_s + (a,)
            reward = self.compute_reward(d, last_d)
            if last_SA:
                self.learner.learn(last_SA, next_s, last_reward)
            last_d = d
            last_SA = next_sa
            last_reward = reward