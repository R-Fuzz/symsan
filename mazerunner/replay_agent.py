import os
import pickle

from agent import *
from learner import BasicQLearner

class ReplayAgent(Agent):

    def __init__(self, config: Config, model: RLModel, output_dir: str):
        super().__init__(config, model, output_dir)
        # TODO: remove assertion after testing
        assert model is not None
        assert output_dir is not None
        self.model = model
        self.learner = BasicQLearner(model.Q_table, config.discount_factor, config.learning_rate)

    def replay_log(self, log_dir):
        seed_traces = os.listdir(log_dir)
        for t in seed_traces:
            print(f'processing {t}', end='\r')
            f = os.path.join(log_dir, t)
            with open(f, 'rb') as fd:
                trace = list(pickle.load(fd))
                self.replay_trace(trace)

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
