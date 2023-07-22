import atexit
import os
import pickle

from agent import *
from learner import BasicQLearner

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
