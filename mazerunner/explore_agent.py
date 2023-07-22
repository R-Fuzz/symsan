import atexit

from agent import *
from learner import BasicQLearner

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
