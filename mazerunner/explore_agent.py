import atexit

from agent import *
from defs import TaintFlag
from learner import BasicQLearner
from model import RLModel

class ExploreAgent(Agent):

    def __init__(self, config: Config):
        super().__init__(config)
        # TODO: remove assertion after testing
        assert config.mazerunner_dir is not None
        self.model = RLModel(config)
        self.model.load()
        self.learner = BasicQLearner(self.model.Q_table, config.discount_factor, config.learning_rate)
        atexit.register(self.model.save)

    def handle_new_state(self, msg, action):
        tmp = self.last_state 
        self.last_state = self.curr_state
        self.curr_state = tmp if tmp else ProgramState(distance=self.max_distance)
        has_dist = True if msg.flags & TaintFlag.F_HAS_DISTANCE else False
        if has_dist:
            d = msg.avg_dist
        else:
            d = self.max_distance
        if d < self.min_distance:
            self.min_distance = d
        self.curr_state.update(msg.addr, msg.context, action, d)
        curr_sa = self.curr_state.state + (self.curr_state.action, )
        self.model.visited_sa.add(curr_sa)
        self._learn(has_dist)

    def is_interesting_branch(self):
        reversed_action = 1 if self.curr_state.action == 0 else 0
        reversed_sa = self.curr_state.state + (reversed_action, )
        return reversed_sa not in self.model.visited_sa
