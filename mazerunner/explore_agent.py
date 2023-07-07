from agent import *
from defs import *

class ExploreAgent(Agent):

    def handle_new_state(self, msg, action):
        tmp = self.last_state 
        self.last_state = self.curr_state
        self.curr_state = tmp if tmp else ProgramState(distance=self.config.max_distance)
        has_dist = True if msg.flags & TaintFlag.F_HAS_DISTANCE else False
        if has_dist:
            d = msg.avg_dist
        else:
            d = self.config.max_distance
        self.curr_state.update(msg.addr, msg.context, action, d)
        curr_sa = self.curr_state.state + (self.curr_state.action, )
        self.visited.add(curr_sa)
        self._learn(has_dist)
        if self.config.trace_logging_enabled:
            self.episode.append(self.curr_state.serialize())

    def is_interesting_branch(self):
        reversed_action = 1 if self.curr_state.action == 0 else 0
        reversed_sa = self.curr_state.state + (reversed_action, )
        return reversed_sa not in self.visited
