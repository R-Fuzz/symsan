from agent import *

class RecordAgent(Agent):

    def handle_new_state(self, msg, action):
        d = msg.avg_dist
        self.curr_state.update(msg.addr, msg.context, action, d)
        self.episode.append(self.curr_state.serialize())

    def is_interesting_branch(self):
        return False
