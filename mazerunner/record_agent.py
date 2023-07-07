import pickle
from agent import *

class RecordAgent(Agent):

    def handle_new_state(self, msg, action):
        d = msg.avg_dist
        self.curr_state.update(msg.addr, msg.context, action, d)
        self.episode.append(self.curr_state.serialize())

    def save_trace(self, log_path):
        with open(log_path, 'wb') as fd:
            pickle.dump(self.episode, fd)

    def is_interesting_branch(self):
        return False
