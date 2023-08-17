import collections
import os
import pickle

from utils import mkdir

class RLModel:
    def __init__(self, config):
        self.config = config
        self.visited_sa = collections.Counter()
        self.all_target_sa = set()
        self.unreachable_sa = set()
        self.Q_table = {}
        if config.mazerunner_dir:
            mkdir(self.my_dir)
            self.load()

    @property
    def my_dir(self):
        return os.path.join(self.config.mazerunner_dir, "model")

    def save(self):
        with open(os.path.join(self.my_dir, "visited_sa"), 'wb') as fp:
            pickle.dump(self.visited_sa, fp, protocol=pickle.HIGHEST_PROTOCOL)
        with open(os.path.join(self.my_dir, "Q_table"), 'wb') as fp:
            pickle.dump(self.Q_table, fp, protocol=pickle.HIGHEST_PROTOCOL)  
        with open(os.path.join(self.my_dir, "unreachable_branches"), 'wb') as fp:
            pickle.dump(self.unreachable_sa, fp, protocol=pickle.HIGHEST_PROTOCOL)
        with open(os.path.join(self.my_dir, "target_sa"), 'wb') as fp:
            pickle.dump(self.all_target_sa, fp, protocol=pickle.HIGHEST_PROTOCOL)
    
    def load(self):
        visited_sa_path = os.path.join(self.my_dir, "visited_sa")
        if os.path.isfile(visited_sa_path):
            with open(visited_sa_path, 'rb') as fp:
                self.visited_sa = pickle.load(fp)
        Q_table_path = os.path.join(self.my_dir, "Q_table")
        if os.path.isfile(Q_table_path):
            with open(Q_table_path, 'rb') as fp:
                self.Q_table = pickle.load(fp)
        unreachable_branches_path = os.path.join(self.my_dir, "unreachable_sa")
        if os.path.isfile(unreachable_branches_path):
            with open(unreachable_branches_path, 'rb') as fp:
                self.unreachable_sa = pickle.load(fp)
        target_sa_path = os.path.join(self.my_dir, "target_sa")
        if os.path.isfile(target_sa_path):
            with open(target_sa_path, 'rb') as fp:
                self.all_target_sa = pickle.load(fp)

    def Q_lookup(self, key):
        return self.Q_table.get(key, 0.)
    
    def Q_update(self, key, value):
        if value != 0.:
            self.Q_table[key] = value

    def add_unreachable_sa(self, sa):
        self.unreachable_sa.add(sa)

    def add_visited_sa(self, sa):
        self.visited_sa.update([sa])
    
    def add_target_sa(self, sa):
        self.all_target_sa.add(sa)
    
    def remove_target_sa(self, sa):
        if sa in self.all_target_sa:
            self.all_target_sa.remove(sa)
