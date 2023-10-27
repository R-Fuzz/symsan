import collections
import os
import pickle

from decimal import Decimal, getcontext
from enum import Enum
from utils import mkdir

class RLModelType(Enum):
    unknown = 0
    distance = 1
    reachability = 2


class RLModel:

    def __init__(self, config):
        self.config = config
        getcontext().prec = config.decimal_precision
        self.default_q = self.config.max_distance / 2
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

    def get_distance(self, key):
        if key not in self.Q_table:
            value = self.config.initial_policy.get((key[0], key[-1]), None)
            value = self.default_q if value is None else value
        else:
            value = self.Q_table[key]
        return float(value)

    def add_unreachable_sa(self, sa):
        self.unreachable_sa.add(sa)

    def add_visited_sa(self, sa):
        self.visited_sa.update([sa])
    
    def add_target_sa(self, sa):
        self.all_target_sa.add(sa)
    
    def remove_target_sa(self, sa):
        if sa in self.all_target_sa:
            self.all_target_sa.remove(sa)


class DistanceModel(RLModel):
    def Q_lookup(self, key):
        return self.get_distance(key)

    def Q_update(self, key, value):
        if value >= self.config.max_distance:
            self.Q_table[key] = self.config.max_distance
            return
        if value <= 0:
            self.Q_table[key] = 0.
            return
        self.Q_table[key] = value


class ReachabilityModel(RLModel):
    # Constants
    ZERO = Decimal(0)
    ONE = Decimal(1)
    TWO = Decimal(2)

    @staticmethod
    def distance_to_prob(d):
        """
        Converts a distance to a probability.
        Returns: 1 / 2 ** (d / 1000)
        """
        if d == -1.:
            return ReachabilityModel.ZERO
        return ReachabilityModel.ONE / (ReachabilityModel.TWO ** Decimal(float(d) / 1000))

    @staticmethod
    def prob_to_distance(p):
        """
        Converts a probability to a distance.
        Returns: -log_2(p) * 1000
        """
        if p == ReachabilityModel.ZERO:
            return -1.
        res = - (p.ln() / ReachabilityModel.TWO.ln())
        return float(res) * 1000

    def Q_lookup(self, key):
        d = self.get_distance(key)
        return ReachabilityModel.distance_to_prob(d)

    def Q_update(self, key, value):
        d = ReachabilityModel.prob_to_distance(value)
        if d >= self.config.max_distance:
            self.Q_table[key] = self.config.max_distance
            return
        if d <= 0:
            self.Q_table[key] = 0.
            return
        self.Q_table[key] = d
