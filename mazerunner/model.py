import collections
import logging
import os
import pickle

from decimal import Decimal, getcontext
from enum import Enum
from utils import mkdir, find_local_min

class RLModelType(Enum):
    unknown = 0
    distance = 1
    reachability = 2


class RLModel:

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__qualname__)
        getcontext().prec = config.decimal_precision
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

    def get_default_distance(self, bid, action):
        assert action == 0 or action == 1
        value = self.config.initial_policy.get(bid, None)[action]
        value = self.config.max_distance if value is None else value
        self.logger.debug(f"get_default_distance: bid={bid}, action={action}, value={value}")
        return value

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
    @staticmethod
    def create_reward_calculator(config, episode, min_distance):
        return DistanceRewardCalculator(config, min_distance, episode)

    @staticmethod
    def distance_to_q(d):
        return -d

    @staticmethod
    def q_to_distance(p):
        return -p

    def get_distance(self, state, action):
        key = state.sa
        if key not in self.Q_table:
            return self.get_default_distance(state.bid, action)
        else:
            return DistanceModel.q_to_distance(self.Q_table[key])

    def Q_lookup(self, state, action):
        key = state.sa
        if key not in self.Q_table:
            d = self.get_default_distance(state.bid, action)
            return DistanceModel.distance_to_q(d)
        return self.Q_table[key]

    def Q_update(self, key, value):
        self.Q_table[key] = value

class ReachabilityModel(RLModel):
    # Constants
    ZERO = Decimal(0)
    ONE = Decimal(1)
    TWO = Decimal(2)

    @staticmethod
    def create_reward_calculator(config, episode, min_distance):
        return ReachabilityRewardCalculator(config, min_distance, episode)

    @staticmethod
    def distance_to_prob(d):
        """
        Converts a distance to a probability.
        Returns: 1 / 2 ** (d / 1000)
        """
        if d == float('inf'):
            return ReachabilityModel.ZERO
        if d == 0.:
            return ReachabilityModel.ONE
        return ReachabilityModel.ONE / (ReachabilityModel.TWO ** Decimal(float(d) / 1000))

    @staticmethod
    def prob_to_distance(p):
        """
        Converts a probability to a distance.
        Returns: -log_2(p) * 1000
        """
        if p == ReachabilityModel.ZERO:
            return float('inf')
        if p == ReachabilityModel.ONE:
            return 0.
        res = - (p.ln() / ReachabilityModel.TWO.ln())
        return float(res) * 1000

    def get_distance(self, state, action):
        key = state.sa
        if key not in self.Q_table:
            return self.get_default_distance(state.bid, action)
        else:
            return self.Q_table[key]

    def Q_lookup(self, state, action):
        d = self.get_distance(state, action)
        return ReachabilityModel.distance_to_prob(d)

    def Q_update(self, key, value):
        d = ReachabilityModel.prob_to_distance(value)
        self.Q_table[key] = d

class RewardCalculator:
    def __init__(self, config, min_distance, trace):
        self.config = config
        self.min_distance = min_distance
        self.trace = trace

    def compute_reward(self, i):
        raise NotImplementedError("This method should be overridden by subclass")


class DistanceRewardCalculator(RewardCalculator):
    def __init__(self, config, min_distance, trace):
        super().__init__(config, min_distance, trace)
        self.local_min_indices = find_local_min([s.d for s in trace])

    def compute_reward(self, i):
        if i >= len(self.trace) and self.min_distance > 0:
                return -self.config.max_distance
        _, _, d = self.trace[i]
        if d == 0:
            return self.config.max_distance
        r = 0
        if i in self.local_min_indices:
            r = (1000 / d) * (1000 / d) * self.config.max_distance
        return r


class ReachabilityRewardCalculator(RewardCalculator):
    def compute_reward(self, i):
        if i >= len(self.trace):
            return Decimal(0)
        d = self.trace[i].d
        if d == 0:
            return Decimal(1)
        return Decimal(0)
