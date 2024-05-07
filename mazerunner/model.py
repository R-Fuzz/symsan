import collections
import logging
import os
import pickle
import heapq

from decimal import Decimal, getcontext
from enum import Enum
from utils import mkdir

class SortedDict:
    def __init__(self, need_sort=False):
        self.need_sort = need_sort
        self.data = collections.OrderedDict()
        self.heap = []

    def __len__(self):
        return len(self.data)
    
    def __setitem__(self, key, value):
        if self.need_sort:
            if key in self.data:
                self.remove(key, mark_only=True)
            heapq.heappush(self.heap, (value, key[2], key))
        self.data[key] = value

    def __getitem__(self, key):
        return self.data.get(key, None)

    def __delitem__(self, key):
        self.remove(key)

    def __contains__(self, key):
        return key in self.data
    
    def __iter__(self):
        return iter(self.data)

    def keys(self):
        return self.data.keys()

    def values(self):
        return self.data.values()

    def items(self):
        return self.data.items()

    @property
    def is_heap_empty(self):
        if not self.heap:
            return True

    def remove(self, key, mark_only=False):
        if key in self.data:
            del self.data[key]
            if self.need_sort and not mark_only:
                self.rebuild_heap()

    def pop(self):
        while self.heap:
            value, _, key = heapq.heappop(self.heap)
            if key in self.data and self.data[key] == value:
                # don't remove item in Q-table
                # self.remove(key)
                return key
        return None

    def peak(self):
        while self.heap:
            value, _, key = self.heap[0]
            if key in self.data and self.data[key] == value:
                return key
            heapq.heappop(self.heap)
        return None

    def rebuild_heap(self):
        if not self.need_sort:
            return
        self.heap = [(-v, k[2], k) for k, v in self.data.items() if k in self.data]
        heapq.heapify(self.heap)


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
        if self.config.use_ordered_dict:
            self.distance_table = SortedDict(need_sort=True)
        else:
            self.distance_table = SortedDict(need_sort=False)
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
            if self.distance_table.need_sort:
                self.distance_table.rebuild_heap()
            pickle.dump(self.distance_table, fp, protocol=pickle.HIGHEST_PROTOCOL)  
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
                self.distance_table = pickle.load(fp)
        unreachable_branches_path = os.path.join(self.my_dir, "unreachable_sa")
        if os.path.isfile(unreachable_branches_path):
            with open(unreachable_branches_path, 'rb') as fp:
                self.unreachable_sa = pickle.load(fp)
        target_sa_path = os.path.join(self.my_dir, "target_sa")
        if os.path.isfile(target_sa_path):
            with open(target_sa_path, 'rb') as fp:
                self.all_target_sa = pickle.load(fp)

    def get_default_distance(self, bid, a):
        assert a == 0 or a == 1
        initial_distances = self.config.initial_policy.get(str(bid), None)
        value = initial_distances[a] if initial_distances else None
        value = self.config.max_distance if value is None else value
        self.logger.debug(f"get_default_distance: bid={bid}, action={a}, value={value}")
        return value

    def add_unreachable_sa(self, sa):
        self.unreachable_sa.add(sa)
        self.update_unreachable_Q(sa)

    def add_visited_sa(self, sa):
        self.visited_sa.update([sa])
        if sa in self.unreachable_sa:
            self.unreachable_sa.remove(sa)
    
    def add_target_sa(self, sa):
        self.all_target_sa.add(sa)
    
    def remove_target_sa(self, sa):
        if sa in self.all_target_sa:
            self.all_target_sa.remove(sa)


class DistanceModel(RLModel):

    @staticmethod
    def distance_to_q(d):
        return -d

    @staticmethod
    def q_to_distance(p):
        return -p

    def get_distance(self, s, a):
        q = self.Q_lookup(s, a)
        return DistanceModel.q_to_distance(q)

    def Q_lookup(self, s, a):
        key = s.state + (a,)
        if key not in self.distance_table:
            d = self.get_default_distance(s.bid, a)
            self.distance_table[key] = d
        return DistanceModel.distance_to_q(self.distance_table[key])

    def Q_update(self, key, value):
        d = DistanceModel.q_to_distance(value)
        self.distance_table[key] = d
        self.logger.debug(f"Q_update: key={key}, value={value}")

    def update_unreachable_Q(self, sa):
        self.Q_update(sa, -float('inf'))

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

    def get_distance(self, s, a):
        key = s.state + (a,)
        if key not in self.distance_table:
            d = self.get_default_distance(s.bid, a)
            self.distance_table[key] = d
        return self.distance_table[key]

    def Q_lookup(self, s, a):
        d = self.get_distance(s, a)
        return ReachabilityModel.distance_to_prob(d)

    def Q_update(self, key, value):
        d = ReachabilityModel.prob_to_distance(value)
        if d > self.config.max_distance * 2:
            d = float('inf')
        self.distance_table[key] = d
        self.logger.debug(f"Q_update: key={key}, value={value}")

    def update_unreachable_Q(self, sa):
        self.Q_update(sa, ReachabilityModel.ZERO)
