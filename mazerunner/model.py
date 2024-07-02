import abc
import collections
import logging
import os
import pickle
import heapq
import math

from decimal import Decimal, getcontext
from enum import Enum
from utils import mkdir

DISTANCE_SCALE = 1000

class SortedDict:
    def __init__(self, need_sort=False):
        self.need_sort = need_sort
        self.data = collections.OrderedDict()
        self.heap = []
        self._heap_items = set()

    def __len__(self):
        return len(self.data)
    
    def __setitem__(self, key, value):
        self.data[key] = value
        if self.need_sort:
            self.reload(key)

    def __getitem__(self, key):
        return self.data[key]

    def __delitem__(self, key):
        self.remove(key)

    def __contains__(self, key):
        return key in self.data
    
    def __iter__(self):
        return iter(self.data)

    @property
    def is_heap_empty(self):
        assert len(self.heap) == len(self._heap_items)
        if not self.heap:
            return True
        return False

    @property
    def heap_size(self):
        assert len(self.heap) == len(self._heap_items)
        return len(self._heap_items)

    def keys(self):
        return self.data.keys()

    def values(self):
        return self.data.values()

    def items(self):
        return self.data.items()

    def reload(self, key):
        if not self.need_sort:
            return
        t = (self.data[key], key[2], key)
        if t in self._heap_items:
            return
        self._heap_items.add(t)
        heapq.heappush(self.heap, t)

    def remove(self, key, mark_only=False):
        if key in self.data:
            del self.data[key]
            if self.need_sort and not mark_only:
                self.clean_heap()

    def pop(self):
        while self.heap:
            t = heapq.heappop(self.heap)
            self._heap_items.remove(t)
            value, _, key = t
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
            t = heapq.heappop(self.heap)
            self._heap_items.remove(t)
        return None

    def clean_heap(self):
        if not self.need_sort:
            return
        new_heap = []
        for (v, c, k) in self.heap:
            if k not in self.data:
                continue
            if self.data[k] != v:
                continue
            new_heap.append((v, c, k))
        self.heap = new_heap
        self._heap_items = set(self.heap)
        heapq.heapify(self.heap)
    
    def rebuild_heap(self, targets={}):
        if not self.need_sort:
            return
        if targets:
            self.heap = [(self.data[k], k[2], k) for k in targets if k in self.data]
        else:
            self.heap = [(v, k[2], k) for k, v in self.data.items()]
        self._heap_items = set(self.heap)
        heapq.heapify(self.heap)


class RLModelType(Enum):
    unknown = 0
    distance = 1
    reachability = 2


class RLModel(abc.ABC):

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.visited_sa = collections.Counter()
        self.all_target_sa = set()
        self.unreachable_sa = set()
        if self.config.use_ordered_dict:
            self.q_table = SortedDict(need_sort=True)
        else:
            self.q_table = SortedDict(need_sort=False)
        if config.mazerunner_dir:
            mkdir(self.my_dir)
            self.load()

    @property
    def my_dir(self):
        return os.path.join(self.config.mazerunner_dir, "model")
    
    @abc.abstractmethod
    def Q_lookup(self, s, a):
        pass
    
    @abc.abstractmethod
    def Q_update(self, key, value):
        pass

    @abc.abstractmethod
    def get_distance(self, s, a, compare_only):
        pass

    @abc.abstractmethod
    def update_unreachable_Q(self, sa):
        pass

    @abc.abstractmethod
    def is_unreachable(self, state, action):
        pass

    def save(self):
        with open(os.path.join(self.my_dir, "visited_sa"), 'wb') as fp:
            pickle.dump(self.visited_sa, fp, protocol=pickle.HIGHEST_PROTOCOL)
        with open(os.path.join(self.my_dir, "Q_table"), 'wb') as fp:
            if self.q_table.need_sort:
                self.q_table.clean_heap()
            pickle.dump(self.q_table, fp, protocol=pickle.HIGHEST_PROTOCOL)  
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
                self.q_table = pickle.load(fp)
        unreachable_sa_fp = os.path.join(self.my_dir, "unreachable_sa")
        if os.path.isfile(unreachable_sa_fp):
            with open(unreachable_sa_fp, 'rb') as fp:
                self.unreachable_sa = pickle.load(fp)
        target_sa_path = os.path.join(self.my_dir, "target_sa")
        if os.path.isfile(target_sa_path):
            with open(target_sa_path, 'rb') as fp:
                self.all_target_sa = pickle.load(fp)

    def get_default_distance(self, s, a):
        assert a == 0 or a == 1
        bid = s.bid
        initial_distances = self.config.initial_policy.get(bid, None)
        value = initial_distances[a] if initial_distances else None
        value = self.config.max_distance if value is None else value
        self.logger.debug(f"get_default_distance: bid={bid}, action={a}, value={value}")
        value += (s.state[2] - 1) * DISTANCE_SCALE
        return value

    def add_unreachable_sa(self, sa):
        self.unreachable_sa.add(sa)
        self.update_unreachable_Q(sa)

    def add_visited_sa(self, sa):
        self.visited_sa.update([sa])
        if sa in self.unreachable_sa:
            self.unreachable_sa.remove(sa)
    
    def add_target_sa(self, sa):
        if self.config.defferred_solving_enabled:
            self.q_table.reload(sa)
        else:
            self.all_target_sa.add(sa)
    
    def remove_target_sa(self, sa):
        if self.config.defferred_solving_enabled:
            return
        if sa in self.all_target_sa:
            self.all_target_sa.remove(sa)

    def rebuild_targets(self, last_sa):
        if not self.config.defferred_solving_enabled:
            return
        targets = set(self.visited_sa.keys()) - self.unreachable_sa
        self.q_table.rebuild_heap(targets)
        if self.q_table.peak() == last_sa:
            self.add_unreachable_sa(last_sa)
            self.q_table.pop()

class DistanceModel(RLModel):

    @staticmethod
    def distance_to_q(d):
        return -d

    @staticmethod
    def q_to_distance(p):
        return -p

    def get_distance(self, s, a, compare_only=False):
        q = self.Q_lookup(s, a)
        return DistanceModel.q_to_distance(q)

    def Q_lookup(self, s, a):
        key = s.state + (a,)
        if key not in self.q_table:
            d = self.get_default_distance(s, a)
            self.q_table[key] = d
        return DistanceModel.distance_to_q(self.q_table[key])

    def Q_update(self, key, value):
        d = DistanceModel.q_to_distance(value)
        self.q_table[key] = d

    def update_unreachable_Q(self, sa):
        self.Q_update(sa, -float('inf'))

    def is_unreachable(self, state, action):
        d = DistanceModel.q_to_distance(self.Q_lookup(state, action))
        if d == float('inf'):
            return True
        return False

'''
Slow but accurate, use it when precision is needed.
'''
class ReachabilityModelDecimal(RLModel):
    # Constants
    ZERO = Decimal(0)
    ONE = Decimal(1)
    TWO = Decimal(2)
    
    def __init__(self, config):
        super().__init__(config)
        getcontext().prec = config.decimal_precision

    @staticmethod
    def distance_to_prob(d):
        """
        Converts a distance to a probability.
        Returns: 1 / 2 ** (d / DISTANCE_SCALE)
        """
        if d == float('inf'):
            return ReachabilityModelDecimal.ZERO
        if d == 0.:
            return ReachabilityModelDecimal.ONE
        return ReachabilityModelDecimal.ONE / (ReachabilityModelDecimal.TWO ** Decimal(float(d) / DISTANCE_SCALE))

    @staticmethod
    def prob_to_distance(p):
        """
        Converts a probability to a distance.
        Returns: -log_2(p) * DISTANCE_SCALE
        """
        if p == ReachabilityModelDecimal.ZERO:
            return float('inf')
        if p == ReachabilityModelDecimal.ONE:
            return 0.
        res = - (p.ln() / ReachabilityModelDecimal.TWO.ln())
        return float(res) * DISTANCE_SCALE

    def get_distance(self, s, a, compare_only=False):
        key = s.state + (a,)
        if key not in self.q_table:
            d = self.get_default_distance(s, a)
            self.q_table[key] = d
        return self.q_table[key]

    def Q_lookup(self, s, a):
        d = self.get_distance(s, a)
        return ReachabilityModelDecimal.distance_to_prob(d)

    def Q_update(self, key, value):
        d = ReachabilityModelDecimal.prob_to_distance(value)
        self.q_table[key] = d

    def update_unreachable_Q(self, sa):
        self.Q_update(sa, ReachabilityModelDecimal.ZERO)

    def is_unreachable(self, state, action):
        d = self.get_distance(state, action)
        if d == float('inf'):
            return True
        return False

'''
Be carefull about precision lost when doing computations between numbers 
that the diff = |num_1 - number_2| > (1.0 / 2**52), 
and one number is smaller than (1.0 / 2**52).
Fall back to ReachabilityModelDecimal if needed.
'''
class ReachabilityModelFloat(RLModel):

    @staticmethod
    def q_to_prob(q):
        return -q

    @staticmethod
    def prob_to_q(p):
        return -p
    
    @staticmethod
    def distance_to_prob(d):
        if d == float('inf'):
            return 0.
        if d == 0:
            return 1.
        return 1. / (2 ** (d / DISTANCE_SCALE))

    @staticmethod
    def prob_to_distance(p):
        if p == 0:
            return float('inf')
        if p == 1:
            return 0.
        return -math.log2(p) * DISTANCE_SCALE

    def get_distance(self, s, a, compare_only=False):
        key = s.state + (a,)
        if key not in self.q_table:
            d = self.get_default_distance(s, a)
            p = ReachabilityModelFloat.distance_to_prob(d)
            self.Q_update(key, p)
            if compare_only: return self.q_table[key]
            return d
        if compare_only: return self.q_table[key]
        p = ReachabilityModelFloat.q_to_prob(self.q_table[key])
        d = ReachabilityModelFloat.prob_to_distance(p)
        return d

    def Q_lookup(self, s, a):
        key = s.state + (a,)
        if key not in self.q_table:
            d = self.get_default_distance(s, a)
            p = ReachabilityModelFloat.distance_to_prob(d)
            self.Q_update(key, p)
        return ReachabilityModelFloat.q_to_prob(self.q_table[key])

    def Q_update(self, key, p):
        assert 0 <= p <= 1
        q = ReachabilityModelFloat.prob_to_q(p)
        self.q_table[key] = q

    def update_unreachable_Q(self, sa):
        self.Q_update(sa, 0.)

    def is_unreachable(self, state, action):
        p = ReachabilityModelFloat.q_to_prob(self.Q_lookup(state, action))
        if p == 0:
            return True
        return False
