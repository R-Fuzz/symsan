import abc
import heapq
import logging
import numpy as np

class SeedScheduler(abc.ABC):
    @abc.abstractmethod
    def put(self, fn, info, from_fuzzer=False):
        pass

    @abc.abstractmethod
    def pop(self):
        pass
    
    @abc.abstractmethod
    def is_empty(self):
        pass

class FILOScheduler(SeedScheduler):
    def __init__(self, q):
        self.queue = q
        self.fuzzer_seeds = []

    def put(self, fn, info, from_fuzzer=False):
        p, _ = info[0], info[1]
        if from_fuzzer:
            self.fuzzer_seeds.append(fn)
        priority = int(p/1000)
        heapq.heappush(self.queue, (priority, fn))

    def pop(self):
        if self.fuzzer_seeds:
            return self.fuzzer_seeds.pop()
        if not self.queue:
            return None
        _, removed_seed = heapq.heappop(self.queue)
        return removed_seed
    
    def is_empty(self):
        return not self.queue and not self.fuzzer_seeds

class PrioritySamplingScheduler(SeedScheduler):
    def __init__(self, q):
        self.queue = q
        self._max = float('-inf')
        self._weights_need_update = True

    def _update_weights(self):
        if not self.queue:
            self._weights = []
            return
        min_priority = self.queue[0][0]
        max_priority = self._max
        mid_val = (min_priority + max_priority) / 2
        self._weights = [self._logistic_function(priority, 1, mid_val) for priority, _ in self.queue]
        self._weights /= np.sum(self._weights)
        self._weights_need_update = False

    def _logistic_function(self, x, k, mid):
        return 1 / (1 + np.exp(k * (x - mid)))

    def put(self, fn, info, from_fuzzer=False):
        p, _ = info[0], info[1]
        if from_fuzzer and p is None:
            p = 0
        priority = int(p/1000)
        heapq.heappush(self.queue, (priority, fn))
        self._max = max(self._max, priority)
        self._weights_need_update = True

    def pop(self):
        if not self.queue:
            return None
        if len(self.queue) == 1:
            return self.queue[0][1]
        if self._weights_need_update:
            self._update_weights()
        chosen_index = np.random.choice(range(len(self.queue)), p=self._weights)
        chosen_seed = self.queue[chosen_index][1]
        if self.queue[chosen_index][0] == 0:
            self.remove(chosen_index)
        return chosen_seed

    def is_empty(self) -> bool:
        return not self.queue

    def remove(self, index_to_remove):
        if not self.queue:
            return
        p_to_remove = self.queue[index_to_remove][0]
        self.queue.pop(index_to_remove)
        heapq.heapify(self.queue)
        if self.queue and self._max == p_to_remove:
            self._max = max(self.queue, key=lambda x: x[0])[0]
        if not self.queue:
            self._max = float('-inf')
        self._weights_need_update = True

class RealTimePriorityScheduler(SeedScheduler):
    def __init__(self, m, t):
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.state_seed_mapping = m
        self.D_table = t
        self.fuzzer_seeds = []
    
    def put(self, fn, info, from_fuzzer=False):
        _, sa = info[0], info[1]
        if from_fuzzer:
            self.fuzzer_seeds.append(fn)
            return
        assert not sa is None
        self.state_seed_mapping[sa] = fn

    def pop(self):
        if self.fuzzer_seeds:
            return self.fuzzer_seeds.pop(), None
        selected_state = self.D_table.pop()
        if selected_state is None:
            return None, None
        self.logger.debug(f"selected state: {selected_state}, distacne: {self.D_table[selected_state]}")
        if selected_state in self.state_seed_mapping:
            return self.state_seed_mapping[selected_state], selected_state
        return None, selected_state
    
    def reset(self):
        self.D_table.rebuild_heap()
    
    def is_empty(self) -> bool:
        return not self.fuzzer_seeds and self.D_table.is_heap_empty
