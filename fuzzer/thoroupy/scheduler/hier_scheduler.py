from typing import List

from control import UcsanTicket # type: ignore
from .base import SchedulerBase
from .seed import Seed


from time import time, sleep
from threading import Thread

import logging
import pickle

from debug_config import target_branch

logger = logging.getLogger(__name__)

class HierachicalScheduler(SchedulerBase):
    def __init__(self, performance = True, save_seeds = False) -> None:
        super().__init__()
        self._id_queue: List[Seed] = []
        self._visited_ids: set[int] = set()
        self._visited_switches: set[tuple[int, int]] = set()
        self._context_queue: List[Seed] = []
        self._visited_contexts = set()
        self._visited_id_contexts = set()
        self._loop_queue: List[Seed] = []
        self._visited_loops = set()
        self._path_queue: List[Seed] = []
        self._path_counter = 0
        self._counter = 0
        self._starttime = time()
        self._track_performance = performance
        self._seeds_hash = set()
        self._save_seeds = save_seeds
        self._last_id = 0
        self._switch_index = 0

    def __next__(self) -> "Seed":
        queue_length = len(self._id_queue) + len(self._context_queue) + len(self._loop_queue) + len(self._path_queue)
        logger.debug(f"Queue: {queue_length} = id:{len(self._id_queue)} + context:{len(self._context_queue)} + loop:{len(self._loop_queue)}, Scheduled: {self._counter}")
        # input("Press Enter to continue...")
        if self._track_performance and self._counter % 100 == 0:
            self.print_performance()
        if self._id_queue:
            self._counter += 1
            seed = self._id_queue.pop(0)
            self._pipe.send(seed.to_ticket())
            logger.debug(f"Send seed {seed} to pipe from ID queue")
            return seed
        elif self._context_queue:
            self._counter += 1
            seed = self._context_queue.pop(0)
            self._pipe.send(seed.to_ticket())
            logger.debug(f"Send seed {seed} to pipe from context queue")
            return seed
        elif self._loop_queue:
            self._counter += 1
            seed = self._loop_queue.pop(0)
            self._pipe.send(seed.to_ticket())
            logger.debug(f"Send seed {seed} to pipe from loop queue")
            return seed
        elif self._path_queue:
            self._counter += 1
            self._path_counter += 1
            seed = self._path_queue.pop(0)
            self._pipe.send(seed.to_ticket())
            logger.debug(f"Send seed {seed} to pipe from path queue")
            return seed

        elif self._counter == 0:
            self._counter += 1
            ticket = UcsanTicket()
            ticket.instance_id = 0
            ticket.session_id = 0
            ticket.msg_type = 1
            ticket.payload_size = 0
            logger.warn("No seed in queue, send initialize ticket")
            self._pipe.send(ticket)
            return Seed()
        else:
            logger.warn("No seed in queue, terminate")
            self.stat()
            raise StopIteration("")

    def print_performance(self):
        logger.info(f"Performance: {self._counter / (time() - self._starttime)} seeds/s")


    def append(self, seed: "Seed", **kwargs) -> None:
        bid = kwargs.get("bid", 0)
        context = kwargs.get("context", 0)
        flags = kwargs.get("flags", 0)
        loop = flags & 0x6 != 0
        switch_case = flags & 0x10 != 0
        switch_use_id_queue = False
        switch_use_context_queue = False
        if switch_case:
            if bid == self._last_id:
                self._switch_index += 1
            else:
                self._switch_index = 0
            if (bid, self._switch_index) not in self._visited_switches:
                switch_use_id_queue = True
            elif (bid, context) not in self._visited_id_contexts:
                switch_use_context_queue = True
            self._visited_switches.add((bid, self._switch_index))
        self._last_id = bid
        logger.info(f"Append seed {seed} to queue from bid {bid} and context {context}")
        digest = seed.digest().hexdigest()
        if digest not in self._seeds_hash:
            if bid not in self._visited_ids:
                self._id_queue.append(seed)
                logger.debug(f"Append seed to ID queue @{len(self._id_queue)}")
            elif switch_case:
                if switch_use_id_queue:
                    self._id_queue.append(seed)
                    logger.debug(f"Append seed to ID queue with switch index {self._switch_index} @{len(self._id_queue)}")
                elif switch_use_context_queue:
                    self._context_queue.append(seed)
                    logger.debug(f"Append seed to context queue with switch index {self._switch_index} @{len(self._context_queue)}")
                elif self._path_counter < len(self._visited_ids) * len(self._visited_contexts):
                    self._path_queue.append(seed)
                    logger.debug(f"Append seed to path queue with switch index {self._switch_index} @{len(self._path_queue)}")
            elif (bid, context) not in self._visited_id_contexts:
                if loop:
                    self._loop_queue.append(seed)
                    logger.debug(f"Append seed to loop queue @{len(self._loop_queue)}")
                else:
                    self._context_queue.append(seed)
                    logger.debug(f"Append seed to context queue @{len(self._context_queue)}")
            else:
                path_limit = len(self._visited_ids) * len(self._visited_contexts)
                # Ensure minimum limit of 100 to avoid premature termination for
                # simple test cases with few unique branch IDs or contexts
                effective_limit = max(100, path_limit)
                if self._path_counter < effective_limit:
                    self._path_queue.append(seed)
                    logger.debug(f"Append seed to path queue @{len(self._path_queue)} (path_counter={self._path_counter}, limit={effective_limit})")
                else:
                    logger.debug(f"Too many seeds, skip (path_counter={self._path_counter} >= limit={effective_limit}, visited_ids={len(self._visited_ids)}, visited_contexts={len(self._visited_contexts)})")
            self._visited_ids.add(bid)
            self._visited_contexts.add(context)
            self._visited_id_contexts.add((bid, context))
            self._seeds_hash.add(digest)
            if self._save_seeds:
                file_name = f"seeds/seed_{time()}.pickle"
                with open(file_name, "wb") as f:
                    pickle.dump([seed], f)
                    logger.info(f"Save seed {seed} to {file_name}")

            if target_branch and target_branch.get("bid")== bid:
                if target_branch.get("context") and context != target_branch["context"]:
                    return
                import pickle
                seed_name = f"queued_seed_{bid}_{context}.pkl"
                with open(seed_name, "wb") as f:
                    pickle.dump([seed], f)

    def stat(self) -> None:
        logger.info(f"Total {self._counter} seeds processed")

    def loads(self, filename):
        logger.info(f"Load seeds from {filename}")
        data = open(filename, "rb").read()
        self._path_queue = pickle.loads(data)
