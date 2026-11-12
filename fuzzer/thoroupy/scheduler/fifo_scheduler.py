from typing import List

from control import UcsanTicket # type: ignore
from .base import SchedulerBase
from .seed import Seed


from time import time, sleep
from threading import Thread

import logging
import pickle

logger = logging.getLogger(__name__)

class PendingTask:
    """A branch's task, parsed while its trace ran and solved only when the
    queue reaches it (on-demand solving): the seed its solution applies to,
    and the termination conditions' question it answers (asked again then)."""
    __slots__ = ("task_id", "seed", "ask")

    def __init__(self, task_id: int, seed: "Seed", ask) -> None:
        self.task_id = task_id
        self.seed = seed
        self.ask = ask

class FIFOScheduler(SchedulerBase):
    def __init__(self, performance = True, save_seeds = False) -> None:
        super().__init__()
        self._queue: List[Seed] = []
        self._counter = 0
        self._starttime = time()
        self._track_performance = performance
        self._seeds_hash = set()
        self._save_seeds = save_seeds
        # on-demand solving: a PendingTask -> its seed, or None (set_resolver)
        self._resolver = None

    def set_resolver(self, resolver) -> None:
        self._resolver = resolver

    def append_task(self, task: PendingTask) -> None:
        self._queue.append(task)

    
    def __next__(self) -> "Seed":
        logger.debug(f"Queue: {len(self._queue)}")
        # input("Press Enter to continue...")
        if self._track_performance and self._counter % 100 == 0:
            self.print_performance()
        while self._queue:
            seed = self._queue.pop(0)
            if isinstance(seed, PendingTask):
                # solved now, the queue having reached it: no seed if its
                # direction was covered meanwhile, it has no solution, or the
                # solution is a seed already run
                seed = self._resolver(seed)
                if seed is None or not self._admit(seed):
                    continue
            self._counter += 1
            self._pipe.send(seed.to_ticket())
            logger.debug("Send seed %s to pipe", seed)
            return seed

        if self._counter == 0:
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
        logger.info("Append seed %s to queue", seed)
        if self._admit(seed):
            self._queue.append(seed)
            logger.debug(f"Queued seed #{len(self._queue)}")

    def _admit(self, seed: "Seed") -> bool:
        # a seed not seen before (and saved, if asked)
        digest = seed.digest().hexdigest()
        if digest in self._seeds_hash:
            logger.debug(f"Duplicate seed skipped (digest={digest[:8]})")
            return False
        self._seeds_hash.add(digest)
        if self._save_seeds:
            file_name = f"seeds/seed_{time()}.pickle"
            with open(file_name, "wb") as f:
                pickle.dump([seed], f)
                logger.info("Save seed %s to %s", seed, file_name)
        return True

    def stat(self) -> None:
        logger.info(f"Total {self._counter} seeds processed")
    
    def loads(self, filename):
        logger.info(f"Load seeds from {filename}")
        data = open(filename, "rb").read()
        self._queue = pickle.loads(data)
