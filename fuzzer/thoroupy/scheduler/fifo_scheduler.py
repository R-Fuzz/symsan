from typing import List

from control import UcsanTicket # type: ignore
from .base import SchedulerBase
from .seed import Seed


from time import time, sleep
from threading import Thread

import logging
import pickle

logger = logging.getLogger(__name__)

class FIFOScheduler(SchedulerBase):
    def __init__(self, performance = True, save_seeds = False) -> None:
        super().__init__()
        self._queue: List[Seed] = []
        self._counter = 0
        self._starttime = time()
        self._track_performance = performance
        self._seeds_hash = set()
        self._save_seeds = save_seeds

    
    def __next__(self) -> "Seed":
        logger.debug(f"Queue: {len(self._queue)}")
        # input("Press Enter to continue...")
        if self._track_performance and self._counter % 100 == 0:
            self.print_performance()
        if self._queue:
            self._counter += 1
            seed = self._queue.pop(0)
            self._pipe.send(seed.to_ticket())
            logger.debug(f"Send seed {seed} to pipe")
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
        logger.info(f"Append seed {seed} to queue")
        digest = seed.digest().hexdigest()
        if digest not in self._seeds_hash:
            self._queue.append(seed)
            self._seeds_hash.add(digest)
            logger.debug(f"Queued seed #{len(self._queue)} (digest={digest[:8]})")
            if self._save_seeds:
                file_name = f"seeds/seed_{time()}.pickle"
                with open(file_name, "wb") as f:
                    pickle.dump([seed], f)
                    logger.info(f"Save seed {seed} to {file_name}")
        else:
            logger.debug(f"Duplicate seed skipped (digest={digest[:8]})")

    def stat(self) -> None:
        logger.info(f"Total {self._counter} seeds processed")
    
    def loads(self, filename):
        logger.info(f"Load seeds from {filename}")
        data = open(filename, "rb").read()
        self._queue = pickle.loads(data)
