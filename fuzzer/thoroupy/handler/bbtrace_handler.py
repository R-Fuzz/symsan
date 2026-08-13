from .handler import HandlerBase
from control.message.enums import PIPE_EVENT_TYPE
from itertools import count

import logging
logger = logging.getLogger(__name__)

from debug_config import target

class BBTraceHandler(HandlerBase):
    SUB=[PIPE_EVENT_TYPE.TRACE_BB]

    def __init__(self, manager: "UcsanManager", output=None, dedup=True, **kwargs) -> None:
        super().__init__(manager)
        if output is not None:
            self._output = open(output, "w")
            self._visited = set()
        self.dedup = dedup

    def handle(self, msg):
        info = (msg.func_id, msg.bb_id)
        if self._manager._current.traces is None:
            self._manager._current.traces = []
        self._manager._current.traces.append(info)
        logger.debug(f"BBTraceHandler: recording {info}")

        if target and msg.func_id == target.get("func_id"):
            if msg.bb_id == target.get("save_bb_id"):
                import pickle
                seed_name = f"reached_seed_{msg.bb_id}.pkl"
                with open(seed_name, "wb") as f:
                    logger.info(f"Targeted seed dumped into {seed_name}")
                    pickle.dump([self._manager._current], f)
            if msg.bb_id in target.get("stop_bb_ids"):
                self._manager.epilogue()

        if self._output is not None:
            if msg.func_id == 0 and msg.bb_id == 0:
                self._output.write("===========\n")
                self._output.flush()
            if not self.dedup or (self.dedup and info not in self._visited):
                self._visited.add(info)
                self._output.write(f"{info[0]}:{info[1]} ({msg.func_id}, {msg.bb_id})\n")
                self._output.flush()


bbtrace_handler = BBTraceHandler

