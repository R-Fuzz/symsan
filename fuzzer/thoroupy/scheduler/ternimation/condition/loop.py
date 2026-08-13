from typing import TYPE_CHECKING

from collections import defaultdict
from logging import getLogger
import ctypes
from . import TerminationConditionBase

from control import UcsanTicket # type: ignore

if TYPE_CHECKING:
    from control.message import PipeMsg # type: ignore

TRACE_BRANCH = False

logger = getLogger(__name__)

class _LoopCounter():
    def __init__(self, id:int, context:int, depth:int, parent: "_LoopCounter | None" = None) -> None:
        self._current = 0
        self._direction = 0
        self._max = 0
        self._id = id
        self._context = context
        self._depth = depth
        self._parent = parent
        self._val = 0

    def __hash__(self) -> int:
        return hash((self._id, self._context, self._depth, self._current, self._parent, self._val))

    def reset(self):
        self._current = 0
        self._max = 0
        self._val = 0

    def trace(self):
        self._current += 1
        logger.debug(f"Trace loop counter: {self._current}, {self._max}")
        if self._current > self._max:
            self._max = self._current

    def __lt__(self, threshold: int):
        # must be the current loop and the max count is less than threshold
        return self._current == self._max and self._max < threshold

    def __gt__(self, value: int):
        return not self.__lt__(value)

    def __repr__(self) -> str:
        return f"< counter: {self._current}/{self._max}, val:{self._val} >"

    def is_current(self)->bool:
        return self._current == self._max

    def visit_branch(self, bid: int, taken: bool):
        if TRACE_BRANCH:
            self._val = hash((self._val, bid, taken))
            logger.debug(f"Trace Visit branch: {bid}, {taken}, {self._val = }")

class _NestManager():
    def __init__(self) -> None:
        self.counters = defaultdict(_LoopCounter)
        self.loop_path = [_LoopCounter(0, 0, 0)]
        self.loop_counters = defaultdict(int)
        # Loop-counter / loop-exit states actually *executed* (across all
        # executions).  Like a branch target, keep flipping a loop header
        # toward a direction until the state it reaches has actually been
        # visited -- not merely until the flip was attempted once.  Persisted
        # across executions (NOT cleared in reset()).
        self._visited_iter = set()
        self._visited_exit = set()

    @property
    def inner_most_counter(self):
        return self.loop_path[-1]

    @property
    def current_parent_counter(self):
        return self.loop_path[-2] if len(self.loop_path) > 1 else self.inner_most_counter

    @property
    def current_depth(self):
        return len(self.loop_path) - 1

    def trace(self, id:int, context: int, depth:int):
        if depth < self.current_depth: # exit a loop
            self.loop_path = self.loop_path[:depth+1]
            logger.debug(f"Exit loop to depth: {depth}, self.loop_path: {self.loop_path}")
            return
        if depth > self.current_depth: # enter a new nested loop
            loop_hash = hash((id, context, depth))
            if loop_hash not in self.counters:
                logger.debug(f"Adding new loop counter: {loop_hash}, {id}, {context}, {depth}")
                self.counters[loop_hash] = _LoopCounter(id, context, depth, self.inner_most_counter)
            loop_counter = self.counters[loop_hash]
            self.loop_path.append(loop_counter)
            logger.info(f"Trace loop: {id}, context: {context}, depth: {depth}, current depth: {self.current_depth}")
            loop_counter.trace()
            return
            # assert depth == self.current_depth # not sure if this covers all cases
        # else: same loop

        # depth == self.current_depth, trace the current loop or replace the current loop counter
        # loop_hash = hash((id, context, depth))
        # if loop_hash not in self.counters:
        #     logger.debug(f"Adding new loop counter: {loop_hash}, {id}, {context}, {depth}, {self.current_parent_counter}")
        #     self.counters[loop_hash] = _LoopCounter(id, context, depth, self.current_parent_counter)
        # loop_counter = self.counters[loop_hash]
        # self.loop_path[-1] = loop_counter
        loop_counter = self.inner_most_counter
        if (loop_counter._id != id or
                loop_counter._context != context or
                loop_counter._depth != depth):
            # Recursive decompilation can enter a different loop site at the
            # same nesting depth. Treat that as a sibling loop instead of
            # aborting the whole run.
            loop_hash = hash((id, context, depth))
            if loop_hash not in self.counters:
                logger.debug(
                    f"Adding sibling loop counter: {loop_hash}, {id}, "
                    f"{context}, {depth}, {self.current_parent_counter}"
                )
                self.counters[loop_hash] = _LoopCounter(
                    id, context, depth, self.current_parent_counter
                )
            loop_counter = self.counters[loop_hash]
            self.loop_path[-1] = loop_counter
        logger.info(f"Trace loop: {id}, context: {context}, depth: {depth}, current depth: {self.current_depth}")
        loop_counter.trace()

    def reset(self):
        self.loop_path = [_LoopCounter(0, 0, 0)]
        [v.reset() for _,v in self.counters.items()]

    def check(self, threshold: int, exiting:bool=False) -> bool:
        c = self.inner_most_counter
        sig = (c._id, c._context, c._depth, c._current)
        # The loop header just executed at this counter value -> mark visited.
        self._visited_iter.add(sig)
        if exiting:
            # Execution is exiting at this iteration; flip toward "continue"
            # (one deeper iteration) only while at the frontier and below the
            # threshold, and only until that deeper count has been reached.
            self._visited_exit.add(sig)
            if not (c < threshold):
                return False
            target = (c._id, c._context, c._depth, c._current + 1)
            return target not in self._visited_iter
        # Latch (continuing); flip toward "exit here" until an execution has
        # actually exited at this iteration.
        if not c.is_current():
            return False
        return sig not in self._visited_exit

class Loop(TerminationConditionBase):
    def __init__(self, manager, threshold=10, reset_nest=False, trace_branch=False, skip_solve=False) -> None:
        global TRACE_BRANCH
        super().__init__(manager)
        # self.loops = defaultdict(_LoopCounter)
        self._skip_solve = skip_solve
        self._default_threshold = 0x7fffffff if skip_solve else threshold
        self.threshold = 0x7fffffff if skip_solve else threshold
        self._reset_nest = reset_nest
        self._last_cid = 0
        self._nest = _NestManager()
        TRACE_BRANCH = trace_branch

    @property
    def threshold(self):
        return self._threshold

    @threshold.setter
    def threshold(self, threshold: int):
        self._threshold = threshold
        logger.debug(f"Set threshold to {threshold}")
        if self._manager:
            ticket = UcsanTicket()
            ticket.payload_size = 4
            ticket.msg_type = 0x3
            self._manager.pipe.send(ticket)
            self._manager.pipe.send(threshold.to_bytes(4, "little"))

    def check(self, flags, addr, context, id, result) -> bool:
        if flags & 0x6 == 0: # not a loop related branch
            logger.debug(f"Not a loop related branch, update context {self._nest.loop_path = }")
            self._nest.inner_most_counter.visit_branch(id, result)
            return False
        if self._skip_solve:
            return False
        return self._nest.check(self.threshold, flags & 0x2 != 0)

    def trace(self, flags, addr, context, id:int, result:int):
        """
        Trace loop
        id: loop id
        result: loop depth
        """
        # result = ctypes.c_int64(result).value
        logger.debug(f"Trace loop: {id}, context: {context} depth: {result}")
        self._nest.trace(id, context, result)

    def reset(self)-> None:
        self._nest.reset()
        if self.threshold != self._default_threshold:
            self.threshold = self._default_threshold

    def set_threshold(self, threshold: int) -> None:
        if self._skip_solve:
            return
        threshold = int(threshold)
        if threshold > self.threshold:
            logger.critical(
                "Raise loop threshold: %s -> %s",
                self.threshold,
                threshold,
            )
            self.threshold = threshold
