from logging import getLogger
from importlib import import_module

from utils import Config
from .condition import TerminationConditionBase
from .condition.branch import F_CHECK_POINTER

from typing import List


logger = getLogger(__name__)

class TerminationManager(TerminationConditionBase):
    def __init__(self, config, pipe = None) -> None:
        self.checkers: List[TerminationConditionBase] = []
        self.pipe = pipe
        # Coverage over the whole session, what a run achieved: the basic
        # blocks executed (KO_TRACE_BB) and the symbolic branch directions
        # taken, (id, result).  A seed count is not: a loop over a mask makes
        # hundreds of seeds that take the same few branches.
        self.blocks = set()
        self.directions = set()

        for item, value in config.termination.items(): # type: ignore
            self.checkers.append(self.load(item, value))
        logger.debug("TerminationManager loaded with %s", self.checkers)

    def check(self, flags, addr, context, id, result) -> bool:
        if not flags & F_CHECK_POINTER:
            self.directions.add((id, result))
        rets = [
            checker.check(flags, addr, context, id, result) 
            for checker in self.checkers
        ]
        # the questions the checkers that asked asked (last_ask), for an
        # on-demand task to be asked again; None if one cannot be
        self._last_ask = []
        for checker, ret in zip(self.checkers, rets):
            if not ret:
                continue
            ask = getattr(checker, "last_ask", None)
            if ask is None:
                self._last_ask = None
                break
            self._last_ask.append((checker, ask))
        return any(rets)

    def last_ask(self):
        return getattr(self, "_last_ask", None)

    def still_wanted(self, asks) -> bool:
        # an on-demand task's questions, asked again: wanted unless every
        # checker that asked has seen its direction taken since (none known,
        # e.g. a policy target solved regardless: wanted)
        return not asks or any(c.still_wanted(a) for c, a in asks)
    
    def trace(self, flags, addr, context, id, result):
        [checker.trace(flags, addr, context, id, result) for checker in self.checkers]

    
    def reset(self):
        [checker.reset() for checker in self.checkers]
    
    def trace_bb(self, function_index, bb_index):
        self.blocks.add((function_index, bb_index))
        [checker.trace_bb(function_index, bb_index) for checker in self.checkers]

    def set_loop_threshold(self, threshold: int):
        for checker in self.checkers:
            if hasattr(checker, "set_threshold"):
                checker.set_threshold(threshold)

    def load(self, condition, config) -> TerminationConditionBase:
        logger.debug(" Loading condition %s", condition)
        ConditionClass = import_module(f".condition.{condition}", __package__).__getattribute__(condition.capitalize())
        config = config if config else {}
        ret = ConditionClass(self, **config)
        logger.debug(ret)
        logger.debug(config)
        if isinstance(ret, TerminationConditionBase):
            return ret
        else:
            raise TypeError(f"Condition {condition} is not a subclass of TerminationConditionBase")
    
    def __repr__(self) -> str:
        return super().__repr__() + "\n|=> " + "\n|=> ".join([repr(checker) for checker in self.checkers])
