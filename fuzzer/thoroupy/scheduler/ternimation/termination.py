from logging import getLogger
from importlib import import_module

from utils import Config
from .condition import TerminationConditionBase

from typing import List


logger = getLogger(__name__)

class TerminationManager(TerminationConditionBase):
    def __init__(self, config, pipe = None) -> None:
        self.checkers: List[TerminationConditionBase] = []
        self.pipe = pipe

        for item, value in config.termination.items(): # type: ignore
            self.checkers.append(self.load(item, value))
        logger.debug("TerminationManager loaded with %s", self.checkers)

    def check(self, flags, addr, context, id, result) -> bool:
        return any([
            checker.check(flags, addr, context, id, result) 
            for checker in self.checkers
        ])
    
    def trace(self, flags, addr, context, id, result):
        [checker.trace(flags, addr, context, id, result) for checker in self.checkers]

    
    def reset(self):
        [checker.reset() for checker in self.checkers]
    
    def trace_bb(self, function_index, bb_index):
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
