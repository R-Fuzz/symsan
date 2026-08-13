from abc import ABC, abstractmethod


class TerminationConditionBase(ABC):
    def __init__(self, manager, **kwargs) -> None:
        self._manager = manager

    @abstractmethod
    def reset(self):
        pass

    @abstractmethod
    def check(self, flags, addr, context, id, result) -> bool:
        pass

    @abstractmethod
    def trace(self, flags, addr, context, id, result):
        pass

    def trace_bb(self, function_index, bb_index):
        pass