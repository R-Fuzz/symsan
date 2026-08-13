from abc import ABC
from control import Pipe, UcsanTicket # type: ignore
from .seed import Seed

class SchedulerBase(ABC):
    _pipe: Pipe
    def __init__(self) -> None:
        pass

    def __call__(self, pipe:Pipe) -> "SchedulerBase":
        self._pipe = pipe
        return self

    def __next__(self) -> "Seed": # type: ignore        
        """Get next seed"""
        if self._pipe == None:
            raise ValueError("Pipe not initialized")
    
    def __iter__(self) -> "SchedulerBase":
        return self

    def append(self, other: "Seed", **kwargs) -> None:
        raise NotImplementedError("append() not implemented")

