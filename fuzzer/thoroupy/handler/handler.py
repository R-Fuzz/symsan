from abc import ABC, abstractmethod
import typing
from collections import defaultdict
import importlib
import logging

if typing.TYPE_CHECKING:
    from manager import UcsanManager

logger = logging.getLogger(__name__)

class HandlerBase(ABC):
    SUB:list[int]
    def __init__(self, manager: "UcsanManager") -> None:
        super().__init__()
        self._manager = manager
    @abstractmethod
    def handle(self, msg):
        pass
    

class HandlerManager:
    def __init__(self, manager: "UcsanManager") -> None:
        config = manager.config
        self.consumer = defaultdict(list)
        if "handler" not in config:
            return
        for handler_name, kwargs in config.handler: # type: ignore
            handler_cls = importlib.import_module(f".{handler_name}", __package__).__getattribute__(handler_name)
            handler = handler_cls(manager, **kwargs)
            for sub in handler_cls.SUB:
                self.consumer[sub].append(handler)
            logger.debug(f"Handler {handler_name} added to consumers: {handler_cls.SUB}")
    

    def handle(self, msg):
        for sub in self.consumer[msg.context]:
            sub.handle(msg)

    def on_seed_done(self):
        """Notify all handlers that the current seed execution finished."""
        for handlers in self.consumer.values():
            for h in handlers:
                if hasattr(h, 'on_seed_done'):
                    h.on_seed_done()
