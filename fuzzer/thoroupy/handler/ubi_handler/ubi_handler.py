import logging

from control.message.enums import PIPE_EVENT_TYPE

from ..handler import HandlerBase


logger = logging.getLogger(__name__)
class ubi_handler(HandlerBase):
    SUB = [PIPE_EVENT_TYPE.EVENT_UBI]
    def __init__(self, manager) -> None:
        super().__init__(manager)

    def handle(self, msg):
        logger.warning(f"Ubi checker triggered@{msg.addr:#x}")