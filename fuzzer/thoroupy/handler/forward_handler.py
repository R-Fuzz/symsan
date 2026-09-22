from .handler import HandlerBase
from control.message.enums import PIPE_EVENT_TYPE

PIPE_EVENT_TYPE.__dict__

class ForwardHandler(HandlerBase):
    SUB=[PIPE_EVENT_TYPE.EVENT_OOB, PIPE_EVENT_TYPE.EVENT_UAF]

    def handle(self, msg):
        self._manager._report(msg.context)

forward_handler = ForwardHandler
