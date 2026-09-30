from .handler import HandlerBase
from control.message.enums import PIPE_EVENT_TYPE

PIPE_EVENT_TYPE.__dict__

class ForwardHandler(HandlerBase):
    SUB=[PIPE_EVENT_TYPE.EVENT_OOB, PIPE_EVENT_TYPE.EVENT_UAF]

    def handle(self, msg):
        # msg.addr is the error's own PC (the instrumented access)
        self._manager._report(msg.context, getattr(msg, "addr", 0))

forward_handler = ForwardHandler
