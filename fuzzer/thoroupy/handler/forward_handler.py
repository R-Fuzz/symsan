from .handler import HandlerBase
from control.message.enums import PIPE_EVENT_TYPE

PIPE_EVENT_TYPE.__dict__

class ForwardHandler(HandlerBase):
    # The memory errors the target reports as events, UCSan's or SymSan's own
    # (a memerr message), become findings at the event's PC.  UBI and NULL used
    # to be left out: SymSan's check then Die()d with exit status 1, which
    # read as a failure with nothing to say why.
    SUB=[PIPE_EVENT_TYPE.EVENT_OOB, PIPE_EVENT_TYPE.EVENT_UAF,
         PIPE_EVENT_TYPE.EVENT_UBI, PIPE_EVENT_TYPE.EVENT_NULL_DEREF]

    def handle(self, msg):
        # msg.addr is the error's own PC (the instrumented access)
        self._manager._report(msg.context, getattr(msg, "addr", 0))

forward_handler = ForwardHandler
