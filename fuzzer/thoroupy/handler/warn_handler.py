"""Handler for kernel WARN() events.

UCSanPass turns a WARN (a _BUG_FLAGS ud2 with BUGFLAG_WARNING) into a call to
ucsan_trace_warn, and the run continues, as it would in the kernel.  Each hit
arrives as an EVENT_WARN:
  msg.context = EVENT_WARN (106, dispatch key)
  msg.result  = source line
  msg.id      = bug flags (BUGFLAG_WARNING | BUGFLAG_ONCE | taint << 8 ...)
  msg.addr    = address of the WARN in the target
Distinct sites (by address) are logged once and kept in `warnings`.
"""

import logging

from control.message.enums import PIPE_EVENT_TYPE
from .handler import HandlerBase

logger = logging.getLogger(__name__)


class warn_handler(HandlerBase):
    SUB = [PIPE_EVENT_TYPE.EVENT_WARN]

    def __init__(self, manager, **kwargs) -> None:
        super().__init__(manager)
        self.warnings = {}  # addr -> (line, flags, hits)

    def handle(self, msg):
        line, flags, hits = self.warnings.get(msg.addr, (msg.result, msg.id, 0))
        if hits == 0:
            logger.critical(f"WARN hit at {msg.addr:#x} (line {line}, flags {flags:#x}), "
                            f"seed: {self._manager._current}")
        self.warnings[msg.addr] = (line, flags, hits + 1)
