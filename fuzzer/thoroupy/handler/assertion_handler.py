"""Handler for assertion events from harness contracts.

Records per-seed assertion outcomes (pass/fail with contract ID and kind).

Message fields (from __taint_trace_event_addr):
  msg.context  = EVENT_ASSERTION (103, dispatch key)
  msg.result   = assertion_id    (harness contract ID)
  msg.id       = assertion_type  (ucsan_assertion_type enum)
  msg.label    = taint label
  msg.addr     = pointer address
"""

import logging
from dataclasses import dataclass

from control.message.enums import PIPE_EVENT_TYPE
from .handler import HandlerBase

logger = logging.getLogger(__name__)

# Mirrors ucsan_assertion_type enum
ASSERTION_TYPE = {
    0: "none",
    1: "none_symbolic",
    2: "allocated_failed",
    3: "allocated_success",
    4: "freed_failed",
    5: "freed_success",
    6: "init_failed",
    7: "init_success",
    8: "cond_failed",
    9: "cond_success",
    10: "assumption_contraction",
}


@dataclass
class AssertionEvent:
    assertion_id: int
    assertion_type: str
    failed: bool
    label: int
    addr: int
    seed_index: int


class assertion_handler(HandlerBase):
    """Collects assertion events emitted by ucsan harness contracts."""

    SUB = [PIPE_EVENT_TYPE.EVENT_ASSERTION]

    def __init__(self, manager: "UcsanManager") -> None:
        super().__init__(manager)
        self._seed_index: int = 0
        self._events: list[AssertionEvent] = []
        self._per_seed: list[AssertionEvent] = []

    def handle(self, msg) -> None:
        atype = ASSERTION_TYPE.get(msg.id, f"unknown({msg.id})")
        failed = "failed" in atype or atype in ("none", "none_symbolic")
        evt = AssertionEvent(
            assertion_id=int(msg.result),
            assertion_type=atype,
            failed=failed,
            label=int(msg.label),
            addr=int(msg.addr) if msg.addr is not None else 0,
            seed_index=self._seed_index,
        )
        self._per_seed.append(evt)
        self._events.append(evt)
        level = logging.WARNING if failed else logging.DEBUG
        logger.log(
            level,
            f"[Assertion] id={evt.assertion_id} type={evt.assertion_type} "
            f"label={evt.label:#x} seed={evt.seed_index}"
        )

    def on_seed_done(self) -> None:
        """Called by manager when a seed execution finishes (EXIT_TYPE)."""
        if self._per_seed:
            n_fail = sum(1 for e in self._per_seed if e.failed)
            n_pass = len(self._per_seed) - n_fail
            logger.info(
                f"[Assertion] Seed {self._seed_index}: "
                f"{n_pass} passed, {n_fail} failed"
            )
        self._per_seed = []
        self._seed_index += 1

    @property
    def events(self) -> list[AssertionEvent]:
        return self._events

    def summary(self) -> dict:
        """Return structured summary of all assertion events."""
        by_id: dict[int, list[AssertionEvent]] = {}
        for evt in self._events:
            by_id.setdefault(evt.assertion_id, []).append(evt)

        results = []
        for aid, evts in sorted(by_id.items()):
            failures = [e for e in evts if e.failed]
            successes = [e for e in evts if not e.failed]
            results.append({
                "assertion_id": aid,
                "types": sorted({e.assertion_type for e in evts}),
                "fail_count": len(failures),
                "pass_count": len(successes),
                "fail_seeds": sorted({e.seed_index for e in failures}),
                "pass_seeds": sorted({e.seed_index for e in successes}),
            })
        return {
            "total_events": len(self._events),
            "total_seeds": self._seed_index,
            "assertions": results,
        }
