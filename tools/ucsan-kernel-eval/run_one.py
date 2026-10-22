#!/usr/bin/env python3
"""Run one UCSan-instrumented binary under UcsanManager and write result.json.

The manager side of eval.py.  It mirrors fuzzer/thoroupy/debug.py (same
termination/handler/runtime options) but is meant to be run by a batch driver:
it has a wall-clock budget, and everything the driver needs to classify the run
goes into <workdir>/result.json instead of a log to be read by hand.

  run_one.py <binary> [--workdir DIR] [--budget SECONDS] [--loop-threshold N]

The budget is soft: when it runs out the manager is told to stop after the seed
in flight, and "budget_exhausted" is set.  A seed that never returns (a hang in
the target) cannot be stopped from in here; the driver kills the process group
and calls that a hang.

Run it with the venv python (needs pyelftools, PyYAML, psutil) and
b4/lib/symsan on PYTHONPATH (the `symsan` extension module).
"""
import argparse
import collections
import json
import logging
import os
import sys
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "fuzzer", "thoroupy"))

TARGET_TAIL_BYTES = 4096
MAX_ERRORS = 20
MAX_LOG_BYTES = 16384  # run.log is a hard-capped sample, never the full log
MAX_LINE = 400


class Capture(logging.Handler):
    """Keeps what the driver classifies on, and nothing else.

    The manager logs every seed at INFO, which for a long budget is megabytes
    of text nobody reads; only the ERROR+ records, the "target died" record and
    the tail of the target's own stdout/stderr (its FATAL/ERROR lines) matter.
    """

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.errors = []
        self.proc_died = False
        self.tail = b""
        self.log = []
        self._log_bytes = 0

    def emit(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            return
        if record.name == "output_monitor":
            # "\033[96m\n<text>\033[0m"; the monitor thread also spins on an
            # empty read once the target is gone, which carries no text.
            text = msg.replace("\033[96m", "").replace("\033[0m", "").strip("\n")
            if text:
                self.tail = (self.tail + text.encode(errors="replace") + b"\n")[-TARGET_TAIL_BYTES:]
            return
        if "Process terminaed unexpectedly" in msg:
            self.proc_died = True
        if record.levelno >= logging.WARNING and self._log_bytes < MAX_LOG_BYTES:
            line = f"{record.name} {record.levelname} {msg}"[:MAX_LINE]
            self.log.append(line)
            self._log_bytes += len(line) + 1
        # ERROR only: the manager's CRITICAL records are bookkeeping ("Found
        # bug", "New branch reached", ...), not failures
        if (record.levelno == logging.ERROR and "New branch reached" not in msg
                and len(self.errors) < MAX_ERRORS and msg[:MAX_LINE] not in self.errors):
            self.errors.append(msg[:MAX_LINE])


def build_config(loop_threshold):
    # debug.py's config, minus bbtrace_handler (its output file grows with the
    # trace and this is a compatibility run, not a debugging session), plus
    # warn_handler as in tests/ucsan/test.py so kernel WARN events are consumed.
    return {
        "termination": {
            "loop": {"threshold": loop_threshold, "skip_solve": False},
            "branch": {"always_true": False, "path_sensitive": False},
        },
        "handler": {
            "ubi_handler": {},
            "objtrace_handler": {},
            "forward_handler": {},
            "warn_handler": {},
        },
        "scheduler": {"fifo": {"checksum": True}},
        "enum_index": False,
        # explore the whole queue rather than halting at the first finding, so
        # one early PANIC does not hide a crash on a later path
        "stop_on_error": False,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--workdir", default=".")
    ap.add_argument("--budget", type=float, default=60.0)
    ap.add_argument("--loop-threshold", type=int, default=5)
    args = ap.parse_args()

    # Resolve before the chdir.  It must also exist: the manager forks and then
    # execve()s, and if that fails the *child* carries on running the manager's
    # code (there is no _exit after it), so a bad path is a hang, not an error.
    binary = os.path.abspath(args.binary)
    if not os.access(binary, os.X_OK):
        sys.exit(f"run_one: {binary} is not an executable file")
    os.makedirs(args.workdir, exist_ok=True)
    os.chdir(args.workdir)  # the manager drops current_seed.bin, blocking/, ... in cwd

    cap = Capture()
    root = logging.getLogger()
    # WARNING+ everywhere (the manager's per-seed INFO is dropped before it is
    # formatted); only the target's own output, read by the monitor thread, is
    # let through at DEBUG.
    root.setLevel(logging.WARNING)
    root.addHandler(cap)
    logging.getLogger("output_monitor").setLevel(logging.DEBUG)

    result = {
        "binary": binary,
        "budget": args.budget,
        "budget_exhausted": False,
        "seeds": 0,
        "exit_counts": {},
        "events": {},
        "exception": None,
        "proc_died": False,
        "errors": [],
        "target_tail": "",
        "elapsed": 0.0,
    }
    start = time.time()

    # solver-side ub options as debug.py: the taint options label the object
    # bound, the ucsan options trace it
    env = {"trace_bounds": "1", "solve_ub": "1",
           # a poison-flag violation (nsw/nuw/exact) on the seed's made-up
           # values is a finding, not the end of the run: it goes on with
           # the poisoned value concrete (dfsan.cpp poison_check)
           "exit_on_poison": "0"}
    # checker_nullderef: a NULL the program itself dereferences is reported
    # (a finding, EVENT_NULL_DEREF), not left to fault, so what is left as a
    # SIGSEGV is a UCSan/SymSan failure and not a NULL the kernel code returned
    env["ucsan_options"] = {"checker_nullderef": "1", "checker_ubi": "1",
                            "trace_bounds": "1", "no_enlarge": "1"}

    m = None
    try:
        from manager import UcsanManager
        m =UcsanManager(binary, config=build_config(args.loop_threshold), env=env)

        def watchdog():
            time.sleep(args.budget)
            result["budget_exhausted"] = True
            m._stop_requested = True
        threading.Thread(target=watchdog, daemon=True).start()

        m.run()
    except BaseException:
        result["exception"] = traceback.format_exc()[-3000:]
    finally:
        result["elapsed"] = round(time.time() - start, 2)
        if m is not None:
            result["exit_counts"] = dict(collections.Counter(str(s) for s in m.exit_status))
            result["events"] = {str(k): v for k, v in m.event_counts.items()}
            result["seeds"] = getattr(m.scheduler, "_counter", 0)
        result["proc_died"] = cap.proc_died
        result["errors"] = cap.errors
        result["target_tail"] = cap.tail.decode(errors="replace")
        with open("result.json", "w") as f:
            json.dump(result, f, indent=1)
        with open("run.log", "w") as f:
            f.write("\n".join(cap.log) + "\n")
    # the manager leaves threads and a forkserver behind; do not wait for them
    os._exit(0)


if __name__ == "__main__":
    main()
