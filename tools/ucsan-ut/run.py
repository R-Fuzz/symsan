#!/usr/bin/env python3
"""Run one UCSan unit-test entry under UcsanManager and write result.json.

fuzzer/thoroupy/debug.py's job, for a UT entry (tools/ucsan-ut) rather than a
hand debugging session: it explores, and everything worth reading afterwards
goes into <workdir>/result.json -- each seed that ran with its exit status and
its objects' bytes, the exit statuses and events, the event sites (symbolized
with --symbolize), coverage, and the [FLIP-DBG] records of a --target branch.

  run.py BINARY [--workdir DIR] [--budget SECONDS] [--trace-only]
         [--seed FILE] [--target BID [--target-result 0|1]]
         [--loop-threshold N] [--ucsan-option K=V]... [--taint-option K=V]...
         [--config JSON] [--symbolize]

BINARY is the instrumented program itself, not a wrapper script: the manager
watches the process it started, and a wrapper (gdb, say) that exits after the
first child is a dead target to it -- it stops after one seed.

Run it with the venv python and b4/lib/symsan on PYTHONPATH (the `symsan`
extension module), as tests/ucsan/test.py.
"""
import argparse
import collections
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "fuzzer", "thoroupy"))

TARGET_TAIL_BYTES = 8192
MAX_FLIP_LINES = 200

# debug.py's defaults, with what a UT entry needs (see tools/ucsan-ut/README.md
# and the v8 fixture): globals are the test's concrete state, a null the
# program dereferences is a finding, and SymSan's uninitialized-shadow branch
# is a report, not the end of the trace (exit_on_memerror).
DEFAULT_UCSAN_OPTIONS = {
    "checker_ubi": "1",
    "checker_nullderef": "1",
    "trace_bounds": "1",
    "no_enlarge": "1",
    "concrete_globals": "1",
}
DEFAULT_TAINT_OPTIONS = {
    "trace_bounds": "1",
    "solve_ub": "1",
    "exit_on_poison": "0",
    "exit_on_memerror": "0",
}


def build_config(loop_threshold, bbtrace):
    config = {
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
        "stop_on_error": False,
    }
    if bbtrace:
        config["handler"]["bbtrace_handler"] = {"output": "bbtrace.txt"}
    return config


def deep_merge(base, override):
    result = dict(base)
    for key, value in override.items():
        if isinstance(result.get(key), dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def seed_record(seed):
    """A seed's objects as bytes: value and lvalue in hex, and the first 4 and
    8 value bytes as little-endian integers (an int argument reads off them)."""
    objects = []
    for i, o in enumerate(getattr(seed, "objects", ()) or ()):
        value = b"".join(o.value)
        rec = {"index": i, "value": value.hex(),
               "lvalue": b"".join(o.lvalue[::-1]).hex()}
        if len(value) >= 4:
            rec["i32"] = int.from_bytes(value[:4], "little", signed=True)
        if len(value) >= 8:
            rec["i64"] = int.from_bytes(value[:8], "little", signed=True)
        objects.append(rec)
    return objects


def normalize(status):
    return status >> 8 if status > 255 else status


class Capture(logging.Handler):
    """Per seed, the exit status the manager logs, with the seed that ran; the
    [FLIP-DBG] records; and the tail of the target's own output."""

    FINISH = re.compile(r"Finish one seed, exit with code: (-?\d+)")

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.manager = None
        self.seeds = []
        self.flip = []
        self.errors = []
        self.proc_died = False
        self.tail = b""

    def emit(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            return
        if record.name == "output_monitor":
            text = msg.replace("\033[96m", "").replace("\033[0m", "").strip("\n")
            if text:
                self.tail = (self.tail + text.encode(errors="replace") +
                             b"\n")[-TARGET_TAIL_BYTES:]
            return
        m = self.FINISH.search(msg)
        if m and self.manager is not None:
            status = int(m.group(1))
            self.seeds.append({"exit": normalize(status), "wait_status": status,
                               "objects": seed_record(self.manager._current)})
        elif "[FLIP-DBG]" in msg and len(self.flip) < MAX_FLIP_LINES:
            self.flip.append(msg)
        elif "Process terminaed unexpectedly" in msg:
            self.proc_died = True
        elif record.levelno == logging.ERROR and len(self.errors) < 50:
            self.errors.append(msg[:400])


def symbolize(binary, addrs):
    """addr -> its frames, innermost first, as "function file:line"
    (llvm-addr2line-18 -i; one call per address, since its output has no
    separator between one address's inlined frames and the next's)."""
    result = {}
    for a in addrs:
        try:
            out = subprocess.run(
                ["llvm-addr2line-18", "-f", "-C", "-i", "-e", binary, "%#x" % a],
                capture_output=True, text=True, timeout=120).stdout.splitlines()
        except (OSError, subprocess.TimeoutExpired):
            continue
        result["%#x" % a] = ["%s %s" % (out[j], out[j + 1])
                             for j in range(0, len(out) - 1, 2)]
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("binary")
    ap.add_argument("--workdir", default=".")
    ap.add_argument("--budget", type=float, default=0,
                    help="seconds; the manager stops after the seed in flight "
                         "(0: until the queue is empty)")
    ap.add_argument("--trace-only", action="store_true",
                    help="concrete replay: no solving")
    ap.add_argument("--seed", default=None, help="a seed file to start from")
    ap.add_argument("--target", type=int, default=None, metavar="BID",
                    help="a branch to debug: [FLIP-DBG] logs its label, the "
                         "solver's answers and whether replaying them flips it")
    ap.add_argument("--target-result", type=int, default=1,
                    help="the target's direction on the first seed")
    ap.add_argument("--target-occurrence", type=int, default=1)
    ap.add_argument("--loop-threshold", type=int, default=10)
    ap.add_argument("--ucsan-option", action="append", default=[],
                    metavar="K=V", help="UCSAN_OPTIONS flag")
    ap.add_argument("--taint-option", action="append", default=[],
                    metavar="K=V", help="TAINT_OPTIONS flag")
    ap.add_argument("--config", default=None,
                    help="JSON merged over the defaults: {ucsan_config, "
                         "ucsan_options, taint_options}, as debug.py's")
    ap.add_argument("--bbtrace", action="store_true",
                    help="write the (function, block) trace to bbtrace.txt")
    ap.add_argument("--symbolize", action="store_true",
                    help="symbolize the event sites (llvm-addr2line-18)")
    args = ap.parse_args()

    # The manager forks and execve()s the binary; if that fails the child goes
    # on running the manager's code, so a bad path hangs rather than fails.
    binary = os.path.abspath(args.binary)
    if not os.access(binary, os.X_OK):
        sys.exit(f"run.py: {binary} is not an executable file")
    seed = os.path.abspath(args.seed) if args.seed else None
    config_path = os.path.abspath(args.config) if args.config else None
    os.makedirs(args.workdir, exist_ok=True)
    os.chdir(args.workdir)  # current_seed.bin, blocking/, task_*.smt2 land here
    os.makedirs("blocking", exist_ok=True)  # _bug() saves each finding's seed

    config = {"ucsan_config": build_config(args.loop_threshold, args.bbtrace),
              "ucsan_options": dict(DEFAULT_UCSAN_OPTIONS),
              "taint_options": dict(DEFAULT_TAINT_OPTIONS)}
    if config_path:
        with open(config_path) as f:
            config = deep_merge(config, json.load(f))
    for opt in args.ucsan_option:
        k, _, v = opt.partition("=")
        config["ucsan_options"][k] = v
    for opt in args.taint_option:
        k, _, v = opt.partition("=")
        config["taint_options"][k] = v
    env = dict(config["taint_options"])
    env["ucsan_options"] = dict(config["ucsan_options"])

    # manager (and the schedulers it imports) bind debug_config.target_branch
    # when imported, so it is set first
    import debug_config
    if args.target is not None:
        debug_config.target_branch = {
            "bid": args.target,
            "context": 0,
            "occurrence": args.target_occurrence,
            "original_result": args.target_result,
            "verify_flip": True,
            "stop_if_not_flipped": False,
            "stop_if_not_reached": False,
        }

    cap = Capture()
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fh = logging.FileHandler("run.log", mode="w")
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter(
        "[%(asctime)s] %(name)s %(levelname)s - %(message)s"))
    root.addHandler(fh)
    root.addHandler(cap)
    # the target's own output, read by the manager's monitor thread, only
    # into the capture's tail
    out_log = logging.getLogger("output_monitor")
    out_log.setLevel(logging.DEBUG)
    out_log.propagate = False
    out_log.addHandler(cap)

    result = {"binary": binary, "workdir": os.getcwd(), "config": config,
              "target": args.target, "budget": args.budget,
              "budget_exhausted": False, "exception": None}
    start = time.time()
    events = collections.Counter()
    m = None
    try:
        from manager import UcsanManager
        m = UcsanManager(binary, seed=seed, config=config["ucsan_config"],
                         env=env, trace_only=args.trace_only)
        cap.manager = m
        # every event the handlers get, (event, PC): the manager's own
        # event_counts sees UCSan's events only, and SymSan's memory errors
        # (a UBI from library code, say) reach the handlers as MERRO messages
        from control.message.enums import PIPE_EVENT_TYPE
        dispatch = m._event_handlers.handle

        def counted(msg):
            if msg.context != PIPE_EVENT_TYPE.TRACE_BB:
                events[(int(msg.context), int(getattr(msg, "addr", 0)))] += 1
            return dispatch(msg)
        m._event_handlers.handle = counted
        if args.budget > 0:
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
        result["seeds"] = cap.seeds
        if m is not None:
            result["exit_counts"] = dict(collections.Counter(
                str(normalize(s)) for s in m.exit_status))
            per_event = collections.Counter()
            for (event, _), n in events.items():
                per_event[event] += n
            result["events"] = {str(k): v for k, v in sorted(per_event.items())}
            result["event_sites"] = {"%d@%#x" % k: v
                                     for k, v in sorted(events.items())}
            tm = getattr(m, "_termination_manager", None)
            result["blocks"] = len(getattr(tm, "blocks", ()))
            result["directions"] = len(getattr(tm, "directions", ()))
            if args.symbolize:
                addrs = sorted({addr for (_, addr) in events if addr})
                result["event_symbols"] = symbolize(binary, addrs)
        result["flip"] = cap.flip
        result["proc_died"] = cap.proc_died
        result["errors"] = cap.errors
        result["target_tail"] = cap.tail.decode(errors="replace")
        with open("result.json", "w") as f:
            json.dump(result, f, indent=1)
    # the manager leaves threads and a forkserver behind; do not wait for them
    os._exit(0)


if __name__ == "__main__":
    main()
