#!/usr/bin/env python3
"""fgtest, in python: trace a target, solve what it branched on, write the
inputs that flip those branches.

Same command line and the same TAINT_OPTIONS as driver/fgtest.cpp, and the same
"generate #N output" result line, so a lit test can point at either one:

    TAINT_OPTIONS="taint_file=<seed>:output_dir=<dir>" test.py <target> <seed>...

What it is for is the binding, not the solving -- everything below goes through
symsan.* and nothing else, so anything the C driver can do and this cannot is a
gap in the wrapper.  It is also the worked example: the event loop here is the
whole protocol, payload draining included.

Options, all read from TAINT_OPTIONS in `k=v:k=v` form, as in fgtest:

    taint_file=stdin   feed the seed on stdin instead of naming it in argv
    output_dir=DIR     where generated inputs go (default ".")
    debug=1            the target's own tracing on stderr
    session_id=N       first session number; each seed gets its own
    solve_ub=1         solve undefined-behaviour checks too
    enum_gep=1         enumerate GEP indices (off by default, as in fgtest)

and two environment variables of its own:

    SYMSAN_VERBOSE=1   the per-event trace, off by default -- it is millions of
                       lines over a corpus and costs more than the parse
    SYMSAN_NO_FORKSRV=1  exec per seed even for a corpus, for A/B measurement

Not ported: SYMSAN_PARSE_ONLY.  Its report is built from last_error() and
retrieve_task(), neither of which the binding exposes; fgtest is the tool for
that sweep.
"""

import ctypes
import os
import re
import sys

import symsan


# The wire format, from runtime/dfsan/dfsan.h.  Kept in the same order and with
# the same names, because the only thing keeping the two in step is that a
# reader can put them side by side.
class pipe_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("msg_type", ctypes.c_uint16),
                ("flags", ctypes.c_uint16),
                ("instance_id", ctypes.c_uint32),
                ("addr", ctypes.c_uint64),
                ("context", ctypes.c_uint32),
                ("id", ctypes.c_uint32),
                ("label", ctypes.c_uint32),
                ("result", ctypes.c_uint64)]


class gep_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("ptr_label", ctypes.c_uint32),
                ("index_label", ctypes.c_uint32),
                ("ptr", ctypes.c_uint64),
                ("index", ctypes.c_int64),
                ("num_elems", ctypes.c_uint64),
                ("elem_size", ctypes.c_uint64),
                ("current_offset", ctypes.c_int64)]


class memcmp_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("label", ctypes.c_uint32)]


class table_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("ptr", ctypes.c_uint64),
                ("num_elems", ctypes.c_uint64),
                ("elem_size", ctypes.c_uint64)]


# pipe_msg_type
COND_TYPE = 0
GEP_TYPE = 1
MEMCMP_TYPE = 2
ADD_CONSTRAINT_TYPE = 3
MINIMIZE_TYPE = 10
TABLE_TYPE = 11

F_ADD_CONS = 0x1        # this condition's constraint is part of a nested task


def ptr(addr):
    """A code address, spelled the way C's %p spells it, so the two drivers'
    verbose output diffs clean against each other."""
    return "(nil)" if addr == 0 else "0x%x" % addr

SOLVE_TIMEOUT = 30000   # ms, as in fgtest


class Options:
    """TAINT_OPTIONS, parsed the way fgtest parses it."""

    def __init__(self, env=None):
        opts = {}
        # ':' or whitespace, because both are in use: the runtime's own flag
        # parser takes either, the lit tests write spaces and the drivers write
        # colons.  Neither separator can appear inside a value, here or in
        # fgtest -- a path with a space in it was never going to survive.
        for field in re.split(r"[:\s]+",
                              env or os.environ.get("TAINT_OPTIONS", "")):
            if "=" in field:
                k, v = field.split("=", 1)
                opts[k] = v

        self.output_dir = opts.get("output_dir", ".")
        self.is_stdin = opts.get("taint_file") == "stdin"
        self.debug = opts.get("debug") in ("1", "true")
        self.solve_ub = opts.get("solve_ub") in ("1", "true")
        # Off by default, which is what ConcolicSession does too -- so this
        # matches the path the fuzzer actually runs rather than the one that
        # enumerates every index.
        self.enum_gep = opts.get("enum_gep") in ("1", "true")
        self.session_id = int(opts.get("session_id", 0))
        self.instance_id = 0

        self.verbose = "SYMSAN_VERBOSE" in os.environ
        self.no_forksrv = "SYMSAN_NO_FORKSRV" in os.environ


class Driver:
    def __init__(self, program, opts):
        self.program = program
        self.opts = opts
        self.session_id = opts.session_id
        self.index = 0          # monotonic across seeds, so nothing collides
        self.input = b""        # the seed being traced, for generate_input
        self.staged = None      # fixed path a fork server reads, or None

    # -- output ------------------------------------------------------------

    def trace(self, fmt, *a):
        if self.opts.verbose:
            print(fmt % a if a else fmt)

    def generate_input(self, solutions):
        """Apply one task's solution to the seed and write the result out."""
        buf = bytearray(self.input)

        # Descending offset order: an INSERT or DELETE at a low offset would
        # otherwise move everything a later solution refers to.
        for sol in sorted(solutions, key=lambda s: s["offset"], reverse=True):
            off = sol["offset"]
            if sol["op"] == symsan.OpType.SET:
                if off < len(buf):
                    self.trace("SET offset %d = %x", off, sol["val"])
                    buf[off] = sol["val"]
            elif sol["op"] == symsan.OpType.INSERT:
                if off <= len(buf):
                    self.trace("INSERT %d bytes at offset %d",
                               len(sol["data"]), off)
                    buf[off:off] = sol["data"]
            elif sol["op"] == symsan.OpType.DELETE:
                if off < len(buf):
                    n = min(sol["len"], len(buf) - off)
                    self.trace("DELETE %d bytes at offset %d", n, off)
                    del buf[off:off + n]

        path = os.path.join(self.opts.output_dir, "id-%d-%d-%d" % (
            self.opts.instance_id, self.session_id, self.index))
        self.index += 1
        try:
            with open(path, "wb") as f:
                f.write(buf)
        except OSError as e:
            print("failed to open new input file for write: %s" % e)
            return

        # A result line, not a trace: tests match on it.
        print("generate #%d output (size: %d -> %d)"
              % (self.index - 1, len(self.input), len(buf)))

    def solve(self, tasks, what, addr):
        for task in tasks:
            status, solutions = symsan.solve_task(task, SOLVE_TIMEOUT)
            if solutions:
                self.trace("%s solved", what)
                self.generate_input(solutions)
            else:
                self.trace("%s not solvable @%s", what, ptr(addr))

    # -- events -------------------------------------------------------------

    def handle_cond(self, msg):
        self.trace("solving label %d = %d, add_nested: %d",
                   msg.label, msg.result, msg.flags & F_ADD_CONS)
        try:
            tasks = symsan.parse_cond(msg.label, msg.result, msg.flags)
        except RuntimeError:
            self.trace("WARNING: failed to parse condition %d @%s",
                       msg.label, ptr(msg.addr))
            return
        self.solve(tasks, "branch", msg.addr)

    def handle_gep(self, msg):
        raw = symsan.read_event(ctypes.sizeof(gep_msg))
        if len(raw) < ctypes.sizeof(gep_msg):
            print("Failed to receive gep msg", file=sys.stderr)
            return
        g = gep_msg.from_buffer_copy(raw)
        if msg.label != g.index_label:
            print("Incorrect gep msg: %d vs %d" % (msg.label, g.index_label),
                  file=sys.stderr)
            return

        self.trace("tainted GEP index: %d = %d, ne: %d, es: %d, offset: %d",
                   g.index, g.index_label, g.num_elems, g.elem_size,
                   g.current_offset)
        try:
            tasks = symsan.parse_gep(g.ptr_label, g.ptr, g.index_label, g.index,
                                     g.num_elems, g.elem_size, g.current_offset,
                                     self.opts.enum_gep)
        except RuntimeError:
            self.trace("WARNING: failed to parse gep %d @%s",
                       g.index_label, ptr(msg.addr))
            return
        self.solve(tasks, "gep", msg.addr)

    def handle_memcmp(self, msg):
        # flags == 0 means both operands are symbolic, so there is no concrete
        # content following and nothing to drain.
        if not msg.flags:
            return
        want = ctypes.sizeof(memcmp_msg) + msg.result
        raw = symsan.read_event(want)
        if len(raw) < want:
            print("Failed to receive memcmp msg", file=sys.stderr)
            return
        m = memcmp_msg.from_buffer_copy(raw)
        if m.label != msg.label:
            print("Incorrect memcmp msg: %d vs %d" % (msg.label, m.label),
                  file=sys.stderr)
            return
        symsan.record_memcmp(msg.label, raw[ctypes.sizeof(memcmp_msg):])

    def handle_table(self, msg):
        # The z3 backend declines tlookup, so these contents go unused -- but
        # the payload must still be drained or every later event is misread.
        # Recorded anyway, so a future implementation only touches the solver.
        want = ctypes.sizeof(table_msg) + msg.result
        raw = symsan.read_event(want)
        if len(raw) < want:
            print("Failed to receive table msg", file=sys.stderr)
            return
        t = table_msg.from_buffer_copy(raw)
        if t.num_elems * t.elem_size != msg.result:
            print("Incorrect table msg: %d x %d vs %d"
                  % (t.num_elems, t.elem_size, msg.result), file=sys.stderr)
            return
        symsan.record_table(t.ptr, raw[ctypes.sizeof(table_msg):])

    def drain(self):
        """Read and dispatch one run's events, to end of trace."""
        n = ctypes.sizeof(pipe_msg)
        events = 0
        while True:
            raw = symsan.read_event(n)
            if len(raw) < n:
                break
            events += 1
            msg = pipe_msg.from_buffer_copy(raw)
            if msg.msg_type == COND_TYPE:
                self.handle_cond(msg)
            elif msg.msg_type == GEP_TYPE:
                self.handle_gep(msg)
            elif msg.msg_type == MEMCMP_TYPE:
                self.handle_memcmp(msg)
            elif msg.msg_type == TABLE_TYPE:
                self.handle_table(msg)
            elif msg.msg_type == ADD_CONSTRAINT_TYPE:
                symsan.add_constraint(msg.label, msg.result)
            elif msg.msg_type == MINIMIZE_TYPE:
                symsan.record_minimize(msg.label)
        return events

    # -- runs ----------------------------------------------------------------

    def run_one(self, path):
        """Trace one seed end to end.  Returns 0, or -1 if it could not run."""
        try:
            with open(path, "rb") as f:
                self.input = f.read()
        except OSError as e:
            print("Failed to open input file %s: %s" % (path, e),
                  file=sys.stderr)
            return -1

        if self.staged:
            # The input path and argv were fixed when the fork server was
            # spawned; only the contents change.  Truncating write: a short seed
            # after a long one would otherwise be read with the tail of its
            # predecessor still attached.
            with open(self.staged, "wb") as f:
                f.write(self.input)
        else:
            symsan.config("stdin" if self.opts.is_stdin else path,
                          args=[self.program, path],
                          debug=int(self.opts.debug), bounds=1,
                          undefined=int(self.opts.solve_ub))

        try:
            if self.opts.is_stdin:
                symsan.run(stdin=path)
            else:
                symsan.run()
        except (OSError, ValueError) as e:
            print("Failed to launch target: %s" % e, file=sys.stderr)
            return -1

        # The parser needs the seed's bytes to evaluate what the trace reports
        # against, so this has to happen after run() and before the first event.
        symsan.reset_input([self.input])

        self.drain()
        symsan.terminate()
        return 0


def main():
    if len(sys.argv) < 3:
        sys.exit("Usage: %s target input [input...]" % sys.argv[0])

    program = sys.argv[1]
    inputs = sys.argv[2:]

    # A target that cannot be exec'd is not an error further down: the launcher
    # forks, execv fails in the child, and every read comes back empty -- which
    # over a corpus reads exactly like a target that parses cleanly.
    if not os.access(program, os.X_OK):
        sys.exit("Cannot execute %s" % program)

    opts = Options()
    symsan.init(program)
    driver = Driver(program, opts)

    # More than one seed: serve them all from one fork server, which skips
    # execv, dynamic linking and the shadow and union table setup per seed.
    # That needs a single fixed input path, so it is only on for a corpus -- a
    # lone seed keeps running where it lies, which is what every existing caller
    # expects.  A stdin target is excluded: its fd has to be wired up per run.
    many = len(inputs) > 1
    if many and not opts.is_stdin and not opts.no_forksrv:
        driver.staged = os.path.join(
            os.environ.get("TMPDIR", "/dev/shm"), "pyfgtest-%d.input" % os.getpid())
        with open(driver.staged, "wb"):
            pass
        symsan.config(driver.staged, args=[program, driver.staged],
                      debug=int(opts.debug), bounds=1,
                      undefined=int(opts.solve_ub), forkserver=1)

    session_base = opts.session_id
    failures = 0
    for i, path in enumerate(inputs):
        if many:
            # Generated inputs are named id-<instance>-<session>-<index>, so
            # give each seed its own session: without it a corpus run's output
            # is one flat sequence with nothing saying which seed produced what.
            driver.session_id = session_base + i
        if driver.run_one(path) != 0:
            failures += 1

    symsan.destroy()
    if driver.staged:
        os.unlink(driver.staged)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
