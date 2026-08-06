"""Drive a corpus through the wrapper twice, with and without the fork server,
and check that the two traces agree.

The fork server is a pure performance change: it swaps execv, dynamic linking
and the shadow/union table setup for a fork, and nothing about what the target
computes or reports may depend on which one happened.  That is the property
worth a test, because a fork server that quietly serves a stale input still
produces a perfectly plausible-looking event stream -- see the frozen-config
check in config().

Also doubles as the worked example of the staging pattern: the server's input
path is fixed once it is running, so many inputs means rewriting the contents of
one path.  Both arms use that same one path, so the only difference between them
is the fork server itself.

  python3 test_forkserver.py <instrumented-target> [input ...]

With no inputs, a small built-in corpus is used, chosen to vary in length in
both directions -- a run that reads the tail of its predecessor is exactly the
failure a fixed input path invites.

The target must be built with KO_USE_FASTGEN=1; the in-process backend has no
fork server and no event stream to compare.
"""

import ctypes
import os
import sys
import time

import symsan


class pipe_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("type", ctypes.c_uint16),
                ("flags", ctypes.c_uint16),
                ("instance_id", ctypes.c_uint32),
                ("addr", ctypes.c_ulonglong),
                ("context", ctypes.c_uint32),
                ("id", ctypes.c_uint32),
                ("label", ctypes.c_uint32),
                ("result", ctypes.c_uint64)]


class memcmp_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("label", ctypes.c_uint32)]


class table_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("ptr", ctypes.c_ulonglong),
                ("num_elems", ctypes.c_ulonglong),
                ("elem_size", ctypes.c_ulonglong)]


def read_trace():
    """One run's events, as comparable tuples.

    `addr` is deliberately left out.  It is a code address in the traced
    process, and the exec arm re-randomizes the load base on every run while the
    fork arm inherits one layout for the life of the server -- so including it
    would report a difference that is ASLR, not the fork server.  Everything
    that identifies the branch (context, cid) and everything the solver reads
    (label, result, payload) is compared.
    """
    trace = []
    while True:
        e = symsan.read_event(ctypes.sizeof(pipe_msg))
        if len(e) < ctypes.sizeof(pipe_msg):
            break
        msg = pipe_msg.from_buffer_copy(e)
        rec = (msg.type, msg.flags, msg.instance_id, msg.context, msg.id,
               msg.label, msg.result)

        payload = b""
        if msg.type == 2 and msg.flags == 1:      # memcmp content
            want = ctypes.sizeof(memcmp_msg) + msg.result
            payload = symsan.read_event(want)
            if len(payload) < want:
                trace.append(("TRUNCATED-MEMCMP",))
                break
        elif msg.type == 11:                      # table content
            want = ctypes.sizeof(table_msg) + msg.result
            payload = symsan.read_event(want)
            if len(payload) < want:
                trace.append(("TRUNCATED-TABLE",))
                break

        trace.append(rec + (payload,))
    return trace


def sweep(prog, inputs, forkserver):
    """Every input in `inputs`, traced through one staged path."""
    staged = "/dev/shm/symsan-fsrv-%d.input" % os.getpid()
    open(staged, "wb").close()

    symsan.init(prog, init_solver=0)
    symsan.config(staged, args=[prog, staged], forkserver=int(forkserver))

    results = []
    started = time.monotonic()
    for buf in inputs:
        # Truncating write: a short input after a long one would otherwise be
        # read with the tail of its predecessor still attached.
        with open(staged, "wb") as f:
            f.write(buf)

        symsan.run()
        trace = read_trace()
        status, is_killed = symsan.terminate()   # ends the run, keeps the server
        results.append((trace, status, is_killed))

    active = symsan.forkserver_active()
    elapsed = time.monotonic() - started
    symsan.destroy()                             # tears the server down
    os.unlink(staged)
    return results, active, elapsed


def check_frozen_config(prog):
    """A live server must refuse a configuration it cannot honour.

    Every field config() sets travels in the environment the server was spawned
    with, so once it is up none of them can change -- and symsan_run() goes
    straight to the server without re-reading any of it.  The whole point of the
    check is that being ignored here is indistinguishable from working.

    Returns the number of failures.
    """
    staged = "/dev/shm/symsan-frozen-%d.input" % os.getpid()
    elsewhere = staged + ".other"
    for p in (staged, elsewhere):
        with open(p, "wb") as f:
            f.write(b"MAGICHDR" + bytes(range(16)))

    failed = 0
    symsan.init(prog, init_solver=0)
    symsan.config(staged, args=[prog, staged], forkserver=1)
    symsan.run()
    read_trace()
    symsan.terminate()

    if not symsan.forkserver_active():
        symsan.destroy()
        return 0                       # nothing frozen; the sweep reports this

    # One per kind of field: the input path, a target option, and the request
    # itself.  argv is covered by the input case, since it names the same path.
    for kwargs in ({"input": elsewhere}, {"debug": 1}, {"forkserver": 0}):
        call = {"args": [prog, staged], "forkserver": 1}
        call.update(kwargs)
        path = call.pop("input", staged)
        try:
            symsan.config(path, **call)
            print("FAIL: config(%r) accepted while the fork server is running"
                  % kwargs)
            failed += 1
        except RuntimeError:
            pass

    # ...but an identical one is a no-op, not an error: re-stating the same
    # configuration each time round the loop is a reasonable thing to write.
    symsan.config(staged, args=[prog, staged], forkserver=1)
    symsan.run()
    n = read_trace()
    symsan.terminate()
    if not n or not symsan.forkserver_active():
        print("FAIL: the server stopped serving after an identical config()")
        failed += 1
    symsan.destroy()

    # args= is optional and omitting it used to reach PyList_Size(NULL).
    symsan.init(prog, init_solver=0)
    symsan.config(staged)
    symsan.destroy()

    for p in (staged, elsewhere):
        os.unlink(p)
    if not failed:
        print("ok frozen-config: refused input/debug/forkserver, kept serving")
    return failed


# Long, then short, then long again: the short one has to come between two
# longer ones or a stale tail on the staged path would go unnoticed.
BUILTIN_CORPUS = [
    (b"MAGICHDR", b"MAGICHDR" + bytes(range(56))),
    (b"long", bytes(range(64))),
    (b"short", b"ab"),
    (b"mixed", b"AB" + b"\xef\xbe\xad\xde" + b"XY"),
    (b"empty", b""),
    (b"long-again", bytes(range(63, -1, -1))),
]


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    prog = sys.argv[1]
    if len(sys.argv) > 2:
        names = sys.argv[2:]
        inputs = [open(p, "rb").read() for p in names]
    else:
        names = [n.decode() for n, _ in BUILTIN_CORPUS]
        inputs = [b for _, b in BUILTIN_CORPUS]

    exec_runs, exec_active, exec_time = sweep(prog, inputs, forkserver=False)
    if exec_active:
        sys.exit("FAIL: a fork server came up with forkserver=0")

    fork_runs, fork_active, fork_time = sweep(prog, inputs, forkserver=True)
    if not fork_active:
        # Not a failure of this wrapper: the target has no fork server in it,
        # or the input mode cannot use one.  Say so rather than claiming a pass
        # on a comparison of two identical arms.
        sys.exit("SKIP: no fork server for %s (built without KO_USE_FASTGEN?)"
                 % prog)

    failures = 0
    for name, (a, sa, ka), (b, sb, kb) in zip(names, exec_runs, fork_runs):
        if a != b:
            failures += 1
            print("MISMATCH %s: %d events exec, %d fork" % (name, len(a), len(b)))
            for j, (x, y) in enumerate(zip(a, b)):
                if x != y:
                    print("  first differs at event %d:\n    exec %r\n    fork %r"
                          % (j, x, y))
                    break
        elif (sa, ka) != (sb, kb):
            failures += 1
            print("MISMATCH %s: exit (%d,%d) exec vs (%d,%d) fork"
                  % (name, sa, ka, sb, kb))
        else:
            print("ok %s: %d events" % (name, len(a)))

    print("%d inputs, %.3fs exec vs %.3fs fork (%.1fx)"
          % (len(inputs), exec_time, fork_time,
             exec_time / fork_time if fork_time else 0))

    failures += check_frozen_config(prog)

    if failures:
        sys.exit("FAIL: %d check(s) failed" % failures)
    print("PASS")


if __name__ == "__main__":
    main()
