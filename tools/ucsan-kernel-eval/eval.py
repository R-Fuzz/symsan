#!/usr/bin/env python3
"""Evaluate UCSan's compatibility with the Linux kernel, one function at a time.

  tools/ucsan-kernel-eval/eval.py [options] [--root DIR] [--out DIR]

For every bitcode module in <root>/bclist and every function that module
defines (with a body), this makes that function the whole UCSan scope
(`entry: f`, `scope: [f]`; every other function becomes a dangle stub),
compiles it with UCSanPass+TaintPass (`ucsan_opt -b -i -t`), links it, runs it
under UcsanManager (run_one.py) for a bounded time, and logs every way that
went wrong.  The stage that failed is the classification:

  normalize   the module could not be prepared
  instrument  opt (UCSanPass/TaintPass) crashed or reported an error
  codegen     llc rejected the instrumented IR
  link        an unresolved symbol, or ko-clang failed
  run         the target crashed / exited with an unexpected status, the
              manager raised, the solver reported an error, or a seed hung.
              UCSan turns SIGSEGV into a silent exit(1); those are re-run under
              strace -k to name the faulting function ("segv" failures)

An exit status that is a *bug report* (UBI, UAF, OOB, PANIC, kernel BUG, ...)
is a finding, not a failure; they are counted separately.  See FINDING_CODES.

Kernel modules are normalized first (see normalize()): the kernel's own ABI
attributes -- return thunks, fentry, no-SSE, kernel code model, ... -- cannot
be linked and run as a userspace program, and are not what is being evaluated.
For the same reason every binary is linked with link_args(), a stub for the
thunk that module asm still jumps to.  Module asm with absolute 32-bit
relocations (R_X86_64_32S: alternatives, kprobe templates) cannot link at all:
the runtime places the whole image at 0x700000000000, out of their reach, PIE
or not.  Those stay link/pie-relocation failures, a harness limit.

Every function is built with ucsan_opt -r: an out-of-scope callee (a stub, since
only the one function is in scope) resigns its pointer arguments, i.e. what they
point to becomes fresh symbolic input, as if the callee may have written it.
Without that, a stack variable passed to a callee to initialize stays marked
uninitialized and its first read is reported as a UBI (--no-resign for an A/B).

A variadic entry function (panic, _printk, ...) is recorded as "skip", not as a
failure: the pass does not support one, and nothing says it should.  So is a
function with a custom wrapper in the abilists (lib/string.o's strcpy, ...):
calls to it, the driver's included, go to the runtime's model of it, so its own
body never runs and there is nothing of it to evaluate.

Output (all logs are size-capped; nothing here is a full log):
  <out>/results.tsv     one short line per function: module, function, status,
                        failing stage, seeds, seconds, findings, blocks,
                        directions -- the last two coverage: basic blocks
                        executed and symbolic branch directions taken, over
                        the run.  Compare coverage, not seeds: a loop over a
                        mask makes hundreds of seeds that take the same few
                        branches (__pcpu_freelist_pop: 1106 seeds, 21
                        branches; 13 seeds, 26 branches once its bit index was
                        symbolic)
  <out>/failures.jsonl  one record per failed function, with a capped excerpt
  <out>/summary.txt     failures grouped by (stage, kind, signature)
  <out>/funcs/...       work dir of each *failed* function, with repro.sh
  <out>/modules/...     normalized modules (deleted as they complete)
A rerun resumes: functions already in results.tsv are skipped (--fresh to redo).

Long runs (the whole kernel is ~57k functions, hours at --jobs 8):
  * SYMSAN_HOME=<copy of b4/bin + b4/lib> runs against a frozen build, so a
    rebuild or `make install` mid-run cannot change the results.  ucsan_opt and
    ko-clang find their libraries relative to themselves, so the copy is enough.
  * --mem-limit-gb (default 6) kills a function's processes above that RSS and
    records "memory-limit".  Without it a runaway target (one reached 59 GB, see
    HANDOFF-ucsan-unbounded-memops.md) is an outage of the whole machine.
  * --retest DIR reruns only what failed in an earlier --out DIR; use it, without
    SYMSAN_HOME, to check a fix against the installed b4/.
  * the driver has no wall-clock limit of its own; run it in tmux, not as a
    tool-limited background job (those stop after 2 hours).
"""
import argparse
import collections
import concurrent.futures as cf
import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SYMSAN = os.environ.get("SYMSAN_HOME", os.path.join(REPO, "b4"))
UCSAN_OPT = os.path.join(SYMSAN, "bin", "ucsan_opt")
RUN_ONE = os.path.join(HERE, "run_one.py")
VENV_PY = os.path.join(REPO, "venv", "bin", "python")
LLVM_DIS = os.environ.get("LLVM_DIS", "llvm-dis-18")
LLVM_AS = os.environ.get("LLVM_AS", "llvm-as-18")

# exit statuses (runtime/dfsan/ucsan_exit_reason.h) that are UCSan doing its job
FINDING_CODES = {
    150: "UBI", 151: "UAF", 152: "OOB", 153: "NULL_DEREF", 154: "DIV_BY_ZERO",
    155: "INT_OVERFLOW", 156: "DOUBLE_FREE", 157: "MEMLEAK", 158: "INVALID_FREE",
    159: "INEXACT_DIV",
    161: "OOB_UPCAST",
    171: "PANIC", 180: "KERNEL_BUG", 201: "CONTRACTION",
}
# internal termination reasons: execution was cut off, nothing is wrong
# (INVALID_INPUT: the seed breaks an invariant the code relies on, such as
# fastop()'s call landing on an entry of its block -- no input the program
# can have)
BOUND_CODES = {122: "INVALID_INPUT", 123: "LOOP_OOB", 124: "OBJ_OOB",
               125: "STACK_OOB"}

MAX_EXCERPT = 1500      # bytes of log kept in a failure record
MAX_LOG_FILE = 16384    # any log file left on disk is trimmed to this
MAX_SIGNATURES = 20     # per failure kind per function

# --------------------------------------------------------------------------
# module normalization
# --------------------------------------------------------------------------

# Attributes of the kernel ABI that a userspace build cannot honor:
#  fn_ret_thunk_extern  every ret becomes a jmp to __x86_return_thunk
#  fentry-call          every function calls __fentry__
#  patchable-function-* NOP padding before the entry, for ftrace
#  target-features      -sse/-x87/... (no FP or vector registers), retpolines
#  ssp*, stack-protector-*   the guard is a percpu %gs slot in some configs
_ATTR_ENUM = re.compile(r"(?<= )(?:fn_ret_thunk_extern|ssp|sspstrong|sspreq|nonlazybind)(?= )")
_ATTR_STR = re.compile(
    r' "(?:fentry-call|patchable-function-entry|patchable-function-prefix|'
    r'target-features|tune-cpu|stack-protector-buffer-size|stack-protector-guard[a-z-]*|'
    r'indirect-tls-seg-refs|function-return|indirect-branch-cs-prefix|probe-stack)"'
    r'(?:="[^"]*")?')
# module flags that change the ABI: value to force
_MODFLAGS = {
    "SkipRaxSetup": 0,
    "function_return_thunk_extern": 0,
    "indirect_branch_cs_prefix": 0,
    "override-stack-alignment": 16,   # the kernel's 8; UCSan's runtime is userspace ABI
    "Code Model": 1,                  # kernel (2) -> small
}
_MODFLAG = re.compile(r'^(!\d+ = !\{i32 \d+, !"(%s)", i32 )-?\d+(\}.*)$'
                      % "|".join(re.escape(k) for k in _MODFLAGS))
_DEFINE_NAME = re.compile(r' @([-a-zA-Z$._0-9]+|"[^"\\]*")\(')

# Module asm (ASM_RET in the kernel's own .S-in-C, the alternatives and kprobe
# templates) is not touched by normalize() and still jumps to the kernel's
# return thunk; a plain ret is what it stands for.  Weak, so the module that
# defines the real one (arch/x86/lib/retpoline.o) still links.
_LINK_STUB_ASM = """\
        .text
        .weak   __x86_return_thunk
        .type   __x86_return_thunk, @function
__x86_return_thunk:
        ret
        .size   __x86_return_thunk, .-__x86_return_thunk
        .section .note.GNU-stack,"",@progbits
"""


def wrapped_functions():
    """Names with a custom wrapper (`fun:NAME=custom`) in the abilists the
    passes use: an entry function by one of these names is replaced by the
    runtime's model of it."""
    names = set()
    for f in ("ucsan_abilist.txt", "dfsan_abilist.txt"):
        try:
            with open(os.path.join(SYMSAN, "lib", "symsan", f)) as fh:
                for line in fh:
                    m = re.match(r"fun:([^=\s]+)=custom\s*$", line)
                    if m:
                        names.add(m.group(1))
        except OSError:
            pass
    return names


def link_args(out):
    """--link-arg flags for ucsan_opt: the return-thunk stub, built once into
    <out>."""
    stub = os.path.join(out, "link-stub.o")
    if not os.path.exists(stub):
        src = os.path.join(out, "link-stub.s")
        with open(src, "w") as f:
            f.write(_LINK_STUB_ASM)
        subprocess.run([os.environ.get("KO_CC", "clang-18"), "-c", "-o", stub + ".tmp", src], check=True)
        os.replace(stub + ".tmp", stub)
    return ["--link-arg=" + stub]


def normalize(ll):
    """ll: text of a module.  Returns (normalized text, [defined function names],
    number of definitions skipped because of an unquotable name)."""
    out = []
    funcs = []
    skipped = 0
    for line in ll.split("\n"):
        if line.startswith("attributes #"):
            line = _ATTR_STR.sub("", _ATTR_ENUM.sub("", line))
        elif line.startswith("!"):
            m = _MODFLAG.match(line)
            if m:
                line = "%s%d%s" % (m.group(1), _MODFLAGS[m.group(2)], m.group(3))
        elif line.startswith("define "):
            m = _DEFINE_NAME.search(line)
            if m:
                name = m.group(1)
                if name[0] == '"':
                    name = name[1:-1]
                funcs.append(name)
            else:
                skipped += 1
        out.append(line)
    return "\n".join(out), funcs, skipped


def module_key(rel):
    return rel.replace("/", "_")


def prepare_module(root, rel, outdir):
    """Worker (process pool): disassemble, normalize and reassemble one module.
    Returns a dict for the driver."""
    key = module_key(rel)
    moddir = os.path.join(outdir, "modules", key)
    info = {"module": rel, "key": key}
    src = os.path.join(root, rel)
    try:
        with open(src, "rb") as f:
            if f.read(2) != b"BC":
                info["status"] = "skipped-not-bitcode"
                return info
    except OSError as e:
        info.update(status="failed", detail=f"open: {e}")
        return info
    fj = os.path.join(moddir, "funcs.json")
    nb = os.path.join(moddir, "norm.bc")
    if os.path.exists(fj) and os.path.exists(nb):
        with open(fj) as f:
            info.update(status="ok", **json.load(f))
        return info
    os.makedirs(moddir, exist_ok=True)
    dis = subprocess.run([LLVM_DIS, "-o", "-", src], capture_output=True)
    if dis.returncode != 0:
        info.update(status="failed", detail="llvm-dis: " + dis.stderr.decode(errors="replace")[-MAX_EXCERPT:])
        return info
    # latin-1 maps bytes 1:1, so nothing in a string constant can fail to decode
    text, funcs, skipped = normalize(dis.stdout.decode("latin-1"))
    asm = subprocess.run([LLVM_AS, "-o", nb], input=text.encode("latin-1"), capture_output=True)
    if asm.returncode != 0:
        info.update(status="failed", detail="llvm-as: " + asm.stderr.decode(errors="replace")[-MAX_EXCERPT:])
        return info
    data = {"functions": funcs, "unquotable": skipped}
    with open(fj, "w") as f:
        json.dump(data, f)
    info.update(status="ok", **data)
    return info


# --------------------------------------------------------------------------
# running commands, capped logs
# --------------------------------------------------------------------------

_live = set()
_live_lock = threading.Lock()


def group_rss_kb(sid):
    """Resident memory of everything in the session `sid` (the target, the
    manager, the forkserver and its children).  UCSan maps a lot of address
    space it never touches, so only RSS says anything."""
    try:
        out = subprocess.run(["ps", "-o", "rss=", "--sid", str(sid)], capture_output=True, text=True).stdout
        return sum(int(x) for x in out.split())
    except (OSError, ValueError):
        return 0


def run_cmd(cmd, cwd, log, timeout, env=None, mem_limit_kb=0):
    """Run cmd in its own process group with output to `log`.  Returns the
    return code, None on timeout, or "oom" if the group's RSS went over
    mem_limit_kb (a runaway target must not take the machine with it: one hit
    59 GB and the kernel OOM-killer ended the whole run).  The group is killed
    in every case, so a hung target does not outlive its function."""
    with open(log, "wb") as lf:
        p = subprocess.Popen(cmd, cwd=cwd, stdout=lf, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, env=env, start_new_session=True)
        with _live_lock:
            _live.add(p)
        deadline = time.time() + timeout
        try:
            while True:
                try:
                    p.wait(timeout=max(0.01, min(1.0, deadline - time.time())))
                    rc = p.returncode
                    break
                except subprocess.TimeoutExpired:
                    if time.time() >= deadline:
                        rc = None
                        break
                    if mem_limit_kb and group_rss_kb(p.pid) > mem_limit_kb:
                        rc = "oom"
                        break
        finally:
            with _live_lock:
                _live.discard(p)
            try:
                os.killpg(p.pid, signal.SIGKILL)   # stragglers (forkserver, children)
            except OSError:
                pass
            p.wait()
    trim_file(log)
    return rc


def trim_file(path, cap=MAX_LOG_FILE):
    """Keep the head and the tail of a log; the middle of a long one is noise."""
    try:
        size = os.path.getsize(path)
        if size <= cap:
            return
        with open(path, "rb") as f:
            head = f.read(cap // 4)
            f.seek(size - (cap - cap // 4))
            tail = f.read()
        with open(path, "wb") as f:
            f.write(head + b"\n[... %d bytes trimmed ...]\n" % (size - cap) + tail)
    except OSError:
        pass


def read_tail(path, n=MAX_EXCERPT):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - n))
            return f.read().decode(errors="replace")
    except OSError:
        return ""


def norm_sig(msg, n=140):
    """A message with the run-specific parts (addresses, numbers) masked, so
    that the same failure groups together across functions."""
    msg = re.sub(r"\x1b\[[0-9;]*m", "", msg)
    msg = re.sub(r"==\d+==", "", msg)   # sanitizer pid prefix
    msg = re.sub(r"0x[0-9a-fA-F]+", "0x?", msg)
    msg = re.sub(r"\d+", "N", msg)
    return " ".join(msg.split())[:n]


# --------------------------------------------------------------------------
# failure classification
# --------------------------------------------------------------------------

def classify_build(log_text, rc):
    """A ucsan_opt failure -> [(stage, kind, signature)], from which of its
    three commands (opt, llc, ko-clang) ran last."""
    last = None
    for m in re.finditer(r"^Running command: .*$", log_text, re.M):
        last = m.group(0)
    if re.search(r"<unknown>:0: error:", log_text):
        stage = "codegen"        # llc assembling module asm
    elif re.search(r"linker command failed|undefined reference to", log_text):
        # the log is trimmed to head+tail, so a long linker error can push the
        # last "Running command" line out and the stage would read as opt's
        stage = "link"
    elif last is None:
        stage = "instrument"
    elif "opt-18" in last:
        stage = "instrument"
    elif "llc-18" in last:
        stage = "codegen"
    else:
        stage = "link"
    if rc is None:
        return [(stage, "timeout", "")]
    if rc == "oom":
        return [(stage, "memory-limit", "")]
    sigs = []
    if stage == "link":
        for m in re.finditer(r"undefined reference to [`'\"]?([^'\"`\s]+)", log_text):
            s = m.group(1)
            if s not in [x[2] for x in sigs]:
                sigs.append((stage, "undefined-reference", s))
        for m in re.finditer(r"hidden symbol [`']([^'`]+)' isn't defined", log_text):
            sigs.append((stage, "hidden-undefined", m.group(1)))
        if re.search(r"R_X86_64_32S against .* can not be used when making a PIE", log_text):
            sigs.append((stage, "pie-relocation", "R_X86_64_32S against .text in a PIE"))
        if not sigs:
            for m in re.finditer(r"^.*(?:error|ld\.lld|/usr/bin/ld)[: ].*$", log_text, re.M):
                sigs.append((stage, "link-error", norm_sig(m.group(0))))
                break
    else:
        pats = [
            (r"LLVM ERROR: (.*)", "llvm-error"),
            (r"Assertion [`'](.*)' failed", "assertion"),
            (r"^(Instruction does not dominate.*|Broken module.*|.*does not match.*|"
             r"Call parameter type.*|PHI node.*|Basic Block in function.*)$", "invalid-ir"),
            (r"error: (.*)", "error"),
            (r"UCSan: (.*)", "ucsan-message"),
            (r"^(Stack dump:|PLEASE submit a bug report)", "crash"),
        ]
        for pat, kind in pats:
            m = re.search(pat, log_text, re.M)
            if m:
                sigs.append((stage, kind, norm_sig(m.group(1) if m.groups() else m.group(0))))
                break
        if not sigs:
            sigs.append((stage, "failed", norm_sig(log_text.strip().split("\n")[-1] if log_text.strip() else "")))
    return sigs[:MAX_SIGNATURES]


def target_signature(tail):
    lines = [l for l in tail.split("\n") if l.strip()]
    for l in reversed(lines):
        if re.search(r"FATAL|ERROR|CHECK failed|Assertion|panic|PANIC", l):
            return norm_sig(l)
    for l in reversed(lines):
        if "fork server" not in l.lower() and "pipe_fd" not in l:
            return norm_sig(l)
    return ""


# Solver errors that are a deliberate decline, not a compatibility failure.
SOLVER_DECLINES = (
    "symbolic string too long",  # z3-ts kMaxSeqLength
)


def classify_run(res):
    """result.json of run_one.py -> (failures, findings, seeds, coverage)."""
    fails = []
    findings = {}
    if res.get("exception"):
        last = [l for l in res["exception"].strip().split("\n") if l.strip()][-1]
        fails.append(("run", "manager-exception", norm_sig(last)))
    if res.get("proc_died"):
        fails.append(("run", "target-died", target_signature(res.get("target_tail", ""))))
    for raw, count in res.get("exit_counts", {}).items():
        raw = int(raw)
        if raw < 256 and raw not in FINDING_CODES and raw not in BOUND_CODES and raw < 128:
            # killed by a signal (wait status).  Not any raw < 256: an event
            # the target reports itself arrives as its bare code (152 is OOB,
            # and 152 & 0x7f would read as SIGXCPU).
            try:
                name = signal.Signals(raw).name
            except ValueError:
                name = str(raw)
            fails.append(("run", "signal", name))
            continue
        code = raw if raw < 256 else raw >> 8
        if code in FINDING_CODES:
            findings[FINDING_CODES[code]] = findings.get(FINDING_CODES[code], 0) + count
        elif code in BOUND_CODES:
            pass
        else:
            fails.append(("run", "exit-code", "%d %s" % (code, target_signature(res.get("target_tail", "")))))
    # a poison-flag violation the run goes on past (run_one.py's
    # exit_on_poison=0) is a finding reported as an event, with no exit
    for code in (155, 159):
        n = res.get("events", {}).get(str(code), 0)
        if n:
            name = FINDING_CODES[code]
            findings[name] = max(findings.get(name, 0), n)
    for e in res.get("errors", []):
        if any(d in e for d in SOLVER_DECLINES):
            continue
        if "Solver error" in e:
            fails.append(("run", "solver-error", norm_sig(e.split("Solver error:", 1)[-1])))
        else:
            fails.append(("run", "manager-error", norm_sig(e)))
    seen = set()
    uniq = []
    for f in fails:
        if f not in seen:
            seen.add(f)
            uniq.append(f)
    cov = (res["blocks"], res["directions"]) if "blocks" in res else None
    return uniq[:MAX_SIGNATURES], findings, res.get("seeds", 0), cov


# --------------------------------------------------------------------------
# one function
# --------------------------------------------------------------------------

def safe_name(fn):
    s = re.sub(r"[^\w.-]", "_", fn)
    if len(s) > 100 or s != fn:
        s = s[:90] + "-" + hashlib.md5(fn.encode()).hexdigest()[:8]
    return s


def write_repro(wd, rel, fn):
    """repro.sh reruns this one function through eval.py, which normalizes the module
    again, so it does not depend on any intermediate file surviving."""
    frozen = os.environ.get("SYMSAN_HOME")
    with open(os.path.join(wd, "repro.sh"), "w") as f:
        f.write("#!/bin/bash\n# %s :: %s\n" % (rel, fn))
        f.write("cd %s\n" % REPO)
        f.write("%spython3 tools/ucsan-kernel-eval/eval.py --modules '^%s$' --functions '^%s$' "
                "--out /tmp/ucsan-repro --fresh --jobs 1 --keep-passing --keep-modules\n"
                % ("SYMSAN_HOME=%s " % frozen if frozen else "", re.escape(rel), re.escape(fn)))
        f.write("# logs and binary: /tmp/ucsan-repro/funcs/*/<function>/\n")
    os.chmod(os.path.join(wd, "repro.sh"), 0o755)


class Evaluator:
    def __init__(self, args):
        self.a = args
        self.out = args.out
        self.lock = threading.Lock()
        self.results = open(os.path.join(self.out, "results.tsv"), "a")
        self.failures = open(os.path.join(self.out, "failures.jsonl"), "a")
        self.kept_bins = 0
        self.stop = False
        self.remaining = {}
        self.counts = collections.Counter()
        self.done = 0
        self.total = 0
        self.t0 = time.time()
        self.link_args = link_args(self.out)
        self.wrapped = wrapped_functions()

    def record(self, rel, fn, status, stage, seeds, secs, findings, failure=None,
               cov=None):
        fnd = ",".join("%s:%d" % kv for kv in sorted(findings.items())) or "-"
        blocks, dirs = cov if cov else ("-", "-")
        line = "\t".join([rel, fn, status, stage or "-", str(seeds), "%.1f" % secs, fnd,
                          str(blocks), str(dirs)]) + "\n"
        with self.lock:
            self.results.write(line)
            self.results.flush()
            if failure:
                self.failures.write(json.dumps(failure) + "\n")
                self.failures.flush()
            self.done += 1
            self.counts[status] += 1
            if self.done % 100 == 0 or self.done == self.total:
                el = time.time() - self.t0
                print("[%d/%d] pass=%d fail=%d  %.1f fn/s" % (
                    self.done, self.total, self.counts["pass"], self.counts["fail"],
                    self.done / max(el, 1e-9)), file=sys.stderr, flush=True)

    def module_done(self, key):
        with self.lock:
            self.remaining[key] -= 1
            last = self.remaining[key] == 0
        if last and not self.a.keep_modules:
            shutil.rmtree(os.path.join(self.out, "modules", key), ignore_errors=True)

    def do_function(self, rel, key, fn):
        if self.stop:
            return
        t0 = time.time()
        try:
            self._do_function(rel, key, fn, t0)
        except BaseException as e:   # the driver must not lose a function silently
            self.record(rel, fn, "fail", "driver", 0, time.time() - t0, {},
                        {"module": rel, "function": fn,
                         "failures": [{"stage": "driver", "kind": "exception", "signature": norm_sig(repr(e))}]})
        finally:
            self.module_done(key)

    def diagnose_segv(self, wd, run_cmd_line, env):
        """A silent exit 1 is a SIGSEGV that UCSan's handler turned into Die(),
        and it prints nothing.  Re-run under strace and read the stack at the
        exit_group: the frame under the signal trampoline is the faulting one.
        Returns a signature, or None (no strace, or no stack)."""
        if not shutil.which("strace"):
            return None
        st = os.path.join(wd, "strace.txt")
        run_cmd(["strace", "-f", "-k", "-e", "trace=exit_group", "-o", st] + run_cmd_line + ["--budget", "10"],
                wd, os.path.join(wd, "strace.out"), self.a.budget + self.a.grace, env,
                int(self.a.mem_limit_gb * 1024 * 1024))
        sig = None
        try:
            frames = None
            with open(st, errors="replace") as f:
                for line in f:
                    if re.search(r"exit_group\(1\)", line):
                        frames = []
                    elif frames is not None and line.startswith(" > "):
                        m = re.match(r" > \S+?\((.*?)(?:\+0x[0-9a-f]+)?\) \[0x[0-9a-f]+\]", line)
                        frames.append(m.group(1) if m else "?")
                    elif frames is not None and "+++ exited" not in line:
                        break   # strace prints "+++ exited" between the call and its stack
            if frames:
                # ... segfault_handler, <signal trampoline>, <faulting frame>, ...
                idx = next((i for i, fr in enumerate(frames) if "segfault_handler" in fr), None)
                if idx is not None and idx + 2 < len(frames):
                    where = frames[idx + 2]
                    if where.endswith(".taint"):   # an instrumented kernel function
                        where = "instrumented kernel code"   # (its name would never group)
                    sig = "SIGSEGV in %s" % where
        except OSError:
            pass
        for junk in ("strace.txt", "strace.out"):
            try:
                os.unlink(os.path.join(wd, junk))
            except OSError:
                pass
        return sig

    def _do_function(self, rel, key, fn, t0):
        a = self.a
        if fn in self.wrapped:
            # not a failure: see the module docstring
            self.record(rel, fn, "skip", "custom-wrapper", 0, time.time() - t0, {})
            return
        wd = os.path.join(self.out, "funcs", key, safe_name(fn))
        shutil.rmtree(wd, ignore_errors=True)
        os.makedirs(wd)
        os.symlink(os.path.join(self.out, "modules", key, "norm.bc"), os.path.join(wd, "m.bc"))
        with open(os.path.join(wd, "scope.yaml"), "w") as f:
            f.write("entry: %s\nscope:\n  - %s\n" % (json.dumps(fn), json.dumps(fn)))

        # -r: out-of-scope callees resign their pointer arguments (see the
        # module docstring); without it a stack variable a callee would have
        # initialized stays uninitialized and its first read is a UBI
        build_cmd = [UCSAN_OPT, "-b", "-i", "-t", "-v", "-m", "scope.yaml", "-o", "f.ucsan"] + \
            (["-r"] if a.resign else []) + self.link_args + ["m.bc"]
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.join(SYMSAN, "lib", "symsan") + os.pathsep + env.get("PYTHONPATH", "")
        run_cmd_line = [a.python, RUN_ONE, "f.ucsan", "--workdir", "run",
                        "--budget", str(a.budget), "--loop-threshold", str(a.loop_threshold)]

        def fail(stage, sigs, log_text, findings=None, seeds=0, cov=None):
            failure = {"module": rel, "function": fn, "workdir": wd,
                       "failures": [{"stage": s, "kind": k, "signature": g} for s, k, g in sigs],
                       "excerpt": log_text[-MAX_EXCERPT:]}
            write_repro(wd, rel, fn)
            self.record(rel, fn, "fail", sigs[0][0] if sigs else stage, seeds,
                        time.time() - t0, findings or {}, failure, cov)

        mem = int(a.mem_limit_gb * 1024 * 1024)
        rc = run_cmd(build_cmd, wd, os.path.join(wd, "build.log"), a.build_timeout, env, mem)
        binf = os.path.join(wd, "f.ucsan")
        if rc != 0 or not os.path.exists(binf):
            text = read_tail(os.path.join(wd, "build.log"), 200000)
            sigs = classify_build(text, rc)
            return fail("build", sigs, text)

        # A pass can decline the scope with only a warning and exit 0.  For a
        # variadic entry it emits a main() that returns 1, so running it would
        # report "exit code 1" and say nothing about why.
        text = read_tail(os.path.join(wd, "build.log"), 200000)
        warns = [("instrument", "warning", norm_sig(w)) for w in re.findall(r"^Warning: (.*)$", text, re.M)]
        if any("VarArg entry" in w[2] for w in warns):
            # not a failure: see the module docstring
            self.record(rel, fn, "skip", "variadic-entry", 0, time.time() - t0, {})
            shutil.rmtree(wd, ignore_errors=True)
            return

        rc = run_cmd(run_cmd_line, wd, os.path.join(wd, "run.out"), a.budget + a.grace, env, mem)
        if rc == "oom":
            return fail("run", [("run", "memory-limit", "RSS over %g GB" % a.mem_limit_gb)],
                        read_tail(os.path.join(wd, "run.out")))
        rjson = os.path.join(wd, "run", "result.json")
        if rc is None:
            return fail("run", [("run", "hang", "no result within %ds" % (a.budget + a.grace))],
                        read_tail(os.path.join(wd, "run.out")))
        if not os.path.exists(rjson):
            text = read_tail(os.path.join(wd, "run.out"))
            return fail("run", [("run", "runner-crash", norm_sig(text.strip().split("\n")[-1] if text.strip() else "rc=%s" % rc))], text)
        with open(rjson) as f:
            res = json.load(f)
        fails, findings, seeds, cov = classify_run(res)
        fails = (warns + fails)[:MAX_SIGNATURES]
        if not fails:
            self.record(rel, fn, "pass", None, seeds, time.time() - t0, findings,
                        cov=cov)
            if not a.keep_passing:
                shutil.rmtree(wd, ignore_errors=True)
            return
        # exit code 1 with nothing printed is a SIGSEGV that UCSan's handler
        # turned into Die() without a word
        if ("run", "exit-code", "1 ") in fails:
            desc = self.diagnose_segv(wd, run_cmd_line, env)
            if desc:
                fails[fails.index(("run", "exit-code", "1 "))] = ("run", "segv", desc)
        excerpt = "\n".join(res.get("errors", [])[:5]) + "\n--- target ---\n" + res.get("target_tail", "")
        if res.get("exception"):
            excerpt = res["exception"] + "\n" + excerpt
        fail("run", fails, excerpt, findings, seeds, cov)
        # keep the binary of only a few run failures; repro.sh rebuilds the rest
        with self.lock:
            keep = self.kept_bins < a.keep_bins
            self.kept_bins += keep
        if not keep:
            try:
                os.unlink(binf)
            except OSError:
                pass


# --------------------------------------------------------------------------
# summary
# --------------------------------------------------------------------------

def summarize(out, topn=40):
    rows = []
    with open(os.path.join(out, "results.tsv")) as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            # (7 columns before the coverage ones)
            if len(p) in (7, 9):
                rows.append(p + ["-", "-"] if len(p) == 7 else p)
    total = len(rows)
    fnd = collections.Counter()
    stages = collections.Counter()
    permod = collections.defaultdict(lambda: [0, 0])
    npass = 0
    skipped = collections.Counter()
    blocks = dirs = covered = 0
    for rel, fn, st, stage, seeds, secs, findings, nb, nd in rows:
        if nb.isdigit():
            blocks += int(nb)
            dirs += int(nd)
            covered += 1
        if st == "skip":
            skipped[stage] += 1
            continue
        permod[rel][0] += 1
        if st == "pass":
            npass += 1
        else:
            stages[stage] += 1
            permod[rel][1] += 1
        if findings != "-":
            for kv in findings.split(","):
                k, v = kv.rsplit(":", 1)
                fnd[k] += int(v)
    groups = collections.defaultdict(lambda: {"n": 0, "mods": set(), "ex": None})
    with open(os.path.join(out, "failures.jsonl")) as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            for x in r["failures"]:
                g = groups[(x["stage"], x["kind"], x["signature"])]
                g["n"] += 1
                g["mods"].add(r["module"])
                if g["ex"] is None:
                    g["ex"] = "%s :: %s" % (r["module"], r["function"])
    total -= sum(skipped.values())
    L = []
    L.append("functions evaluated: %d   pass: %d   fail: %d (%.1f%%)" % (
        total, npass, total - npass, 100.0 * (total - npass) / max(total, 1)))
    if skipped:
        L.append("skipped (not evaluated): " + ", ".join("%s %d" % kv for kv in skipped.most_common()))
    if covered:
        L.append("coverage over %d runs: %d basic blocks, %d branch directions" % (
            covered, blocks, dirs))
    L.append("")
    L.append("failing functions by stage:")
    for k, v in stages.most_common():
        L.append("  %-12s %d" % (k, v))
    L.append("")
    L.append("findings (bug reports, not failures), total reports across functions:")
    for k, v in fnd.most_common():
        L.append("  %-12s %d" % (k, v))
    L.append("")
    L.append("failure groups (stage / kind / signature), by functions affected:")
    for (stage, kind, sig), g in sorted(groups.items(), key=lambda kv: -kv[1]["n"])[:topn]:
        L.append("  %5d fn %4d mod  %s/%s  %s" % (g["n"], len(g["mods"]), stage, kind, sig))
        L.append("           e.g. %s" % g["ex"])
    L.append("")
    L.append("modules with the most failures:")
    for rel, (n, f) in sorted(permod.items(), key=lambda kv: -kv[1][1])[:20]:
        if f:
            L.append("  %4d/%-4d %s" % (f, n, rel))
    text = "\n".join(L) + "\n"
    with open(os.path.join(out, "summary.txt"), "w") as f:
        f.write(text)
    return text


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default="/test/csong/linux/linux-6.8.2", help="kernel build tree")
    ap.add_argument("--list", default=None, help="bitcode list, relative to --root (default <root>/bclist)")
    ap.add_argument("--out", default="ucsan-kernel-eval.out")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--budget", type=float, default=30.0, help="seconds of exploration per function")
    ap.add_argument("--grace", type=float, default=30.0, help="extra seconds before a run counts as hung")
    ap.add_argument("--build-timeout", type=float, default=300.0)
    ap.add_argument("--mem-limit-gb", type=float, default=6.0,
                    help="kill a function's processes above this RSS (a memory-limit failure)")
    ap.add_argument("--loop-threshold", type=int, default=5)
    ap.add_argument("--modules", default=None, help="regex on the module path")
    ap.add_argument("--functions", default=None, help="regex on the function name")
    ap.add_argument("--sample-modules", type=int, default=0, help="random N modules (with --seed)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--max-functions-per-module", type=int, default=0)
    ap.add_argument("--fresh", action="store_true", help="ignore results.tsv, redo everything")
    ap.add_argument("--keep-passing", action="store_true", help="keep work dirs of passing functions")
    ap.add_argument("--keep-modules", action="store_true", help="keep normalized modules")
    ap.add_argument("--keep-bins", type=int, default=20, help="run-failure binaries to keep")
    ap.add_argument("--python", default=VENV_PY if os.path.exists(VENV_PY) else sys.executable,
                    help="python with pyelftools/PyYAML/psutil, for run_one.py")
    ap.add_argument("--no-resign", dest="resign", action="store_false",
                    help="do not build with ucsan_opt -r (out-of-scope callees resign their "
                         "pointer arguments); for an A/B")
    ap.add_argument("--retest", default=None, metavar="DIR",
                    help="only the functions that failed in an earlier --out DIR (to check a fix)")
    ap.add_argument("--summarize-only", action="store_true")
    a = ap.parse_args()

    a.out = os.path.abspath(a.out)
    os.makedirs(a.out, exist_ok=True)
    for f in ("results.tsv", "failures.jsonl"):
        if a.fresh and not a.summarize_only:
            open(os.path.join(a.out, f), "w").close()
        else:
            open(os.path.join(a.out, f), "a").close()
    if a.summarize_only:
        print(summarize(a.out))
        return
    if a.fresh:
        shutil.rmtree(os.path.join(a.out, "funcs"), ignore_errors=True)
        shutil.rmtree(os.path.join(a.out, "modules"), ignore_errors=True)

    for p in (UCSAN_OPT, RUN_ONE):
        if not os.path.exists(p):
            sys.exit("missing %s (run `make install` in b4?)" % p)

    lst = os.path.join(a.root, a.list or "bclist")
    with open(lst) as f:
        mods = [l.strip() for l in f if l.strip()]
    if a.modules:
        rx = re.compile(a.modules)
        mods = [m for m in mods if rx.search(m)]
    if a.sample_modules:
        random.Random(a.seed).shuffle(mods)
        mods = sorted(mods[:a.sample_modules])
    frx = re.compile(a.functions) if a.functions else None
    retest = None
    if a.retest:
        retest = collections.defaultdict(set)   # module -> failed functions ("*": the whole module)
        with open(os.path.join(a.retest, "failures.jsonl")) as f:
            for line in f:
                r = json.loads(line)
                retest[r["module"]].add(r["function"])
        mods = [m for m in mods if m in retest]

    done = set()
    if not a.fresh:
        with open(os.path.join(a.out, "results.tsv")) as f:
            for line in f:
                p = line.split("\t", 2)
                if len(p) >= 2:
                    done.add((p[0], p[1]))

    ev = Evaluator(a)
    print("phase 1: normalizing %d modules" % len(mods), file=sys.stderr, flush=True)
    tasks = []
    skipped = 0
    with cf.ProcessPoolExecutor(max_workers=a.jobs) as pp:
        futs = [pp.submit(prepare_module, a.root, m, a.out) for m in mods]
        for fu in futs:
            info = fu.result()
            rel = info["module"]
            if info["status"] == "skipped-not-bitcode":
                skipped += 1
                continue
            if info["status"] != "ok":
                if (rel, "*") not in done:
                    ev.record(rel, "*", "fail", "normalize", 0, 0.0, {},
                              {"module": rel, "function": "*",
                               "failures": [{"stage": "normalize", "kind": "failed",
                                             "signature": norm_sig(info.get("detail", ""))}],
                               "excerpt": info.get("detail", "")})
                continue
            fns = info["functions"]
            if frx:
                fns = [f for f in fns if frx.search(f)]
            if retest is not None and "*" not in retest[rel]:
                fns = [f for f in fns if f in retest[rel]]
            if a.max_functions_per_module:
                fns = fns[:a.max_functions_per_module]
            fns = [f for f in fns if (rel, f) not in done]
            if fns:
                ev.remaining[info["key"]] = len(fns)
                tasks += [(rel, info["key"], f) for f in fns]
            elif not a.keep_modules:
                shutil.rmtree(os.path.join(a.out, "modules", info["key"]), ignore_errors=True)
    ev.total = len(tasks) + ev.done
    print("phase 2: %d functions (%d modules skipped as not bitcode), %d jobs, %.0fs budget each"
          % (len(tasks), skipped, a.jobs, a.budget), file=sys.stderr, flush=True)

    ex = cf.ThreadPoolExecutor(max_workers=a.jobs)
    try:
        futs = [ex.submit(ev.do_function, *t) for t in tasks]
        for fu in futs:
            fu.result()
    except KeyboardInterrupt:
        print("interrupted; stopping (rerun to resume)", file=sys.stderr)
        ev.stop = True
        ex.shutdown(wait=False, cancel_futures=True)
        with _live_lock:
            for p in list(_live):
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
    else:
        ex.shutdown()
    print(summarize(a.out))
    print("summary: %s" % os.path.join(a.out, "summary.txt"), file=sys.stderr)


if __name__ == "__main__":
    main()
