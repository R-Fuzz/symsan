# Unit tests as UCSan entries

Tools for running a gtest test under UCSan, with its literal inputs
symbolized: the test's invocation sequence is the harness, as in UTopia, but
its values are explored instead of fixed. Written for v8's unittests (built
with clang-18 into bitcode), but neither tool knows about v8.

```bash
tools/ucsan-ut/build.sh OUTDIR    # ut-entry, ut-strip, ut-cg and ut-unit, with clang++-18 / llvm-config-18
```

Override the compiler with `CXX` and the LLVM install with `LLVM_CONFIG`.

## ut-unit: what a test calls into

```bash
ut-unit -p BUILD_DIR test/unittests/utils/bit-vector-unittest.cc > out.jsonl
```

This is a libTooling pass over a test file, so `BUILD_DIR` needs a
`compile_commands.json`. For each `TestBody` it lists the API calls the test
makes, with test code (fixtures, helpers, lambdas) treated as transparent, and
the shape of each owner class: member access, nested classes, friends and
bases. It works at the source level because debug info has no friends and
inlining hides which API a test called. The scope of a test (its function
list) is derived from this output.

## ut-entry: assumptions, not findings

```bash
ut-entry IN.bc OUT.bc ALLOW --fatal MANGLED... --fatal-prefix NAME... \
         --helper-prefix NAME... > assume.txt
```

This tool turns a failed check on something the test controls into invalid
input (`ucsan_invalid_input`, exit 122) instead of a PANIC. It handles two
kinds of check:

- **The test's own checks.** For example, a fixture's `CHECK_NOT_NULL` on what
  an out-of-scope dependency returned.
- **The unit's preconditions on what the test passes it.** Each unit function
  the test calls directly is cloned as `F.ut_entry`, and in the clone the
  fatal reporters are replaced by assumptions. This also covers the check
  helpers the function calls. Only the test's call sites use the clone, so the
  same check reached from inside the unit is still a finding.

`ALLOW` is the scope's allow file, whose `harness-prefix`/`harness-exact`
lines name the test's functions. The tool prints the `__ucsan_ut_assume.N`
names it declared. Map each one in the scope YAML:

```yaml
custom:
  "__ucsan_ut_assume.0":
    ref_name: ucsan_invalid_input
    arg_maps: []
```

## ut-strip: library code from a prebuilt archive

```bash
ut-strip IN.bc OUT.bc DEFS KEEP && opt-18 -passes=globaldce OUT.bc -o OUT.bc
```

Library code (what the scope calls out of it, run concretely under TaintPass)
can come from an archive built once: each object of the library TaintPass'd
on its own as library code (`-taint-ucsan-lib`), its definitions made weak.
Then a test's module needs no copy of it. Linking the library's bitcode for
the scope analysis brings in everything the test reaches, which for a v8
Isolate test is all of v8.

`DEFS` lists the symbols the archive defines, a function's without `.taint`.
`KEEP` lists the scope. Each definition in `DEFS` but not in `KEEP` becomes a
declaration, and each alias of one becomes a declaration too. The scope's
copies stay. They are UCSan's and strong, so they win over the archive's weak
ones, also for library code's calls into the scope.

A static constructor the archive defines is dropped from the module's
`llvm.global_ctors` (and `llvm.global_dtors`). Its object's own `.init_array`
runs it whenever that object is linked in, so a second entry would construct
the same global twice. gmock's `g_gmock_implicit_sequence` then created two
pthread keys and failed the second `pthread_key_delete` at exit.

## ut-cg: call graph facts for the scope

```bash
ut-cg IN.bc > OUT.cg
```

This prints what the scope script needs from a module, one fact per line:
definitions with their source file, size and noreturn attribute,
declarations, aliases, what each global's initializer and each function
names, direct callees, the number of indirect call sites, and the classes a
function allocas. Names are spelled as `llvm-dis` spells them. Reading these
facts from bitcode instead of parsing `llvm-dis` text with regexes took the
scope step of a v8 Isolate test from about 20 minutes to under a minute.

## run.py: exploring an entry

```bash
venv/bin/python tools/ucsan-ut/run.py BINARY --build-dir build \
    --workdir DIR [--budget SECONDS] [--trace-only] [--seed FILE] \
    [--target BID [--target-result 0|1]] [--loop-threshold N] \
    [--ucsan-option K=V]... [--taint-option K=V]... [--config JSON] \
    [--symbolize] [--bbtrace]
```

This runs the entry under `UcsanManager` (fuzzer/thoroupy) and writes
`DIR/result.json`. It records each seed that ran, with its exit status and its
objects' bytes, and the exit statuses and events. It also records the event
sites, symbolized with `--symbolize`, the coverage (blocks and directions) and
the tail of the target's output. The manager's log is `DIR/run.log`, and the
seed of each finding is saved under `DIR/blocking/`.

The defaults are what a UT entry needs: `concrete_globals`, the UBI and null
checkers, and `exit_on_memerror=0`. Without that last one, SymSan's first
uninitialized-shadow branch in library code ends the trace.

`--target BID` names a branch to debug. The run then logs its label, the
solver's answers, and whether replaying them flips it, in `result.json`'s
`flip`. Block ids are `100000 + n` for the entry's n-th block, and
`(i + 2) * 100000 + n` for the function at index i (from 0) of the scope
YAML's `scope` list.

Pass the instrumented binary itself, not a wrapper script such as one under
gdb. The manager watches the process it started, so a wrapper that exits after
the first child looks like a dead target, and the run stops after one seed.
