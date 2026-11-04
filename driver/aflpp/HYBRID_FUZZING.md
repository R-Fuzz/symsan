# Hybrid fuzzing with SymSan + AFL++: a how-to

This walkthrough takes a C/C++ target from source to a running AFL++ campaign
with SymSan as a custom mutator.  [`README.md`](README.md) in this directory
covers the plugin's design and extension points.  The LibAFL front end has
its own guide,
[`bindings/rust/HYBRID_FUZZING.md`](../../bindings/rust/HYBRID_FUZZING.md).
Both front ends share the same session and solver ladder.

## How the plugin fits into AFL++

AFL++ loads `libSymSanMutator.so` as a custom mutator.  For each queue entry
AFL++ picks:

1. `afl_custom_fuzz_count` runs the SymSan build of the target on the entry
   and turns each new branch it reaches into a solving task.
2. `afl_custom_fuzz` is called once per task.  It hands the task to the solver
   ladder (i2s, then JIGSAW, then Z3) and gives AFL++ the solution as the next
   input to execute.  AFL++ keeps the input if it finds new coverage.

AFL++'s own stages (deterministic, havoc, splice) still run on the same
entry.  Havoc supplies the structure and SymSan supplies the exact values.

## 1. Build AFL++ and SymSan

The plugin compiles against AFL++'s headers, so build AFL++ first.  It is
tested with **v4.31c** and LLVM 18:

```shell
git clone --depth=1 --branch=v4.31c https://github.com/AFLplusplus/AFLplusplus aflpp
make -C aflpp LLVM_CONFIG=llvm-config-18 CC=clang-18 CXX=clang++-18 NO_NYX=1 source-only
```

Then configure SymSan with `-DAFLPP_PATH` (the plugin is not built without
it) and install:

```shell
mkdir -p build && cd build
CC=clang-18 CXX=clang++-18 cmake -DAFLPP_PATH=/path/to/aflpp -DCMAKE_INSTALL_PREFIX=$PWD ..
make -j && make install          # -> bin/libSymSanMutator.so, bin/ko-clang
```

## 2. Build the target twice

**a. The fuzzing build (`target.afl`)** is what AFL++ executes.  Leave CmpLog
**off**:

```shell
env -u AFL_LLVM_CMPLOG -u AFL_CMPLOG afl-clang-fast -O2 -g target.c -o target.afl
```

> afl-cc only checks whether `AFL_LLVM_CMPLOG` is *set*, so
> `AFL_LLVM_CMPLOG=0`, or even an empty `AFL_LLVM_CMPLOG=`, turns CmpLog
> **on**.  Unset it.  If the compile prints `Running cmplog-routines-pass`,
> CmpLog is on.

**b. The concolic build (`target.symsan`)** is what SymSan traces.  It must
use the out-of-process (`KO_USE_FASTGEN`) backend:

```shell
KO_CC=clang-18 KO_USE_FASTGEN=1 /path/to/symsan/bin/ko-clang -g target.c -o target.symsan
```

For C++, use `KO_CXX=clang++-18` and `ko-clang++`.  ko-clang adds `-O3`
unless `KO_DONT_OPTIMIZE` is set, and any value counts as set, including `0`.
For an autotools or CMake project, set `KO_CONFIG=1` while it configures and
unset it to build.  `README.md` lists the remaining `KO_*` options.

## 3. Run

```shell
AFL_CUSTOM_MUTATOR_LIBRARY=/path/to/symsan/bin/libSymSanMutator.so \
SYMSAN_TARGET=$PWD/target.symsan \
SYMSAN_TOKENS=1 \
SYMSAN_DONT_EXIT_ON_MEMERROR=1 \
  afl-fuzz -i seeds -o out -- ./target.afl @@
```

Give `SYMSAN_TARGET` as an absolute path.  A target that reads stdin (no
`@@`) works the same way; the plugin follows AFL++'s input mode.  The plugin
keeps its scratch files in `out/<instance>/symsan/` (set
`SYMSAN_OUTPUT_DIR` to move them), so `-M`/`-S` instances do not collide.
Each instance needs the same environment.

This is the `aflpp-i2s` arm of the [baseline](../../eval/results/2026-11-03/README.md).
On those 15 subjects it had the best average rank of the seven arms.

### The knobs worth knowing

| env | default | effect |
|---|---|---|
| `SYMSAN_TOKENS` | off | adds the bytes the target compares its input against to AFL++'s **auto dictionary** (`a_extras`, which havoc uses).  Case-folded keyword compares (`(c & ~0x20) == 'S'`) count.  It also creates **apply-at-site** mutations: where the input's bytes differ from the constant they are compared with, the constant is written over them (RedQueen-style).  The baseline ran with it on. |
| `SYMSAN_DONT_EXIT_ON_MEMERROR` | off | keep tracing past the first memory error (e.g. a branch on uninitialized shadow), which otherwise ends the trace.  The baseline ran with it on. |
| `SYMSAN_USE_JIGSAW` | off | add JIGSAW (JIT-compiled local search) after i2s |
| `SYMSAN_USE_Z3` | off | add Z3 at the end of the ladder.  Slow; the baseline never used it. |
| `SYMSAN_NO_I2S` | off | drop i2s.  Only useful for attributing solves to the solvers after it. |
| `SYMSAN_USE_NESTED` | off | include the conditions of enclosing branches when building a task |
| `SYMSAN_SOLVE_UB` | off | also solve for undefined behaviour (implies `SYMSAN_TRACE_BOUNDS`) |
| `SYMSAN_BRANCH_MAP` | none | a TaintPass branch map shared with the AFL++ build's edge ids, so SymSan skips branches the fuzzer has already covered.  See `bindings/rust/README.md`. |
| `SYMSAN_MAX_TASKS` | 0 (unbounded) | cap the task backlog |
| `SYMSAN_LOG_FILE` | stderr | where the plugin logs |

The full list, with the reasoning for each default, is `ConcolicConfig` in
[`include/concolic.h`](../../include/concolic.h).

### SymSan only, no havoc

```shell
AFL_CUSTOM_MUTATOR_ONLY=1 AFL_DISABLE_TRIM=1 \
AFL_CUSTOM_MUTATOR_LIBRARY=... SYMSAN_TARGET=... SYMSAN_TOKENS=1 \
  afl-fuzz -i seeds -o out -- ./target.afl @@
```

This setting skips AFL++'s deterministic, havoc and splice stages.  Every
new input then comes from SymSan, which makes it the arm to use when you
want to measure SymSan by itself (`cmo-i2s` in the baseline).  Trimming is
off because nothing would grow a trimmed input back.  This mode is not a
good way to *find bugs*:

- It covers less than with havoc on (in the baseline, about 87% of the best
  arm's coverage against 99%).
- It usually runs out of new tasks within minutes and then cycles an empty
  queue.  Each cycle prints a line, so send `afl-fuzz`'s output to
  `/dev/null` and read `out/default/fuzzer_stats`.

The baseline never loads the plugin together with AFL++'s own CmpLog (`-c`).
They are separate arms there, so the combination is untested.

## 4. Read the results

- `out/default/fuzzer_stats` and `plot_data`: AFL++'s own numbers.
- `out/default/queue/`: every kept input.  Measure coverage by replaying the
  queue on a separate `gcc --coverage` build of the target, as
  `eval/scripts/replay_cov.sh` does.  Seed counts and "new path" lines are a
  poor measure of what SymSan contributed.
- With `SYMSAN_TOKENS`, `out/default/queue/.state/auto_extras/` holds the
  dictionary entries the plugin added.

## Troubleshooting

| symptom | likely cause | fix |
|---|---|---|
| `SYMSAN_TARGET not defined` | env not passed to `afl-fuzz` | set it on the `afl-fuzz` command line, as an absolute path |
| compile prints `cmplog-routines-pass` for `target.afl` | `AFL_LLVM_CMPLOG` set, even to `0` or empty | `env -u AFL_LLVM_CMPLOG -u AFL_CMPLOG` |
| SymSan-only mode stops making progress after a few inputs, with very few execs | out of tasks.  One known cause: a byte compare inside a loop (`for (i…) if (buf[i] == kw[i])`).  Every iteration shares one branch id, and a branch direction counts as covered after one flip. | run with havoc (the default), or with `SYMSAN_TOKENS=1` so the keyword reaches havoc's dictionary |
| huge `fuzz.log` in SymSan-only mode | one line per empty queue cycle | send output to `/dev/null`; read `fuzzer_stats` |
| every crash takes about 1 s | the host's `core_pattern` pipes to apport, and `ulimit -c 0` does not stop a piped core dump | `echo core \| sudo tee /proc/sys/kernel/core_pattern` (`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` only silences AFL++'s startup check) |

For a reproducible multi-subject setup with all of this already wired up,
see [`eval/`](../../eval/README.md).
