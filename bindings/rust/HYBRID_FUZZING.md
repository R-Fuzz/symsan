# Hybrid fuzzing with SymSan + LibAFL — a how-to

This is a task-oriented walkthrough: take a C/C++ target from source to a running
hybrid-fuzzing campaign, then scale it and read the results. It is the companion
to [`README.md`](README.md), which is the *reference* for every flag, the shared
coverage map, and where the C++ lives. When this guide says "see the README," it
means that file.

## What hybrid fuzzing buys you here

A coverage-guided fuzzer (LibAFL, running the target through an AFL forkserver)
is fast and cheap but blind at hard gates: magic numbers, checksums, chained byte
equalities, table lookups. A concolic engine (SymSan) is the opposite — it traces
one input symbolically and *solves* the branch conditions the fuzzer can't guess,
but each trace is expensive.

The integration runs them together. LibAFL drives breadth; SymSan runs as a
LibAFL **stage** that, for each interesting corpus entry, traces it, hands the
branch constraints to a solver ladder (i2s → jigsaw → z3), and feeds every
solution back into the corpus. The fuzzer then explores from the freshly-opened
gate. Structure comes from mutation; hard *values* come from the solver.

The rest of this document is the loop: **build once, build the target twice, run,
scale, read.**

---

## 1. Build SymSan

Build and install SymSan first — the Rust crates and the target instrumentation
both need the installed toolchain (`ko-clang`, the runtime, the passes). Follow
the top-level [`README.md`](../../README.md#compilation); in this repo the
install tree is `b4/`:

```shell
cd b4 && make -j && make install
```

## 2. Build the Rust fuzzer

The fuzzer lives in `bindings/rust/`. It is a normal Cargo workspace:

- `symsan` — safe wrapper over the SymSan C ABI (no LibAFL dependency)
- `libafl-symsan` — the `SymSanStage` / `SymSanStageBuilder`
- `fuzzer` — the `symsan-fuzz` binary you actually run

```shell
cd bindings/rust
cargo build --release
# binary at bindings/rust/target/release/symsan-fuzz
```

## 3. Build the target — twice (or three times)

The target is compiled once per role. This is not optional and it is the step
people get wrong; the "why" is in the README's *"Why the target is built twice"*
section. The short version: the coverage build and the concolic build use
incompatible instrumentation, so they are separate binaries fed to the one
`symsan-fuzz` process.

**a. Coverage build (`target.afl`)** — the forkserver LibAFL executes:

```shell
afl-clang-fast target.c -o target.afl
```

**b. Concolic build (`target.symsan`)** — what SymSan traces. Use the out-of-
process (Fastgen) backend; the stage requires it:

```shell
KO_CC=clang-18 KO_USE_FASTGEN=1 b4/bin/ko-clang target.c -o target.symsan
```

For C++, use `KO_CXX=clang++-18` and `b4/bin/ko-clang++` (see CLAUDE.md / README).

**c. (optional) cmplog build (`target.cmplog`)** — only if you want the LibAFL
input-to-state baseline to A/B against SymSan:

```shell
AFL_LLVM_CMPLOG=1 afl-clang-fast target.c -o target.cmplog
```

> **Deferred forkserver / empty-corpus trap.** If your target defers the
> forkserver or expects a persistent loop and you see an empty coverage map and a
> "target's fault" error, that is the known trap — read the README's forkserver
> and `AFL_MAP_SIZE` notes before debugging the target.

## 4. Run

Minimal run — coverage target after `--`, concolic target via `--symsan`, input
file passed as `@@` (expanded per process, so the target must read a file):

```shell
symsan-fuzz \
  -i ./seeds -o ./out \
  --symsan ./target.symsan \
  -- ./target.afl @@
```

Add the cmplog baseline arm by pointing `--cmplog` at that build:

```shell
symsan-fuzz -i ./seeds -o ./out \
  --symsan ./target.symsan --cmplog ./target.cmplog \
  -- ./target.afl @@
```

Useful first-run flags (full list: `symsan-fuzz --help` and the README):

| flag | default | what it does |
|------|---------|--------------|
| `-t, --timeout` | 1200 ms | per-exec timeout for the coverage target |
| `--symsan-timeout` | 60000 ms | per-trace timeout for the concolic target |
| `--symsan-budget` | 0 (off) | cap wall-time spent in the concolic stage |
| `-d, --debug-child` | off | let the target's stderr through (otherwise `/dev/null`) |

`-d` is the first thing to reach for when a target "does nothing" — its stderr is
suppressed by default.

## 5. Production coverage sharing — `--branch-map`

By default the SymSan constraint ids and the AFL++ edge ids live in different
namespaces, so a branch SymSan solves and a branch the fuzzer covers can't be
matched up. For a real campaign you want them **shared**: then a SymSan cid *is*
an AFL edge id, `--flip-log` can score each solve against the fuzzer's own
coverage for free, and the cmplog filter is precise.

Producing the `.bmap` is a one-time LTO link + `opt` TaintPass recipe
(`afl-clang-lto -Wl,--save-temps=precodegen`, then `opt-18 -passes=taint` over the
merged `.precodegen.bc`, with `AFL_LLVM_LTO_STARTID=4096` = `symsan::AFL_ID_BASE`).
The exact commands and the `covcheck` validation step are in the README's
**`--branch-map`** section — follow it there rather than reproducing it here.
Then:

```shell
symsan-fuzz -i ./seeds -o ./out \
  --symsan ./target.symsan \
  --branch-map ./target.bmap --validate-branch-map --flip-log \
  -- ./target.afl @@
```

Use `--validate-branch-map` once when you build a new map (it cross-checks the map
against the target and is worth the startup cost); drop it for steady-state runs.

## 6. Tuning the solver ladder

Each traced branch is offered to the solvers in order: **i2s** (input-to-state,
cheap) → **jigsaw** (JIT'd local search) → **z3** (SMT, thorough but slow). A rung
that declines or fails escalates the task to the next. Defaults are tuned for
throughput: **i2s and jigsaw on, z3 off.**

| flag | effect |
|------|--------|
| `--symsan-no-i2s` | disable the i2s rung |
| `--symsan-no-jigsaw` | disable the jigsaw rung |
| `--symsan-z3` | enable z3 (the thorough, slow rung) |
| `--symsan-solve-ub` | also solve undefined-behavior checks |
| `--symsan-escalate-unkept` | climb the ladder when a rung's SAT answer retired nothing |
| `--symsan-max-tasks N` | cap tasks per trace (0 = unbounded) |
| `--symsan-task-priority` / `--symsan-requeue-tasks` | reorder / requeue the task queue |

Turn on `--symsan-z3` when you suspect the target has nested/path-sensitive
constraints the local solvers keep declining — it is the correctness lever, at a
throughput cost. `--symsan-solve-ub` is a measured throughput hit that buys
little on well-formed parsers; enable it deliberately.

The cmplog arm shares the ladder's philosophy but is a separate baseline; SymSan's
taint filters which comparisons cmplog attempts. `--no-symsan-cmplog-filter`
turns that filter off (attempts everything cmplog would, unfiltered) — use it only
when A/B-ing the filter itself.

## 7. Scale across cores

`symsan-fuzz` is **one session per process** — the concolic side keeps
file-global state, so a process fuzzes on one core. To use N cores, run N
instances pinned to separate cores, each with its own output directory (or a
shared corpus dir if you want them to cooperate). This is exactly what the Magma
runner does; the mechanism and LibAFL's `Launcher` are covered in the README's
process-model section.

For a batteries-included multi-core campaign with the four arms
(both / symsan / cmplog / havoc), use the Magma harness:

```shell
tools/magma/campaign.sh --timeout 24h --repeat 3 --workers 8 libpng
```

It builds the target(s), wires `--branch-map`, pins one instance per worker, and
collects the runs. See `tools/magma/campaign.sh --help` for `--build-line`,
`--solve-ub`, and arm selection.

## 8. Read the results

- **`./out/`** — LibAFL corpus, crashes, and the fuzzer's own stats UI.
- **`--flip-log`** (requires a shared `--branch-map`) — attributes each solved
  branch to whether it produced new fuzzer coverage. This is the honest
  measure of whether the concolic stage is *earning its keep*, as opposed to
  producing byte-identical duplicates or chasing directions nothing ever covers.
- A concolic stage that reports many SAT answers but little new coverage is
  usually solving *feasible-in-isolation but dead-in-context* branches — expected
  on recovering parsers, and not a bug. It means the win is in structure the
  fuzzer/LLM must supply, not in more solving.

---

## Troubleshooting quick table

| symptom | likely cause | fix |
|---------|--------------|-----|
| empty coverage map, "target's fault" | deferred forkserver / persistent loop not detected | README forkserver + `AFL_MAP_SIZE` notes |
| target "does nothing", no output | stderr suppressed | run with `-d` |
| C++ target segfaults at teardown | a stray shared `libc++.so.1` beside the instrumented static one | check `ldd`; use the instrumented libc++ |
| solver solves a lot, coverage flat | dead-in-context branches / duplicate answers | read `--flip-log`; this is often expected |
| SymSan solutions never matched to coverage | cid/edge namespaces not shared | build and pass `--branch-map` |

For anything about a specific flag, the shared map internals, or the C++/Rust
boundary, go to [`README.md`](README.md).
