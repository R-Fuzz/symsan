# SymSan Rust bindings

Three crates, layered so each is useful without the one above it:

| crate | what it is | depends on LibAFL? |
|---|---|---|
| [`symsan`](symsan/) | safe wrapper over the `libsymsan_c.so` C ABI | no |
| [`libafl-symsan`](libafl-symsan/) | `SymSanStage`, a LibAFL `Stage` | yes |
| [`fuzzer`](fuzzer/) | `symsan-fuzz`, an example front-end binary | yes |

`symsan` is a peer of [`bindings/python`](../python/): a binding, not a
front-end. If you want to drive SymSan from your own harness rather than from
LibAFL, that is the crate you want.

## Quick start

```bash
# 1. build SymSan itself (this is what produces libsymsan_c.so)
cd <symsan>/b4 && make -j && make install

# 2. build the Rust side
cd <symsan>/bindings/rust && cargo build --release

# 3. instrument your target -- twice, see below
afl-clang-fast -o target.afl target.c
KO_CC=clang-18 KO_USE_FASTGEN=1 <symsan>/b4/bin/ko-clang -o target.symsan target.c

# 4. fuzz
./target/release/symsan-fuzz \
    -i ./seeds -o ./out --symsan ./target.symsan -- ./target.afl @@
```

### Why the target is built twice

Coverage feedback and concolic execution need different instrumentation, and
they run in different processes:

- `target.afl` (afl-cc) is what the **forkserver executor** runs, ~1.4k times a
  second, to measure coverage.
- `target.symsan` (ko-clang) is what the **stage** runs, once per corpus entry,
  to collect symbolic constraints.

This is the same arrangement the AFL++ custom mutator used, where the second
binary came from `$SYMSAN_TARGET`.

`@@` means "the input file", as in AFL. It is expanded twice, to two different
paths — the forkserver's scratch file and the stage's — because the two
processes are independent. Leave it out and both read stdin.

## Layout

```
bindings/rust/
├── Cargo.toml            workspace
├── symsan/
│   ├── build.rs          bindgen over ../../include/symsan_c.h; link + rpath
│   ├── src/lib.rs        Session, Config, Error, Stats
│   └── tests/
│       ├── data/branch.c a tiny target with two chained magic values
│       └── session.rs    trace -> solve -> verify against an uninstrumented build
├── libafl-symsan/
│   ├── build.rs          re-emits the rpath (cargo does not propagate it)
│   └── src/lib.rs        SymSanStage + SymSanStageBuilder
└── fuzzer/
    ├── build.rs          ditto
    └── src/main.rs       forkserver_simple + the SymSan stage + a cmplog baseline
```

Nothing here is built by `make`; a C++ user needs no Rust toolchain. Configure
with `-DSYMSAN_BUILD_RUST=ON` to get a `rust` target that shells out to cargo.

## How the stage works

Once per corpus entry, `SymSanStage::perform`:

1. skips the entry if it has already been traced;
2. runs `target.symsan` on it and turns the branches it hit into solving tasks;
3. drains the solutions, handing each to `fuzzer.evaluate_filtered(...)`;
4. feeds the resulting `ExecuteInputResult` back with `report_result`.

Step 4 is the concrete win over the AFL++ custom mutator. A mutator never learns
what happened to the bytes it produced, so the old driver inferred it by
comparing queue-entry filenames afterwards. A stage runs the evaluation itself,
so the answer is exact — and it matters, because `report_result(false)`
escalates that task to the next, more expensive solver in the ladder while
`report_result(true)` retires it.

### It compounds

The solver only sees constraints from branches the target actually *executed*.
A branch nested behind an unsolved one does not exist yet. Solving the outer one
produces an input that is interesting, so it enters the corpus, so the stage
traces it, so the inner branch appears. Each round reaches one level deeper.

You can watch this in the example target, which has two chained 4-byte magic
values:

```
corpus: 1 -> 2      # 0xdeadbeef solved from the seed
objectives: 0 -> 1  # 0x12345678 solved from re-tracing that new entry
```

Measured on `tests/data/branch.c` with an `abort()` on the inner path, 90-second
runs:

| | crash found | executions |
|---|---|---|
| with `--symsan` | **yes, after 1s / 18 execs** | — |
| havoc only | no | 106,434 |

Two chained 4-byte equalities is 2^64 of search space; havoc is not going to
stumble into it.

## Sharing coverage with the fuzzer (`--branch-map`)

By default the stage only knows what *it* has traced, so it happily spends
solver time on branches the fuzzer covered an hour ago. The two sides name
branches differently — SymSan by source location, AFL++ by a sequential edge id
— so neither can read the other's knowledge.

`--branch-map` closes that. A patched AFL++ (`patches/aflpp-document-ids.patch`,
recipe in `patches/README.md`) makes `AFL_LLVM_DOCUMENT_IDS` emit the source
location each edge id came from, which is enough to join the two namespaces:

```bash
# build the coverage target with LTO, debug info, and the id dump
AFL_LLVM_DOCUMENT_IDS=$PWD/branch.map \
    <aflpp>/afl-clang-lto -g -o target.afl target.c

KO_CC=clang-18 KO_USE_FASTGEN=1 <symsan>/b4/bin/ko-clang -o target.symsan target.c

./target/release/symsan-fuzz -i ./seeds -o ./out \
    --symsan ./target.symsan --branch-map ./branch.map -- ./target.afl @@
```

The stage then reads `MaxMapFeedback`'s history map before each trace and hands
it to the session, which treats a branch direction whose edge ids are all
already covered as not worth solving.

Where the map has nothing to say the behaviour is exactly what it was without
it, so a partial map costs opportunities, not correctness — a solution the
solver does produce is as valid as before. (A map left over from a *different*
build is the one case worth avoiding: it can point a branch at some other
branch's edge id and make the stage skip work it should have done. Regenerate
the map whenever you rebuild the target.) Three things make a correct map
partial, all of them expected:

- **AFL++ prunes blocks** that dominate all their successors, so those branch
  directions have no edge id at all. There is no way to turn this off through
  `ld.lld`; see `patches/README.md`.
- **A switch case joins in one direction only.** Each case has its own id on
  both sides (the switch's location plus the case value), but only "take this
  case" is an edge; "go anywhere but this case" is not, and stays unmapped. The
  `default:` destination is never mapped either. That is the direction worth
  having: the stage asks whether the branch it did *not* take is worth solving,
  which for a case it skipped is "would taking it be interesting?".
- **`select` is not covered.** AFL++ allocates edge ids for both arms but does
  not export them, so the map has nothing to join against.
- **The two clangs must agree on column numbers**, which in practice means the
  same major version. They currently both use LLVM 18.

`Stats::mapped_branches` and `Stats::unmapped_branches` are the split, and the
honest way to check whether any of this is working on your target:
`print_stats` reports them as `Branch map: N entries, M mapped, K unmapped`.

Building without `--branch-map` keeps the old behaviour, including for anyone
using the library directly: `Config::branch_map` and `Session::set_coverage` are
both optional, and `set_coverage` on a session with no map is an error rather
than a silent no-op.

### Checking that the two sides really do agree

`mapped_branches` only says how *much* of the join lands. It cannot say whether
the join is *right*, and that is the failure that costs bugs: a map that
resolved every branch to some other branch's edge id reports a perfect ratio
while telling the stage that everything is already covered. Nothing errors out.
The fuzzer just quietly finds less.

Three checks, cheapest first.

**1. Compare the two id tables, without running anything.** SymSan has its own
counterpart to `AFL_LLVM_DOCUMENT_IDS`: set `SYMSAN_DOCUMENT_IDS` and the
instrumentation appends a `cid=`/`src=` line per branch it instruments, in the
same shape AFL++ uses.

```bash
SYMSAN_DOCUMENT_IDS=$PWD/symsan.ids \
    KO_CC=clang-18 KO_USE_FASTGEN=1 <symsan>/b4/bin/ko-clang -g -o target.symsan target.c
```

Both files are appended to, so delete them before a rebuild. Comparing the
`src=` columns of the two answers the question no ratio can: a location both
sides emit but with *different* columns means the two clangs disagree and the
join is dead, while a location only SymSan emits is AFL++ having pruned the
block, which is expected. A `kind=switch` line never joins — only its cases
are edges, and those come out as `kind=switch-case` lines carrying their case
value — and neither does `kind=select`; see the limits above. They are labelled
rather than left to look like breakage.

**2. Check one input against `afl-showmap`.** `b4/bin/covcheck` traces an input
through the SymSan build and checks every branch direction it took against the
edges the fuzzer's build recorded for the same bytes:

```bash
<aflpp>/afl-showmap -o showmap.out -- ./target.afl input
<symsan>/b4/bin/covcheck -m branch.map -c showmap.out -i input -- ./target.symsan @@
```

It exits non-zero on a contradiction. `tests/fuzzing/branch_map_join.c` in the SymSan
tree is this run as a lit test, including the negative half — the same run with
a deliberately wrong map has to come out `INCONSISTENT`, or a vacuous check
would look identical to a passing one. `tests/fuzzing/branch_map_switch.c` is the same
for switch cases, corrupting only the lines that carry a `case=`.

**3. Audit every entry during a real run.** `--validate-branch-map` (or
`SymSanStageBuilder::validate_coverage`) does the same comparison on each traced
corpus entry, and logs at `error` level when one contradicts the map:

```bash
RUST_LOG=error ./target/release/symsan-fuzz -i ./seeds -o ./out \
    --symsan ./target.symsan --branch-map ./branch.map --validate-branch-map \
    -- ./target.afl @@
```

The ground truth is free: the fuzzer's map feedback is built with
`track_indices()`, so every corpus entry already carries the edge set its own
execution produced — nothing is run a second time. It still costs a hash insert
per branch, so this is a check to run when setting up a new target, not to leave
on.

All three only ever report one direction of disagreement: every branch SymSan
executed must map to an edge the fuzzer recorded. The converse means nothing —
the fuzzer records every edge it walks, including concrete branches and plain
blocks, and a concolic trace only ever hears about the ones whose condition
depended on the input.

## The solver ladder

Three solvers, tried in cost order, each one asked only what the cheaper ones
could not answer — `report_result(false)` is what escalates a task to the next
rung (see above).

| rung | what it is good at | default in `symsan-fuzz` |
| --- | --- | --- |
| **i2s** | input-to-state: an input byte, or a run of them, compared against a constant. Nearly free — it reads the answer off the constraint rather than searching. | on (`--symsan-no-i2s`) |
| **jigsaw** | JITs the constraint and runs gradient descent on it. Handles arithmetic i2s cannot invert, at maybe tens of microseconds a task. | on (`--symsan-no-jigsaw`) |
| **z3** | a real SMT solver: decides what the other two only search for, and is the only one that can say *unsat*. Also the only one that can spend seconds on one task. | **off** (`--symsan-z3`) |

Z3 is off by default because a fuzzing loop is a throughput game, and a rung
that occasionally blocks for seconds costs more exec's than the extra solves
return. That is a default, not a judgement: turn it on for a target whose checks
jigsaw's descent cannot climb — and if you do, `--symsan-timeout` is what bounds
the damage.

Turning a rung off is otherwise a measurement tool: run the same target with
`--symsan-no-i2s` to see what the rungs behind it were actually contributing,
since i2s alone cracks most of the branches a real target has. With every rung
off the stage still traces (and still costs what tracing costs) but can solve
nothing; it says so at startup rather than looking like a target that resists
solving.

Using the library directly the knobs are `Config::i2s/jigsaw/z3`, or
`SYMSAN_NO_I2S`, `SYMSAN_USE_JIGSAW` and `SYMSAN_USE_Z3` in the environment.
Note the defaults differ by entry point: `SymSanStageBuilder` is set up for
fuzzing (i2s + jigsaw), while `Config` and the C++ `ConcolicConfig` start from
i2s alone and add to it, which is what the older drivers expect.

## The cmplog baseline (`--cmplog`)

The question SymSan has to answer is not "does it find things" but "does it find
things the cheap technique does not". The cheap technique is cmplog: log both
operands of every comparison the target executes, then splice the operand it
wanted into the input bytes it read. No solver, no constraints — the same idea as
the i2s rung, reached by observation instead of symbolic execution.

`symsan-fuzz --cmplog <binary>` runs LibAFL's own implementation of it, against a
third build of the target:

```bash
AFL_LLVM_CMPLOG=1 afl-clang-fast -o target.cmplog target.c

# the baseline
symsan-fuzz -i ./seeds -o ./out --cmplog ./target.cmplog -- ./target.afl @@
# SymSan
symsan-fuzz -i ./seeds -o ./out --symsan ./target.symsan -- ./target.afl @@
# both
symsan-fuzz -i ./seeds -o ./out --symsan ./target.symsan \
                                --cmplog ./target.cmplog -- ./target.afl @@
# and with neither flag, the floor: havoc alone
```

Three LibAFL stages behind the one flag, gated to run once per corpus entry
(colorization and the trace both cost real executions, and the answer does not
change the second time round):

1. **`ColorizationStage`** replaces input bytes with random ones that leave the
   coverage bitmap unchanged. What survives is the bytes the comparisons depend
   on — the map from "this value" back to "these offsets".
2. **`AflppCmplogTracingStage`** runs the cmplog build, which writes every
   comparison's operands into a shared `AflppCmpLogMap`.
3. **`AflppRedQueen`** puts each logged operand where the colorized bytes say the
   other one came from.

Two flags, four arms, one binary — which is the point. Comparing against
`afl-fuzz -c` instead would mean comparing two different fuzzers, and any
difference could be the scheduler, the mutator or the feedback rather than the
technique. Here everything outside the stage list is literally the same code.

## The fork server

Tracing an input used to mean a full `execv`: dynamic linking, the shadow and
union table mappings, interceptor setup — all of it repeated for every single
input, and none of it depending on the input. The stage now spawns the target
once and forks a child per trace instead. On `tests/data/branch.c` that is
**24.6 ms → 16.4 ms per trace**, i.e. about 8 ms of fixed cost removed; the
smaller the target, the larger the fraction.

It is on by default in `SymSanStageBuilder`, and `--symsan-no-forkserver` turns
it off. Using the library directly, it is `Config::forkserver(true)` (default
off there) or `SYMSAN_FORKSRV=1`.

Two conditions have to hold, and *neither is an error* — the session quietly
falls back to exec'ing per run, so turning it on is always safe:

- **File input.** A stdin target needs its fd wired into the child, and there is
  no way to reach into a process that is already running.
- **A backend that has one.** `backend/forkserver.cpp` is linked into Fastgen,
  so a target built with `KO_USE_FASTGEN=1` has it. Thoroupy has its own.

Turn it off if the target keeps state across `main()` that a fork would wrongly
share — a `/dev/urandom` fd it seeded itself from, say. The fork happens before
the input is loaded but after the runtime is set up (see the comment at the call
to `InitializeSymSanForkServer` in `runtime/dfsan/dfsan.cpp`), so anything a
*constructor* did is shared between runs.

The protocol is AFL's, on fds 198/199, deliberately: it means a SymSan binary is
also drivable by AFL++ or LibAFL's forkserver executor unchanged, which is what
a coverage backend would need. The one wrinkle is that the event pipe
no longer reaches EOF between runs, since its write end lives in the server —
the child's wait status on fd 199 marks end-of-trace instead, and because the
server only writes it after `waitpid()`, every event that child produced is
already in the pipe by then.

## Process model

SymSan's launcher keeps its configuration in a C file-global, so **one session
per process** — which means one `SymSanStage` per process. `Session::new()`
returns `Error::Busy` for a second one rather than letting two corrupt each
other.

This is not a real limit. LibAFL's `Launcher` scales by forking a process per
core, each getting its own stage and its own session, and the union-table
shared memory is already named `/symsan-union-table-<pid>`.

## Using the binding on its own

```rust
use symsan::{Config, Session};

let config = Config::new("./target.symsan", "/tmp/.cur_input")
    .args(["./target.symsan", "/tmp/.cur_input"])
    .use_stdin(false)
    .jigsaw(true)
    .z3(true)
    .timeout_ms(60_000);

let mut session = Session::new()?;
session.init(&config)?;

let tasks = session.trace(b"AAAAAAAAAAAAAAAA")?;
println!("{tasks} solving tasks");

while let Some(solution) = session.next_solution() {
    let interesting = run_and_check(&solution);   // your harness
    session.report_result(interesting);
}

println!("{:?}", session.stats());
```

`Config::from_env()` reads the same `SYMSAN_*` variables the AFL++ mutator
honours (`SYMSAN_TARGET`, `SYMSAN_USE_JIGSAW`, `SYMSAN_USE_Z3`,
`SYMSAN_USE_NESTED`, `SYMSAN_TRACE_BOUNDS`, `SYMSAN_SOLVE_UB`,
`SYMSAN_SAVE_SOLVED`, …) by calling the same C++ code, so the two front-ends
cannot drift apart on what a variable means.

## Where the C++ lives

The bindings are deliberately thin. Everything real is shared with the AFL++
mutator:

| | |
|---|---|
| `include/symsan_c.h` | the C ABI; bindgen's input |
| `driver/session/symsan_c.cpp` | forwarding + exception guards |
| `driver/session/concolic-session.cpp` | `rgd::ConcolicSession` — the driver policy |
| `driver/session/trace-session.cpp` | `symsan::TraceSession` — the event pump |
| `parsers/rgd-parser.cpp`, `solvers/` | the RGD stack (i2s → jigsaw → z3) |

If you find yourself about to reimplement parsing or solving in Rust, it already
exists in one of those and is reachable through the C ABI.

## Building and testing

```bash
cd <symsan>/bindings/rust

cargo build                       # or --release
cargo test                        # unit tests + the end-to-end session test
cargo clippy --workspace --all-targets
cargo doc --open -p symsan        # the safe API, with the FFI reasoning
```

`build.rs` finds SymSan by trying `b4`, `b3`, `b2`, `build` under the repository
root. Point `SYMSAN_BUILD_DIR` at an install prefix to override; it panics if
set but wrong, rather than silently linking a different build than you meant.

The LibAFL checkout is a path dependency on `../../../libafl`, i.e. a sibling of
the symsan repo. Change it in the workspace `Cargo.toml` if yours is elsewhere.

### A note on the tests

`cargo test` runs a test binary's `#[test]` functions on several threads of one
process, which collides with one-session-per-process. So all session-using
assertions live in a single `#[test]` in `symsan/tests/session.rs`; a second
session test would need a second *file*, since cargo gives each file its own
binary. The tests that need no session are unit tests inside `src/lib.rs`.

## For the Rust-curious

A few things in here are worth reading if you are still learning the language;
the comments in the source go into more detail:

- **`Session` is an RAII handle.** It owns a raw C pointer and frees it in
  `Drop`. You cannot leak it or double-free it, and the borrow checker stops you
  from using a solution buffer after the call that invalidates it.
- **`next_solution` returns an owned `Vec`, not a `&[u8]`.** The borrow would
  block the `report_result` call that must immediately follow, and `BytesInput`
  wants an owned buffer anyway. `next_solution_ref` is the zero-copy escape
  hatch, and its lifetime shows you exactly why the copy is the default.
- **The C enums become newtype structs, not Rust `enum`s.** A Rust `enum`
  holding a value outside its variants is instant UB, and a value crossing FFI
  cannot be proven in range. See `check()` in `symsan/src/lib.rs`.
- **`SymSanStage` has no type parameters.** The four generics live on the
  `impl Stage<E, EM, S, Z>` instead, which is legal because all of them appear
  in the trait — so no `PhantomData` and no turbofish at the call site.
- **`tuple_list!` builds a type, not a value.** That is why `fuzzer/src/main.rs`
  has two nearly identical arms for "with and without the stage" instead of an
  `if`: the set of stages is fixed at compile time, which is how LibAFL keeps
  dynamic dispatch out of the hot loop.
