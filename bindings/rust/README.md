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
    └── src/main.rs       forkserver_simple + the SymSan stage
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
- **`switch` is not covered.** SymSan gives every case of a switch the same
  branch id, so a (id, direction) pair cannot name a case block.
- **The two clangs must agree on column numbers**, which in practice means the
  same major version. They currently both use LLVM 18.

`Stats::mapped_branches` and `Stats::unmapped_branches` are the split, and the
honest way to check whether any of this is working on your target:
`print_stats` reports them as `Branch map: N entries, M mapped, K unmapped`.

Building without `--branch-map` keeps the old behaviour, including for anyone
using the library directly: `Config::branch_map` and `Session::set_coverage` are
both optional, and `set_coverage` on a session with no map is an error rather
than a silent no-op.

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
