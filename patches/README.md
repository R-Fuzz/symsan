# Patches against other projects

## `aflpp-document-ids.patch`

Against [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) (developed on
`++5.02c`, LLVM 18). Apply with:

```bash
cd /path/to/AFLplusplus
git apply /path/to/symsan/patches/aflpp-document-ids.patch
make -f GNUmakefile.llvm ./SanitizerCoverageLTO.so
```

### What it does

`AFL_LLVM_DOCUMENT_IDS=<file>` already dumps one line per instrumented edge:

```
ModuleID=<n> Function=<name> edgeID=<n>
```

Function granularity is not enough to join against anything. The patch appends
the source location of the branch the edge comes out of, so a second toolchain
that names branches by location — SymSan does; see `include/branch_id.h` — can
build a `branch id -> edge id` table and share coverage with the fuzzer:

```
ModuleID=<n> Function=<name> edgeID=<n> dir=<0|1> src=<file>:<line>:<col>
```

`dir=1` is the true edge. `src=` is last because a path may contain spaces and
colons; parse it from the right.

A switch case block gets the same treatment with a wider key, because the
location alone names the switch rather than any one case:

```
ModuleID=<n> Function=<name> edgeID=<n> dir=1 case=<value> src=<switch's location>
```

`case=` is the label's constant zero-extended to 64 bits — the form the
consumer's own instrumentation sees, so both sides normalise the same way. It is
always `dir=1`: "take this case" is this block, while "do not take it" is
everywhere else the switch could go and is not one edge at all.

Fields are only appended for blocks that are one side of a conditional branch or
the destination of a case, so existing consumers see unchanged lines everywhere
else.

The patch is safe because `SplitAllCriticalEdges()` has already run by this
point: every successor of a conditional branch has that branch's block as its
single predecessor, so "this block has one predecessor ending in a conditional
`br`" identifies the edge exactly, and the same holds for each case destination
of a switch. Splitting declines unreachable destinations, so two case values
can still share a block; then both are emitted, against the one edge id, and the
predecessor is asked for as the *unique* one rather than the single one.

The branch is not always the *immediate* predecessor, though. Pruning (below)
drops a block that fully dominates its successors, so wherever one side of an
`if` opens with a straight-line chain — a `while (1) { …; return; }` bail macro,
a loop body falling into its latch — the block that survives to be instrumented
sits one or more **unconditional** hops below the branch. Asking only the
immediate predecessor left most edges on a real target undocumented; the patch
therefore walks those hops back up before looking for the branch. The walk is
exact rather than heuristic: each step requires the child to be its parent's
only successor *and* the parent to be the child's only predecessor, so the two
blocks run under precisely the same condition and the edge means the same thing
at either end. It is bounded at 16 hops because an unconditional cycle is
representable in IR, if not reachable at runtime.

The difference is not marginal. On `fuzzer-challenges` the walk roughly doubles
the documented edges per target — `test-crc32` 8 → 16, `test-transform` 17 → 30
— and, more to the point, the recovered edges are the ones inside loops, which
is where a coverage-sharing consumer most needs an answer.

### Checking the result

SymSan has the mirror image of this: `SYMSAN_DOCUMENT_IDS=<file>` makes its
instrumentation append the same shape of line for each branch *it* names,
`cid=` in place of `edgeID=` plus a `kind=` saying `br`, `switch`, `switch-case`
or `select`. Diffing the `src=` columns of the two files says whether the two
toolchains agree, without running anything — and separates "the two clangs
disagree" (same location, different column) from "AFL++ pruned it" (a location
only SymSan emits). `b4/bin/covcheck` is the dynamic version, against `afl-showmap` as
ground truth; see the SymSan tree's `bindings/rust/README.md`.

Note both files are *appended* to, so remove them before a rebuild.

### Requirements and limits

- **LTO only.** `AFL_LLVM_DOCUMENT_IDS` is not implemented for PCGUARD, and
  could not be: PCGUARD ids are handed out at process start by
  `__sanitizer_cov_trace_pc_guard_init`, so no file written at link time can
  describe them.
- **Needs `-g`.** Without debug info there is no location to emit.
- **Both builds want the same clang major version.** Column numbers are the
  fragile part of the key; a mismatch shows up as a low join rate rather than
  as an error.
- **Pruned blocks have no id.** `shouldInstrumentBlock()` drops blocks that
  dominate all their successors, so some branch directions are simply absent
  from the file — typically the side that leads into a nested branch. The
  walk-up described above recovers the cases where the pruned block is followed
  by an unconditional chain, but not the ones where nothing downstream is
  instrumented either. Consumers must still treat "not in the map" as "no
  information" and fall back.

  There is no way to turn that pruning off: the `lto-coverage-prune-blocks`
  `cl::opt` is registered by the plugin, but `ld.lld` parses `--mllvm` before it
  loads the plugin, so the option is rejected as unknown. Forcing
  `Options.NoPrune` from an environment variable instead was tried and makes
  `ld.lld` spin indefinitely on even a 50-line input, which suggests the
  no-prune path has simply never been exercised under LTO.
- **A switch's `default:` is not described.** Its block still gets an `edgeID=`
  line, but with no `case=` to name it by: "none of the labels matched" is a
  conjunction of every case being false, not a branch a location-plus-value key
  can address.
- **`select` is not described either.** AFL++ does allocate two ids per scalar
  select (and two per element for a vector one), it just never writes them, so
  this is a missing hunk rather than a limit of the approach.
