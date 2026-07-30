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
colons; parse it from the right. Fields are only appended for blocks that are
one side of a conditional branch, so existing consumers see unchanged lines
everywhere else.

The patch is safe because `SplitAllCriticalEdges()` has already run by this
point: every successor of a conditional branch has that branch's block as its
single predecessor, so "this block has one predecessor ending in a conditional
`br`" identifies the edge exactly.

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
  from the file — typically the side that leads into a nested branch. Consumers
  must treat "not in the map" as "no information" and fall back.

  There is no way to turn that pruning off: the `lto-coverage-prune-blocks`
  `cl::opt` is registered by the plugin, but `ld.lld` parses `--mllvm` before it
  loads the plugin, so the option is rejected as unknown. Forcing
  `Options.NoPrune` from an environment variable instead was tried and makes
  `ld.lld` spin indefinitely on even a 50-line input, which suggests the
  no-prune path has simply never been exercised under LTO.
