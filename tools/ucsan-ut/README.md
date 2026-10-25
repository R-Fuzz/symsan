# Unit tests as UCSan entries

Tools for running a gtest test under UCSan, with its literal inputs
symbolized: the test's invocation sequence is the harness, as in UTopia, but
its values are explored instead of fixed. Written for v8's unittests (built
with clang-18 into bitcode), but neither tool knows about v8.

```bash
tools/ucsan-ut/build.sh OUTDIR    # ut-entry and ut-unit, with clang++-18 / llvm-config-18
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
