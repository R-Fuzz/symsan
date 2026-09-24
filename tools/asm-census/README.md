# Inline asm census

Counts the inline asm call sites in a set of (uninstrumented) bitcode files
and classifies each against what `UCSanVisitor::visitInlineAsm`
(`instrumentation/UCSanPass.cpp`) will do with it.  Written for the kernel
(`~/fast/linux/linux-6.8.2/bclist`), but it takes any list of bitcode files.

```bash
tools/asm-census/run.sh ~/fast/linux/linux-6.8.2/bclist /tmp/asm-census
```

This builds `AsmCensus.so` with `clang++-18`/`llvm-config-18` (override with
`CXX`, `LLVM_CONFIG`, `OPT`), runs `opt -passes=asm-census` over every entry
in parallel, and prints the summary from `agg.py`.  Entries that are not
bitcode, such as native objects assembled from `.S` files, fail in `opt` and
are listed in `err.log`.  The kernel list has 36 of them.  The kernel run
takes a few seconds.

## Fields (one JSON object per site)

| field | meaning |
|---|---|
| `file`, `fn` | source file and enclosing function |
| `asm`, `cons` | asm template and LLVM constraint string |
| `ind_out`, `ind_in` | kind of each memory (`*m`) output / input operand |
| `reg_ptr_in` | pointer operands passed in a register: `kind`, operand number, constraint, and `deref` (whether the template contains `($N)` or `(${N:...})`) |
| `size_bad` | checked memory operands whose check size (from the underlying alloca/global, else 0) differs from the operand's `elementtype` size |
| `call_sym`, `call_action` | what UCSan's `call` detection extracts, and whether it would `rewrite` the asm to a direct call, `delete` it (the symbol is not a module Function), or `skip` it |
| `ret`, `ret_used` | result type and whether it is used; the result gets no taint label |
| `trap`, `all_clobbers` | a trap pattern is present, and whether it is clobber-only (only those become `exit(180)`) |
| `imm` | constant-int operands (used to split `_BUG_FLAGS` into BUG and WARN) |

Operand kinds: `global`/`constexpr_*`/`alloca`/`function`/`null` are never
passed to `ucsan_check_pointer`.  `gep_global`, `gep_alloca`, `arg`, `load`,
`call`, `phi`, `inttoptr` and `other` name where a checked pointer comes from.

## Reading the numbers

- The classification copies UCSan's logic *before* the inline asm rework
  (commit 2d58f46): its string matching for `call`, its trap patterns and its
  operand-check rules.  It is the record of what that version got wrong, and
  the baseline the rework was measured against.  It does not describe the
  current `visitInlineAsm`.  To check the current passes, run them over the
  same bitcode and count what is left: that was 101,703 of 129,812 sites,
  with no `ud2` and none of the modeled helper calls.
- `size_bad` overstates the impact.  A memory operand reached through a
  struct field is preceded by a GEP that UCSan checks with the struct's size,
  so the size-0 asm check only matters for a bare `*p` as the first access.
  `%gs:` percpu operands are harmless while the harness's `gs` base is 0.
- `deref` is a textual approximation.  A register pointer used only as an
  address, as `this_cpu_ptr`'s `add %gs:...` does, is correctly not counted.

The matching regression tests are `tests/ucsan/test/asm_*.c`.
