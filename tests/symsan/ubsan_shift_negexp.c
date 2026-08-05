// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x01\x00\x00\x00\xff\xff\xff\xff')" > %t.bin
// RUN: clang -O0 -fsanitize=shift -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env SYMSAN_PARSE_ONLY=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin | FileCheck %s --check-prefix=PARSE
// PARSE: PARSE-SUMMARY conds=1 ok=1 empty=0 failed=0
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 | FileCheck %s
// CHECK: runtime error: left shift of negative value

// Companion to ubsan_shift_negative.c, for the *exponent* half of the same
// width bug.  There the base was already negative at i32; here the exponent is.
//
// The guard was `(int64_t)orig_op2 >= 0`, and orig_op2 holds an op_size-bit
// value zero-extended into a uint64_t, so for any operand narrower than 64 bits
// it is never negative and the guard was always taken.  The comparison it emits
// is built at op_size, where -1 *is* negative -- so `amt <s 0` is already true,
// and __taint_trace_cond(cond, 0, ...) asserts it is false.  z3-ts rejects that
// as `value mismatch for cond`.
//
// The base is 1 so the shift-base check below it stays consistent and this test
// still has something that parses: conds must not go to zero for the wrong
// reason.
//
// That surviving check is also the oracle arm, and it is what makes the
// exponent gating observable.  With the exponent 0xFFFFFFFF the shift is
// *already* undefined -- out-of-range exponent -- so a shift-base task phrased
// as `base <s 0` alone is answered by flipping the base and leaving the
// exponent where it was.  The input is UB, but not the UB cid 5 names: run it
// under -fsanitize=shift and the first diagnostic is "shift exponent -1 is
// negative" (measured).  clang never asks that question in that state --
// EmitShl guards CheckShiftBase on the exponent being in range and phis in
// `true` otherwise -- so the task is now `base <s 0 && amt <u 32`, the solver
// has to bring the exponent back in range, and the diagnostic is the one below.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return 0;
  }

  FILE* fp = chk_fopen(argv[1], "rb");
  int32_t base = 0, amt = 0;

  chk_fread(&base, sizeof(base), 1, fp);
  chk_fread(&amt, sizeof(amt), 1, fp);
  fclose(fp);

  return (base << amt) & 1;
}
