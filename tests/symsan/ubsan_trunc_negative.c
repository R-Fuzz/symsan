// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x18\xfc\xff\xff\x05\x00\x00\x00')" > %t.bin
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env SYMSAN_PARSE_ONLY=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin | FileCheck %s --check-prefix=PARSE
// PARSE: PARSE-SUMMARY conds=3 ok=3 empty=0 failed=0

// The signed-truncation half of the same 64-bit-sign-test bug that
// ubsan_shift_negative.c and ubsan_shift_negexp.c cover for shifts.
//
// The guard was `(int64_t)orig_op1 >= target`, with target the new type's
// minimum sign-extended to 64 (-128 for int8_t).  orig_op1 is an old_size-bit
// value zero-extended into a uint64_t, so it is never negative and the guard
// was always taken -- even for a value that is already below the minimum.  For
// x == -1000 the emitted `x <s -128` is already true, which is exactly what
// __taint_trace_cond(cond, 0, ...) says it is not.
//
// ubsan_trunc.c cannot catch this: its seed is all zeros, and 0 >= -128 both
// before and after the fix.  y == 5 below is that consistent case, kept as a
// positive control so a fix that emitted nothing at all would still fail.

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
  int32_t x = 0, y = 0;

  chk_fread(&x, sizeof(x), 1, fp);
  chk_fread(&y, sizeof(y), 1, fp);
  fclose(fp);

  // x is -1000, already below INT8_MIN; y is 5, comfortably in range
  int8_t a = (int8_t)x;
  int8_t b = (int8_t)y;
  printf("%d %d\n", a, b);
  return 0;
}
