// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\xfe\xff\xff\xff\xfd\xff\xff\xff')" > %t.bin
// RUN: clang -O0 -fsanitize=signed-integer-overflow -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 | FileCheck %s --check-prefix=OVFL
// OVFL: runtime error: signed integer overflow

// The signed half of the multiplication rewrite.  ubsan_mulovfl_zero.c covers
// the unsigned formula; this covers the one whose own comment said "this is an
// approximation - full check would need wider multiplication".
//
// The old signed model was addition's: `((op1^result) & (op2^result)) <s 0`,
// i.e. both operands have a sign different from the result's.  For two negative
// operands the product is positive, so that holds for *every* such pair --
// including -2 * -3 == 6, which does not overflow anything.  The guard is
// computed from the same expression, so at this seed the runtime concluded an
// overflow had already happened, logged a bogus EVENT_INT_OVERFLOW, and emitted
// no check at all.  With the unsigned side also declining (0xFFFFFFFE *
// 0xFFFFFFFD really does overflow at 32 bits unsigned), this multiply produced
// zero inputs.
//
// The check is now sext(op1) * sext(op2) != sext(result) at twice the width,
// which is exact, so one input comes out and it has to trigger the real thing.

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
  int32_t a = 0, b = 0;

  chk_fread(&a, sizeof(a), 1, fp);
  chk_fread(&b, sizeof(b), 1, fp);
  fclose(fp);

  int32_t result = a * b;
  printf("%d\n", result);
  return 0;
}
