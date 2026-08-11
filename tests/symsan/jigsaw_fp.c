// Floating-point solving in the JIGSAW solver (JIT + numeric gradient descent).
//
// The out-of-process RGD chain runs i2s -> jigsaw -> z3 (optimistic; first SAT
// wins).  Each guard below compares a value that has passed through an FP op
// with TWO symbolic operands (or an FP intrinsic) against a constant.  i2s can
// only invert a single FP op with a *constant* operand, so it rejects all of
// these; jigsaw JIT-compiles the constraint, computes a measurable FP distance
// (0 == satisfied), and follows the byte gradient to a solution.
//
// These are all INEQUALITIES on purpose: gradient descent excels at driving a
// measurable distance to zero, but cannot reliably land on an exact FP equality
// (e.g. x*x == 25.0), which is z3's job.  So this test isolates jigsaw's
// strength.
//
// RUN lines use %afltest with SYMSAN_USE_JIGSAW=1 and WITHOUT SYMSAN_USE_Z3:
// enabling z3 would let z3 mask a jigsaw regression, and i2s alone solves none
// of these (verified).  There are no %fgtest / KO_USE_Z3 lines because those
// exercise the in-process z3 path, which has no jigsaw/i2s chain.
//
// The checks are independent (not nested behind an early bail), so one concolic
// run emits one input per check (see tests/symsan/switch.c).
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*60)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" SYMSAN_USE_JIGSAW=1 %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: %t.uninstrumented %t.out/id-0-0-4 | FileCheck --check-prefix=CHECK-GEN5 %s
// RUN: %t.uninstrumented %t.out/id-0-0-5 | FileCheck --check-prefix=CHECK-GEN6 %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  unsigned char buf[60] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  double x0, x1, x2, x3, x4, x5, x6;
  float  fx;
  memcpy(&x0, buf + 0,  sizeof x0);  // FMul (x0*x0)
  memcpy(&x1, buf + 8,  sizeof x1);  // FAdd operand
  memcpy(&x2, buf + 16, sizeof x2);  // FAdd operand
  memcpy(&x3, buf + 24, sizeof x3);  // FpSqrt
  memcpy(&fx, buf + 32, sizeof fx);  // float FMul
  memcpy(&x4, buf + 36, sizeof x4);  // FNeg
  memcpy(&x5, buf + 44, sizeof x5);  // FpMin operand
  memcpy(&x6, buf + 52, sizeof x6);  // FpMin operand

  // Seed is all zeros, so every guard fails.  Each branch has an FP op that i2s
  // cannot invert (two symbolic operands, or an intrinsic), so jigsaw's
  // gradient descent must find the solution.
  if (x0 * x0 > 25.0) {           // two symbolic operands (same var)
    // CHECK-GEN1: GoodMul
    printf("GoodMul\n");
  }
  if (x1 + x2 > 100.0) {          // two symbolic vars
    // CHECK-GEN2: GoodAdd
    printf("GoodAdd\n");
  }
  if (sqrt(x3) > 3.0) {           // FP intrinsic (i2s rejects sqrt)
    // CHECK-GEN3: GoodSqrt
    printf("GoodSqrt\n");
  }
  if (fx * fx > 9.0f) {           // float path (compare promoted to double)
    // CHECK-GEN4: GoodFMul
    printf("GoodFMul\n");
  }
  if (-x4 > 10.0) {               // FNeg
    // CHECK-GEN5: GoodNeg
    printf("GoodNeg\n");
  }
  if (fmin(x5, x6) > 7.0) {       // FpMin, two symbolic vars
    // CHECK-GEN6: GoodMin
    printf("GoodMin\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
