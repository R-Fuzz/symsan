// Floating-point input-to-state solving THROUGH a single arithmetic op.
//
// Each guard compares an input-derived value that has passed through one FP
// arithmetic op against a constant (`x op C <cmp> K`).  The i2s solver inverts
// the arithmetic to recover the input (write `K-C`, `K/C`, ... into the bytes),
// the same RedQueen trick it uses for integer `x op C == K` -- no z3 required.
// Constants are chosen so every inversion is exact (no rounding), and every
// guess is verified before i2s commits it.
//
// Covers FAdd/FMul (float) and FSub/FDiv (double), including a constant on the
// left of a non-commutative op (`10.0 - x`).  The checks are independent (not
// nested behind an early bail), so one concolic run emits one input per check
// (see tests/symsan/switch.c).
//
// The %afltest lines exercise the out-of-process RGD path with i2s only (no
// SYMSAN_USE_Z3), demonstrating that i2s alone solves each branch; the %fgtest /
// KO_USE_Z3 lines additionally confirm the in-process z3 solver.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*40)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: %t.uninstrumented %t.out/id-0-0-4 | FileCheck --check-prefix=CHECK-GEN5 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: %t.uninstrumented %t.out/id-0-0-4 | FileCheck --check-prefix=CHECK-GEN5 %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: %t.uninstrumented %t.out/id-0-0-4 | FileCheck --check-prefix=CHECK-GEN5 %s

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

  unsigned char buf[40] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  float x0, x1;
  double x2, x3, x4;
  memcpy(&x0, buf + 0,  sizeof x0);
  memcpy(&x1, buf + 4,  sizeof x1);
  memcpy(&x2, buf + 8,  sizeof x2);
  memcpy(&x3, buf + 16, sizeof x3);
  memcpy(&x4, buf + 24, sizeof x4);

  // Seed is all zeros, so every guard fails.  i2s inverts the one arithmetic op
  // in each guard to recover the required input.
  if (x0 + 3.5f == 10.0f) {        // FAdd (float):  x0 = 6.5
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }
  if (x1 * 2.0f == 9.0f) {         // FMul (float):  x1 = 4.5
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }
  if (x2 - 1.25 == 100.0) {        // FSub (double, const rhs):  x2 = 101.25
    // CHECK-GEN3: Good3
    printf("Good3\n");
  }
  if (x3 / 4.0 == 2.5) {           // FDiv (double, const rhs):  x3 = 10.0
    // CHECK-GEN4: Good4
    printf("Good4\n");
  }
  if (10.0 - x4 == 3.0) {          // FSub (double, const lhs):  x4 = 7.0
    // CHECK-GEN5: Good5
    printf("Good5\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
