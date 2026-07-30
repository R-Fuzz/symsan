// Floating-point solving, float64 challenge.  Adapted from the AFL
// "test-double.c" challenge: land four float64 values (read from tainted bytes)
// inside very tight ranges / on an exact constant that random mutation can't hit.
//
// Like the float32 challenge (tests/symsan/fp_challenge_float.c), these guards are
// DIRECT comparisons of an input-derived double against a constant, so the
// *input-to-state* (i2s) solver flips them by copying the constant's IEEE-754
// bytes into the input -- no FP arithmetic reasoning / z3 required.  The last
// check is an EXACT double equality (`x3 == pi`), which i2s solves by writing
// pi's exact bit pattern; the AFL original notes "no fuzzer can solve double
// arithmetic", so the exact-equality form is the hardest case still i2s-solvable.
// The four checks are independent (not nested behind an early bail), so one
// concolic run emits one input per check (see tests/symsan/switch.c).
//
// The %afltest lines exercise the out-of-process RGD path with i2s only (no
// SYMSAN_USE_Z3), demonstrating that i2s alone solves the challenge; the
// %fgtest / KO_USE_Z3 lines additionally confirm the in-process z3 solver.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*32)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s

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

  unsigned char buf[32] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  double x0, x1, x2, x3;
  memcpy(&x0, buf + 0,  sizeof x0);
  memcpy(&x1, buf + 8,  sizeof x1);
  memcpy(&x2, buf + 16, sizeof x2);
  memcpy(&x3, buf + 24, sizeof x3);

  // Seed is all zeros, so every value misses its target.  Each guard is a direct
  // float64 comparison against a constant, so i2s copies the boundary (or, for
  // the exact case, the constant itself) into the input.
  if (x0 >= 0.01 && x0 <= 0.99) {
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }
  if (x1 >= 101.9 && x1 <= 109.0) {
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }
  if (x2 >= 22222221.9 && x2 <= 22222225.1) {
    // CHECK-GEN3: Good3
    printf("Good3\n");
  }
  if (x3 == 3.141592653589793116) {       // exact match
    // CHECK-GEN4: Good4
    printf("Good4\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
