// Floating-point solving, float32 challenge.  Adapted from the AFL
// "test-float.c" challenge, which requires landing three float32 values (read
// from tainted bytes) inside very tight ranges that random mutation can't hit.
//
// These challenges are meant for the *input-to-state* (i2s) solver: each guard
// is a DIRECT comparison of an input-derived float against a constant (no FP
// arithmetic in between), so i2s can flip it by copying the constant's IEEE-754
// bytes into the input.  A two-sided range `lo <= x && x <= hi` short-circuits
// after its first condition, but flipping that first bound to the boundary
// (x = lo) already lands inside the range (lo <= hi), so a single concolic run
// solves each range -- no arithmetic reasoning / z3 required.  The three checks
// are independent (not nested behind an early bail), so one run emits one input
// per check (see tests/symsan/switch.c for the multi-output pattern).
//
// The %afltest lines exercise the out-of-process RGD path with i2s only (no
// SYMSAN_USE_Z3), demonstrating that i2s alone solves the challenge; the
// %fgtest / KO_USE_Z3 lines additionally confirm the in-process z3 solver.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*12)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s

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

  unsigned char buf[12] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  float x0, x1, x2;
  memcpy(&x0, buf + 0, sizeof x0);
  memcpy(&x1, buf + 4, sizeof x1);
  memcpy(&x2, buf + 8, sizeof x2);

  // Seed is all zeros, so every value misses its range.  Each guard is a direct
  // float32 comparison against a constant, so i2s copies the boundary into the
  // input; flipping the first bound to the boundary lands inside the range.
  if (x0 >= 1000000.01f && x0 <= 1000010.99f) {
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }
  if (x1 >= 101.9f && x1 <= 109.0f) {
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }
  if (x2 >= 22222221.9f && x2 <= 22222225.1f) {
    // CHECK-GEN3: Good3
    printf("Good3\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
