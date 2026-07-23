// Floating-point solving, double challenge (in-process z3 solver only).
// Adapted from the AFL "test-double.c" challenge: three double values (read
// from tainted bytes) must land inside tight ranges, and a fourth must match
// a constant *exactly* (`== 3.141592653589793116`) -- a case the challenge
// author notes "no fuzzer can solve".  A concolic solver reconstructs each
// value, including the exact IEEE-754 bit pattern, from a single FCmp.  Each
// range check `lo <= x && x <= hi` is expressed as `fabs(x - mid) < half` so
// exactly one solver task is produced per check.  The four checks are
// independent (not nested behind an early bail), so one concolic run flips all
// of them and emits one input per check -- see tests/switch.c for the same
// multi-output pattern.  Exercises double FCmp (range + exact equality),
// FSub, and the fabs intrinsic.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*32)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
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
  memcpy(&x0, buf + 0, sizeof x0);
  memcpy(&x1, buf + 8, sizeof x1);
  memcpy(&x2, buf + 16, sizeof x2);
  memcpy(&x3, buf + 24, sizeof x3);

  // Seed is all zeros, so every value misses its target; the z3 solver must
  // reconstruct each double expression, including the exact constant.
  if (fabs(x0 - 0.5) < 0.49) {            // range [0.01, 0.99]
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }
  if (fabs(x1 - 105.45) < 3.55) {         // range [101.9, 109.0]
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }
  if (fabs(x2 - 22222223.5) < 1.6) {      // range [22222221.9, 22222225.1]
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
