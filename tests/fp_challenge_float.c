// Floating-point solving, float32 challenge (in-process z3 solver only).
// Adapted from the AFL "test-float.c" challenge, which requires landing three
// float32 values (read from tainted bytes) inside very tight ranges that
// random mutation can't hit.  Each range check `lo <= x && x <= hi` is
// expressed as a single branch `fabsf(x - mid) < half` so exactly one solver
// task is produced per check (compound `&&` guards only generate a task for
// the first short-circuited condition).  The three checks are independent
// (not nested behind an early bail), so a single concolic run flips all of
// them and emits one input per check -- see tests/switch.c for the same
// multi-output pattern.  Exercises float32 FCmp + FSub + the fabs intrinsic.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*12)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lm
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

  // Seed is all zeros, so every value misses its range; the z3 solver must
  // reconstruct each float32 expression and land inside the range.
  if (fabsf(x0 - 1000005.5f) < 5.49f) {   // range [1000000.01, 1000010.99]
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }
  if (fabsf(x1 - 105.45f) < 3.55f) {      // range [101.9, 109.0]
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }
  if (fabsf(x2 - 22222223.5f) < 1.6f) {   // range [22222221.9, 22222225.1]
    // CHECK-GEN3: Good3
    printf("Good3\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
