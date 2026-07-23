// FP predicate / rounding libcall solving (in-process z3 solver only; the
// RGD/fastgen path does not model FP).  Exercises the custom wrappers that
// replace the old (broken) `functional` ABI for math libcalls: lrint / llrint
// (round-to-nearest then convert to integer) and __signbit (IEEE sign bit).
// clang keeps these as real calls (isnan/isinf/finite are lowered inline and
// are already covered by the FCmp path).  Reads tainted bytes into three
// doubles; the all-zero seed misses every branch, so a single concolic run
// flips each and emits one input per branch -- see tests/switch.c for the same
// multi-output pattern.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*24)' > %t.bin
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

  unsigned char buf[24] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  double x0, x1, x2;
  memcpy(&x0, buf + 0, sizeof x0);
  memcpy(&x1, buf + 8, sizeof x1);
  memcpy(&x2, buf + 16, sizeof x2);

  // round-to-nearest-integer libcall (custom fp_lrint wrapper)
  if (lrint(x0) == 42) {
    // CHECK-GEN1: BRANCH_LRINT
    printf("BRANCH_LRINT\n");
  }
  // 64-bit round-to-integer libcall
  if (llrint(x1) == 1000) {
    // CHECK-GEN2: BRANCH_LLRINT
    printf("BRANCH_LLRINT\n");
  }
  // IEEE sign-bit predicate libcall (custom fp_signbit wrapper)
  if (__signbit(x2)) {
    // CHECK-GEN3: BRANCH_SIGNBIT
    printf("BRANCH_SIGNBIT\n");
  }

  // CHECK-ORIG: done
  printf("done\n");
  return 0;
}
