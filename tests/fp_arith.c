// Floating-point solving smoke test (in-process z3 solver only; the RGD/fastgen
// path does not model FP).  Reads 8 tainted bytes into a double and exercises,
// in four independent branches, FP arithmetic (FMul/FSub), an FP->int cast
// (FPToSI), the sqrt libcall (custom wrapper), and the fabs intrinsic, each
// guarding a hard-to-reach branch.  The seed (x = 1.0) misses all four, so a
// single concolic run flips each and emits one input per branch -- see
// tests/switch.c for the same multi-output pattern.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import struct,sys; sys.stdout.buffer.write(struct.pack('<d', 1.0))" > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_CC=clang-18 KO_USE_Z3=1 %ko-clang -o %t.z3 %s -lm
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

  unsigned char buf[8] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  double x;
  memcpy(&x, buf, sizeof x);

  // arithmetic + FP compare guarding a hard-to-reach branch
  if (x * 2.0 - 1.5 > 3.0) {
    // CHECK-GEN1: BRANCH_ARITH
    printf("BRANCH_ARITH\n");
  }
  // FP -> int cast
  if ((int)x == 42) {
    // CHECK-GEN2: BRANCH_CAST
    printf("BRANCH_CAST\n");
  }
  // intrinsic
  if (sqrt(x) > 5.0) {
    // CHECK-GEN3: BRANCH_SQRT
    printf("BRANCH_SQRT\n");
  }
  // fabs intrinsic + compare
  if (fabs(x) < 0.25) {
    // CHECK-GEN4: BRANCH_FABS
    printf("BRANCH_FABS\n");
  }

  // CHECK-ORIG: done
  printf("done\n");
  return 0;
}
