// 64-bit FP->int cast solving (in-process z3 solver only).  Regression test for
// the fpa.to_sbv/to_ubv partial-function boundary bug: INT64_MAX / UINT64_MAX
// are not representable as doubles and round *up* to 2^63 / 2^64 (outside the
// target range, where the conversion is undefined), so an over-loose upper
// range bound let the solver pick that out-of-range point and assign the result
// freely -- producing an input that does not actually satisfy the branch.  Each
// branch below casts a tainted double to a 64-bit integer and compares to a
// concrete value; the all-zero seed misses both, so a single concolic run flips
// each and emits one input per branch (see tests/switch.c for the pattern).
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*16)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  unsigned char buf[16] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  double x0, x1;
  memcpy(&x0, buf + 0, sizeof x0);
  memcpy(&x1, buf + 8, sizeof x1);

  // FPToSI to a 64-bit signed integer
  if ((int64_t)x0 == 1000000) {
    // CHECK-GEN1: BRANCH_S64
    printf("BRANCH_S64\n");
  }
  // FPToUI to a 64-bit unsigned integer
  if ((uint64_t)x1 == 2000000) {
    // CHECK-GEN2: BRANCH_U64
    printf("BRANCH_U64\n");
  }

  // CHECK-ORIG: done
  printf("done\n");
  return 0;
}
