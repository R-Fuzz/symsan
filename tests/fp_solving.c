// Floating-point solving (in-process z3 solver only; jigsaw/RGD does not model FP).
// A single hard-to-reach branch whose guard combines the fabs intrinsic, the
// sqrt libcall (modeled via the dfsan_custom.cpp wrapper), and FP arithmetic
// that clang contracts into @llvm.fmuladd (a*b+c, -ffp-contract=on) followed by
// an FP comparison (FCmp).  The seed misses the branch; the z3 solver must
// reconstruct the FP expression and produce an input that flips it.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import struct,sys; sys.stdout.buffer.write(struct.pack('<d', 1.0))" > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

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

  // fabs (intrinsic) + sqrt (custom libcall wrapper) + `a*2.0+1.0` (contracted
  // to @llvm.fmuladd) + FCmp.  Seed x=1.0 => sqrt(1)*2+1 = 3.0, fails the guard.
  if (sqrt(fabs(x)) * 2.0 + 1.0 > 20.0) {
    // CHECK-GEN: GOOD
    printf("GOOD\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  return 0;
}
