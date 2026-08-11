// Floating-point input-to-state solving THROUGH a transcendental libcall.
//
// Each guard compares an input-derived value that has passed through one FP
// transcendental (exp/exp2/log/log2/log10/log1p/pow) against a constant.  z3's
// fpa theory has NO way to invert these, and jigsaw is integer-only -- both
// reject them (see z3-solver.cpp / z3-ts.cpp / jit.cc).  The i2s solver instead
// computes the closed-form libm inverse (log for exp, exp for log, pow(10,.)
// for log10, s^(1/c) for pow, log(K)/log(c) for a constant-base pow, ...) writes
// those IEEE-754 bytes into the input, and VERIFIES the guess end-to-end before
// committing.  So these branches are solvable by i2s ALONE.
//
// Because only i2s (in the out-of-process RGD chain) can invert transcendentals,
// this test uses ONLY the %afltest RUN lines.  It deliberately omits the
// %fgtest / KO_USE_Z3 lines that tests/symsan/fp_arith_i2s.c keeps: those exercise the
// in-process z3 path, which has no i2s and therefore cannot solve these guards.
//
// NOTE on pow exponents/bases: LLVM's simplify-libcalls (optimizePow) rewrites
// the degenerate forms pow(x,2.0) -> x*x and pow(2.0,x) -> exp2(x) even without
// -ffast-math, which would bypass the __dfsw_pow wrapper entirely.  We therefore
// use a cube (exponent 3.0) for the exponent-constant case and base 3.0 for the
// base-constant case, both of which keep the pow libcall (and thus the fp_pow op).
//
// The checks are independent (not nested behind an early bail), so one concolic
// run emits one input per check (see tests/symsan/switch.c).
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*56)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: %t.uninstrumented %t.out/id-0-0-4 | FileCheck --check-prefix=CHECK-GEN5 %s
// RUN: %t.uninstrumented %t.out/id-0-0-5 | FileCheck --check-prefix=CHECK-GEN6 %s
// RUN: %t.uninstrumented %t.out/id-0-0-6 | FileCheck --check-prefix=CHECK-GEN7 %s
// RUN: %t.uninstrumented %t.out/id-0-0-7 | FileCheck --check-prefix=CHECK-GEN8 %s

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

  unsigned char buf[56] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  double x0, x1, x3, x4, x7;
  float  x2, x5, x6;
  memcpy(&x0, buf + 0,  sizeof x0);  // exp2   (double)
  memcpy(&x1, buf + 8,  sizeof x1);  // log    (double)
  memcpy(&x2, buf + 16, sizeof x2);  // log2f  (float)
  memcpy(&x3, buf + 20, sizeof x3);  // log10  (double)
  memcpy(&x4, buf + 28, sizeof x4);  // log1p  (double)
  memcpy(&x5, buf + 36, sizeof x5);  // powf   (float, exponent const)
  memcpy(&x6, buf + 40, sizeof x6);  // expf   (float)
  memcpy(&x7, buf + 44, sizeof x7);  // pow    (double, base const)

  // Seed is all zeros, so every guard fails.  i2s inverts the one transcendental
  // in each guard to recover the required input.  Constants are chosen so the
  // exact-inverse cases round-trip precisely (powers), and the inequality cases
  // (log1p/expf) leave margin for FP rounding.
  if (exp2(x0) == 8.0) {              // x0 = log2(8)  = 3.0
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }
  if (log(x1) == 0.0) {              // x1 = exp(0)   = 1.0
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }
  if (log2f(x2) == 3.0f) {          // x2 = exp2(3)  = 8.0
    // CHECK-GEN3: Good3
    printf("Good3\n");
  }
  if (log10(x3) == 2.0) {           // x3 = pow(10,2) = 100.0
    // CHECK-GEN4: Good4
    printf("Good4\n");
  }
  if (log1p(x4) > 1.0) {            // x4 > expm1(1) ~= 1.718
    // CHECK-GEN5: Good5
    printf("Good5\n");
  }
  if (powf(x5, 3.0f) == 27.0f) {    // x5 = 27^(1/3) = 3.0  (exponent-const)
    // CHECK-GEN6: Good6
    printf("Good6\n");
  }
  if (expf(x6) > 5.0f) {            // x6 > log(5) ~= 1.609
    // CHECK-GEN7: Good7
    printf("Good7\n");
  }
  if (pow(3.0, x7) == 81.0) {       // x7 = log(81)/log(3) = 4.0  (base-const)
    // CHECK-GEN8: Good8
    printf("Good8\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
