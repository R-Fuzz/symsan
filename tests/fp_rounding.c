// Directed floating-point rounding captured in the real-symex instrumentation
// path AND honored by the solvers' arithmetic model.
//
// Built with -frounding-math and FENV_ACCESS ON, so clang lowers the FP square
// and comparison to @llvm.experimental.constrained.* intrinsics; the
// fesetround(FE_DOWNWARD) makes the multiply's rounding mode `round.dynamic`
// (resolved at run time from MXCSR).  TaintPass captures these intrinsics
// (before the blanket llvm.experimental filter) and packs the rounding-mode
// selector into the high byte of the union op; the solvers read it back
// (parsers/rgd-parser.cpp for the RGD/jigsaw chain, solvers/z3-ts.cpp for the
// in-process z3 path) and model round-toward-negative multiplication.
//
// The guard is `x*x == 0x40488000000000ab` (== RTN(x*x) for the solution, one
// ULP below the round-to-nearest square).  This is chosen to actually TEST the
// rounding model, not just capture:
//   * two symbolic operands (x*x) => i2s cannot invert it (i2s would otherwise
//     solve any branch via a concrete candidate + re-execution, which is
//     rounding-correct regardless of the model and would mask a regression);
//   * an exact FP equality => jigsaw gradient descent cannot land it either;
//   * so z3 must solve it, and `x*x == target` is SAT under round-toward-
//     negative but UNSAT under round-to-nearest (verified with z3).
// A solver that fails to honor the captured rounding mode therefore finds the
// formula UNSAT, produces no input, and the CHECK-GEN re-execution below fails.
// The generated input is validated against the -frounding-math oracle (which
// rounds downward for real): it must print HIT.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*8)' > %t.bin
// RUN: clang -O1 -frounding-math -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
//
// in-process z3 solver via fgtest (TaintPass capture -> z3-ts.cpp):
// RUN: env KO_USE_FASTGEN=1 %ko-clang -frounding-math -o %t.fg %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
//
// out-of-process RGD chain via afltest (TaintPass capture -> rgd-parser.cpp;
// i2s and jigsaw GD both reject exact x*x equality, so z3 in the chain solves):
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" SYMSAN_USE_JIGSAW=1 SYMSAN_USE_Z3=1 %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
//
// in-process z3 solver in the instrumented runtime (KO_USE_Z3):
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -frounding-math -o %t.z3 %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <fenv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"
#pragma STDC FENV_ACCESS ON

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

  // Directed-rounded square of a symbolic operand.  FE_DOWNWARD => the
  // constrained.fmul carries round.dynamic and rounds toward -inf at run time.
  // x*x (two symbolic refs) is invertible by neither i2s nor gradient descent,
  // so the rounding-aware z3 model must solve the equality below.
  fesetround(FE_DOWNWARD);
  double y = x * x;
  fesetround(FE_TONEAREST);

  // target == RTN(x*x) for the solution, 1 ULP below the RNE square.  x*x==target
  // is SAT under round-toward-negative but UNSAT under round-to-nearest.
  uint64_t tb = 0x40488000000000abULL;
  double target;
  memcpy(&target, &tb, sizeof target);

  if (y == target) {
    // CHECK-GEN: HIT
    printf("HIT\n");
    return 0;
  }
  // CHECK-ORIG: MISS
  printf("MISS\n");
  return 0;
}
