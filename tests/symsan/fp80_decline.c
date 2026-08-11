// x86_fp80 must be declined by z3 and by jigsaw, and declined EXPLICITLY.
//
// This is the most important kind of negative test: it pins a deferral as a
// decline rather than letting it be an accident of some other check.  The check
// it used to be an accident of has now moved twice, which is the whole argument
// for the test existing:
//
//   1. Until wide operands landed, `long double` fell out of the 64-bit ceiling
//      in combineShadows along with everything else.  Raising that ceiling to
//      128 would have let an 80-bit float through if the FP type check did not
//      come first.
//   2. Then fp80 comparisons were deliberately admitted so i2s could solve them
//      (see fp80_i2s.c), and the ceiling stopped protecting z3 and jigsaw at
//      all.  jigsaw's fp_type() was `bits == 32 ? float : double`, so it
//      answered "double" for 80 and emitted `bitcast i80 -> double`: invalid IR
//      that the caller then JITed anyway, because verifyFunction's verdict was
//      being discarded.  Both are fixed; this test is what keeps them fixed.
//
// The decline is now by FORMAT, stated once per solver, and each of these arms
// hits a different statement of it:
//
//   z3   -- fpa_sort_for() throws for any width but 16/32/64.  (_ FloatingPoint
//           15 64) has an IMPLICIT integer significand bit and is 79 bits wide;
//           x86_fp80 has an EXPLICIT one and is 80.  mk_from_ieee_bv between
//           them would be a bit-reinterpretation that is simply wrong, and x87
//           also produces unnormals, pseudo-denormals and pseudo-NaNs that have
//           no counterpart in the z3 sort at all.  Both z3 stacks carry their
//           own copy of fpa_sort_for, so both arms are worth running.
//   jigsaw -- fp_type() throws for any width but 32/64.  Every FP value here is
//           a bit pattern in a uint64 argument slot; 80 bits does not fit one.
//
// So a "solution" from these arms would be a wrong answer, not an approximate
// one.  What makes that worth a test is that the wrongness is invisible: the
// solver reports SAT, the fuzzer writes a file, and only a replay would show
// the branch was never flipped.
//
// The i2s arm is deliberately absent -- it solves this, and fp80_i2s.c covers
// it.  Keeping the two in one file would mean a single check that could pass
// for the wrong reason if a solver were misrouted.
//
// RUN: python -c'print("A"*16)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_Z3=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_JIGSAW=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  long double x;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&x, 1, sizeof(x), fp);
  fclose(fp);

  if (x == 1.5L) {
    printf("BadFP80\n");
  }

  // unconditional, so the seed run has something to match
  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}

// CHECK-NOSOL-NOT: id-
