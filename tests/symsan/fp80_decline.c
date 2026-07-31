// x86_fp80 must be declined, and declined EXPLICITLY.
//
// This is the most important kind of negative test: it pins a deferral as a
// decline rather than letting it be an accident of some other check.  Until
// wide operands landed, `long double` fell out of the 64-bit ceiling in
// combineShadows along with everything else; raising that ceiling to 128 would
// have let an 80-bit float through if the FP type check did not come first.
// TaintPass rejects anything that is not half/float/double before it ever looks
// at the size, so the ceiling and the FP decline are independent.  This test is
// what keeps them independent.
//
// Modeling fp80 is a different task from widening an integer, not a bigger one:
//
//   x86_fp80 is 80 bits with an EXPLICIT integer significand bit.  z3's
//   (_ FloatingPoint 15 64) has an implicit one and is 79 bits wide, so
//   mk_from_ieee_bv would be a bit-reinterpretation that is simply wrong.  x87
//   can also produce unnormals, pseudo-denormals and pseudo-NaNs, which have no
//   counterpart in the z3 sort at all.
//
//   jigsaw carries every FP value as a double bit pattern in a uint64 arg slot
//   -- fp_type() is literally `bits == 32 ? float : double` -- and fp_decode
//   knows only 32 and 64.  80 bits does not round-trip.
//
// So a "solution" here would be a wrong answer, not an approximate one.  All
// five arms must produce nothing.
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
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
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
