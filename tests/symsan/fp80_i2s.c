// x86_fp80 (`long double`) comparisons, solved by input-to-state.
//
// The counterpart to fp80_decline.c, which pins the *other* half of the same
// decision: z3 and jigsaw cannot model this format and must refuse it, while
// i2s can and does.  The asymmetry is not an accident of effort, it is what the
// format allows each solver to say:
//
//   z3's (_ FloatingPoint 15 64) has an IMPLICIT integer significand bit and is
//   79 bits wide; x86_fp80 has an EXPLICIT one and is 80.  mk_from_ieee_bv
//   between them is a reinterpretation, not a conversion, and x87 additionally
//   produces unnormals, pseudo-denormals and pseudo-NaNs that the z3 sort has no
//   counterpart for.  jigsaw carries every FP value as a bit pattern in a uint64
//   argument slot, which 80 bits does not fit.
//
//   i2s evaluates in C++ on x86, where `long double` IS x86_fp80.  Decoding is a
//   memcpy, and every compare, step and re-encode runs on the same hardware that
//   produced the value -- so there is no model to be wrong about.  That is why
//   solve_fcmp80 is guarded on __LDBL_MANT_DIG__ == 64 (the actual requirement)
//   rather than on an architecture macro.
//
// The two shapes below are the two that fuzzer-challenges' test-longdouble
// uses, and they exercise different machinery: the range needs a directional
// nextafterl step off a constant, the equality needs the constant written back
// verbatim.  Both go through the WideConst multi-slot constant transport, since
// an 80-bit literal does not fit one op1/op2 field either.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: head -c 32 /dev/zero > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
//
// Verify by replay, and check each shape separately: a solution file existing
// proves only that some branch was flipped, not that the right value landed in
// the right ten bytes.  Two passes rather than one so the check does not depend
// on the order the solutions come out in.
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-RANGE %s
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-EQ %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  // sizeof(long double) is 16 on x86-64 but only ten of those bytes are value;
  // the solver must write exactly those ten and leave the six padding bytes
  // alone, which is why the buffer is read as an array rather than a scalar.
  long double vals[2];
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(vals, 1, sizeof(vals), fp);
  fclose(fp);

  // Shape 1: two-sided range, phrased as the challenge phrases it (bail on the
  // complement) so the branch polarity matches.  Solving it needs a value
  // strictly inside the interval, i.e. one nextafterl step off whichever
  // endpoint the constraint names.
  long double lesser = 101.9, greater = 109.0;
  if (!(vals[0] < lesser || vals[0] > greater)) {
    if (isnormal(vals[0])) {
      // CHECK-RANGE: InRange
      printf("InRange\n");
    }
  }

  // Shape 2: exact equality against a double literal promoted to long double.
  // The wanted bytes are exact and known at compile time, so this is the pure
  // write-the-constant-back case -- and it is the one that catches a lo/hi swap
  // in the WideConst transport, since the significand and the sign+exponent
  // travel in separate argument slots.
  if (vals[1] == 3.141592653589793116) {
    // CHECK-EQ: ExactPi
    printf("ExactPi\n");
  }

  // unconditional, so the seed run has something to match
  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}
