// Regression test: standalone i2s (I2SSolver) must write the inverted FP value
// to the offset the arith operand ACTUALLY reads, not to an unrelated input that
// merely holds a coincidentally-equal value.
//
// Each guard is `X == Y op C` where Y (not X) is the symbolic operand of a single
// FP arith op against a constant C.  On the all-zero seed X == Y == 0, so feeding
// X through `op C` yields the same value as `Y op C` -- the old value-only
// structural check matched the X candidate (which sorts first) and wrote the
// inverted result to X, corrupting an unrelated input and leaving the guard
// UNsatisfied.  solve_fcmp now anchors each candidate to the arith operand's
// Read offset, so it writes to Y instead and the guard flips.
//
// The two operands are NON-adjacent (a gap of unused bytes sits between them) so
// each is its own 4/8-byte i2s candidate -- the case where the wrong-offset write
// was observable.  Solved by standalone i2s alone, so only %afltest RUN lines
// (no SYMSAN_USE_JIGSAW / SYMSAN_USE_Z3, no in-process z3 %fgtest lines).
//
// The checks are independent (not nested behind an early bail), so one concolic
// run emits one input per check (see tests/symsan/switch.c).
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*48)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s

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

  unsigned char buf[48] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  double a, b;
  float  fa, fb;
  memcpy(&a,  buf + 0,  sizeof a);   // direct operand of guard 1
  memcpy(&b,  buf + 16, sizeof b);   // arith operand of guard 1 (gap 8..15)
  memcpy(&fa, buf + 32, sizeof fa);  // direct operand of guard 2
  memcpy(&fb, buf + 44, sizeof fb);  // arith operand of guard 2 (gap 36..43)

  // The arith operand (b / fb) is on the RIGHT; the plain input (a / fa) is on
  // the LEFT and sorts first among candidates.  The fix must write to b / fb.
  if (a == b + 1.0) {          // b = -1.0  (so a == 0 == b + 1.0)
    // CHECK-GEN1: GoodDbl
    printf("GoodDbl\n");
  }
  if (fa == fb + 1.0f) {       // fb = -1.0f (so fa == 0 == fb + 1.0f)
    // CHECK-GEN2: GoodFloat
    printf("GoodFloat\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
