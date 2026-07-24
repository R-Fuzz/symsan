// Regression test: standalone i2s (I2SSolver) must write the inverted integer
// value to the offset the operand ACTUALLY reads, not to an unrelated input that
// merely holds a coincidentally-equal value.
//
// This is the integer analogue of tests/fp_i2s_offset.c.  Each guard pairs a
// single-arith-op operand (`X op C`) with a plain-Read operand.  On the all-zero
// seed every symbolic byte is 0, so the arith operand's raw input bytes (0) equal
// the OTHER (plain-Read) operand's value (0).  solve_icmp's direct-match branch
// compares candidates by value only, so it matched the arith operand's candidate
// against the plain-Read operand and wrote that operand's inverted value to the
// arith input -- the WRONG offset, leaving the guard UNsatisfied.  solve_icmp now
// anchors each direct match to the compared side's Read offset, so the coincidental
// candidate is rejected and the arith side is solved through the binop branch.
//
// The two operands of each guard are NON-adjacent (a gap of unused bytes sits
// between them) so each is its own 8-byte i2s candidate -- adjacent operands merge
// into one >8-byte run that solve_icmp skips, hiding the bug.  The arith operand
// sits at the LOWER offset so its candidate is visited first (the premature match).
//
// Guard A exercises the coincidental match against op2 (right side is the plain
// Read); guard B against op1 (left side is the plain Read).
//
// Solved by standalone i2s alone, so only %afltest RUN lines (no
// SYMSAN_USE_JIGSAW / SYMSAN_USE_Z3, no in-process z3 %fgtest lines).
//
// The checks are independent (not nested behind an early bail), so one concolic
// run emits one input per check (see tests/switch.c).
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*64)' > %t.bin
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
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  unsigned char buf[64] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  int64_t bb, aa, cc, dd;
  memcpy(&bb, buf + 0,  sizeof bb);  // guard A arith input (lower offset)
  memcpy(&aa, buf + 16, sizeof aa);  // guard A plain-Read operand (gap 8..15)
  memcpy(&cc, buf + 32, sizeof cc);  // guard B arith input (lower offset, gap 24..31)
  memcpy(&dd, buf + 48, sizeof dd);  // guard B plain-Read operand (gap 40..47)

  // Guard A: the arith side (bb + 1) is on the LEFT (op1); the plain Read (aa) is
  // on the RIGHT (op2).  On the zero seed bb's bytes (0) equal aa's value (0), so
  // the old value-only check matched bb's candidate against op2 and wrote to bb.
  if (bb + 1 == aa) {          // solved by bb = -1 (so bb + 1 == 0 == aa)
    // CHECK-GEN1: GoodA
    printf("GoodA\n");
  }
  // Guard B: the plain Read (dd) is on the LEFT (op1); the arith side (cc + 1) is
  // on the RIGHT (op2).  cc's bytes (0) equal dd's value (0), matching op1.
  if (dd == cc + 1) {          // solved by cc = -1 (so cc + 1 == 0 == dd)
    // CHECK-GEN2: GoodB
    printf("GoodB\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
