// A boolean `^` between two predicates has to be solvable on the RGD path,
// the one a fuzzer actually runs.
//
// tests/symsan/xor_bool.c covers the same source shape through %fgtest, which
// is solvers/z3-ts.cpp -- a different parser that builds the xor directly.
// parsers/rgd-parser.cpp cannot: rgd::Xor is not a relational kind, so the
// clause root was refused with "non-comparison root" and the branch was never
// attempted.  to_nnf() now expands it:
//
//     a ^ b   ==  (a && !b) || (!a && b)
//   !(a ^ b)  ==  (a &&  b) || (!a && !b)
//
// Guard A takes the first form (the seed makes the xor false, so the target
// direction is true), guard B the second.  They read disjoint bytes on
// purpose: sharing them would let A's answer flip B by accident, and the test
// would still pass with the whole rewrite removed.
//
// Do NOT add KO_DONT_OPTIMIZE here.  At -O0 clang zero-extends both
// comparisons and xors them as i32, and find_roots' Xor arm requires a 1-bit
// node ("bool node width") -- so unoptimized, neither guard reaches the
// rewrite at all.  Optimized, both are `xor i1`, which is also what the
// runtime's own ub_integer_sign_change check builds.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"AAAABBBBCCCCDDDD")' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint32_t a = 0, b = 0, c = 0, d = 0;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&a, 1, sizeof(a), fp);
  chk_fread(&b, 1, sizeof(b), fp);
  chk_fread(&c, 1, sizeof(c), fp);
  chk_fread(&d, 1, sizeof(d), fp);
  fclose(fp);

  // Guard A: the seed satisfies neither side, so the xor is false and the
  // solver is asked for true -- exactly one of the two has to hold.
  if ((a == 0xdeadbeef) ^ (b == 0x0badf00d)) {
    // CHECK-GEN-DAG: GoodA
    printf("GoodA\n");
  } else {
    // CHECK-ORIG: BadA
    printf("BadA\n");
  }

  // Guard B: the seed satisfies the left side only ("CCCC"), so the xor is
  // true and the solver is asked for false -- either both hold or neither.
  if ((c == 0x43434343) ^ (d == 0x0badf00d)) {
    // CHECK-ORIG: BadB
    printf("BadB\n");
  } else {
    // CHECK-GEN-DAG: GoodB
    printf("GoodB\n");
  }
  return 0;
}
