// Floating-point input-to-state (RedQueen) heuristic in the JIGSAW solver.
//
// Jigsaw has a built-in in-solver i2s fast path (`try_i2s` in solvers/jigsaw/
// gd.cc) that snaps a raw input chunk onto a comparison operand before running
// gradient descent.  It now handles FP comparisons: it slides an FP-sized window
// across each consecutive-input-byte candidate, matches the window's float/double
// value against a stored operand, and snaps it to satisfy the predicate against
// the other operand (verifying every guess with fp_get_distance == 0).
//
// Each guard below is an exact FP EQUALITY with TWO symbolic operands, and the
// two operands are ADJACENT in the file, so they merge into ONE oversized (16
// byte) i2s candidate run.  That is exactly the case the sliding FP window was
// added to handle -- and it also isolates jigsaw, because:
//   - standalone i2s (I2SSolver, first in the chain) only decodes candidate runs
//     that are exactly 4 or 8 bytes, so it skips the merged 16-byte run entirely;
//     and
//   - gradient descent cannot reliably land on an exact FP equality.
// So only jigsaw's i2s heuristic can flip these.  (The float path -- 4-byte
// window, is_float -- is identical code and is exercised by the out-of-tree
// probe; a committed float guard is omitted because a standalone-i2s quirk grabs
// float arith comparisons first.)
//
// RUN lines use %afltest with SYMSAN_USE_JIGSAW=1 and WITHOUT SYMSAN_USE_Z3, to
// isolate jigsaw (enabling z3 would let it mask a jigsaw regression).  No %fgtest
// / KO_USE_Z3 lines: those exercise the in-process z3 path, which has no
// jigsaw/i2s chain.
//
// The checks are independent (not nested behind an early bail), so one concolic
// run emits one input per check (see tests/switch.c).
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*48)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s -lm
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" SYMSAN_USE_JIGSAW=1 %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s

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

  double a, b, c, d, e, f;
  memcpy(&a, buf + 0,  sizeof a);   // adjacent to b  -> merged 16B run
  memcpy(&b, buf + 8,  sizeof b);
  memcpy(&c, buf + 16, sizeof c);   // adjacent to d  -> merged 16B run
  memcpy(&d, buf + 24, sizeof d);
  memcpy(&e, buf + 32, sizeof e);   // adjacent to f  -> merged 16B run
  memcpy(&f, buf + 40, sizeof f);

  // Seed is all zeros, so every equality is initially false.  Two symbolic
  // operands each, so jigsaw's i2s heuristic must recover the solution.  The
  // three guards also cover both operand-match directions: the input chunk can
  // match the LEFT stored operand (op1) or the RIGHT one (op2).
  if (a == b + 1.0) {          // a = b + 1.0 = 1.0   (input matches op2 side)
    // CHECK-GEN1: GoodAdd
    printf("GoodAdd\n");
  }
  if (c == d - 5.0) {          // c = d - 5.0 = -5.0  (input matches op2 side)
    // CHECK-GEN2: GoodSub
    printf("GoodSub\n");
  }
  if (f == e + 2.0) {          // f = e + 2.0 = 2.0   (input matches op1 side)
    // CHECK-GEN3: GoodRev
    printf("GoodRev\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
