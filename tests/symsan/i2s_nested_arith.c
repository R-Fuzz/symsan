// Nested multi-operand integer arithmetic, with no lookup table involved.
//
//   ((x - 3) * 2) + (y << 4) == 0x142
//
// The flat integer input-to-state path cannot touch this, for three separate
// reasons: it requires exactly one binop kind in the whole constraint (here
// there are four -- Sub, Mul, Shl, Add), it only inspects the comparison's
// direct children rather than recursing into nesting, and it needs one of those
// children to be a Constant, which the top-level Add's are not.
//
// The AST-guided fallback handles all three: it walks down the nested spine,
// and where both operands of an operation are symbolic it pins one at the value
// it holds under the current input and inverts the other.  Pinning is a guess,
// so the candidate is re-evaluated against the whole comparison before SAT is
// claimed -- the same discipline the FP path uses.
//
// This is deliberately table-free so a regression in the arithmetic
// generalization is not misread as a tlookup bug.  The harder case, where
// pinning at the current value is not enough and one operand's value set has to
// be enumerated, is covered by table_lookup_arith.c.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*2)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t buff[2] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buff, 1, sizeof(buff), fp);
  fclose(fp);

  int v = ((buff[0] - 3) * 2) + (buff[1] << 4);

  if (v == 0x142) {
    // CHECK-GEN: Good
    printf("Good\n");
    return 0;
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
