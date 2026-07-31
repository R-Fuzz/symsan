// A genuine 128-bit comparison, both sides read from input.
//
// This test used to assert the opposite of what it asserts now, and the reason
// is worth keeping.  A 128-bit comparison was past what the shadow could carry:
// dfsan_label_info's operand fields are 64-bit, and the whole RGD stack below
// them is 64-bit too.  The instrumentation used to sail through anyway, because
// the size filter in combineShadows looks at the *result* type and an icmp's
// result is i1; the operands were then truncated to 64 bits while the label
// still claimed size = 128.  That is not an approximation, it is a different
// formula, and the solver would "solve" it and emit an input that does not take
// the branch.  So the contract was to produce no task at all for `a == b`, and
// leave the 128-bit compare to cmplog/RedQueen.
//
// What changed is not the label format -- op1 and op2 are still 64 bits each --
// but what a *zero* label is allowed to mean.  The two fields together are
// exactly 128, so a concrete wide operand now arrives as its own leaf label
// (__dfsan::WideConst, l1 = l2 = 0, op1 = lo64, op2 = hi64) that the
// instrumentation materializes, and __taint_union declines any wide op still
// holding a bare zero label where a value belongs.  Nothing is truncated, so
// the formula is the program's.
//
// Here both operands are symbolic, so no WideConst is involved; this is the
// plain case.  The arms legitimately disagree, and that split is the point:
//
//   The three z3 stacks solve it.  What is checked is the REPLAY, not the
//   existence of an output file -- a wrong 128-bit model still produces a file,
//   and only running the uninstrumented binary on it proves the branch flipped.
//
//   jigsaw must DECLINE.  Its comparison lowering ZExtOrTrunc's both operands
//   to i64 so get_distance can work in 64 bits, and a distance of 0 over the
//   low half alone is a false SAT -- it would hand back a model that does not
//   satisfy the constraint.  jit.cc throws invalid_argument for a comparison
//   operand wider than 64 bits and codegen's caller turns that into a clean -1.
//   An output file appearing on that arm is the failure this pins.
//
//   i2s declines too, but for a soft reason rather than a hazard: its value
//   match reads the traced c->op1/c->op2, which are uint64.  The width-agnostic
//   route already exists -- solve_memcmp_ast assembles the wanted bytes from
//   consecutive input_args slots and matches through i2s_walk_wide, needing no
//   traced value at all -- and this shape is the natural candidate for it.  If
//   that lands, this arm is the line to update.
//
// RUN: python -c'print("A"*16 + "B"*16)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_Z3=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s
//
// jigsaw alone: must decline rather than answer
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_JIGSAW=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s
//
// i2s alone: declines, see above
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s

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

  FILE* fp = chk_fopen(argv[1], "rb");
  __uint128_t a, b;
  chk_fread(&a, 1, sizeof(a), fp);
  chk_fread(&b, 1, sizeof(b), fp);
  fclose(fp);

  if (a == b) {
    // CHECK-SOL: Good
    printf("Good\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }
}

// CHECK-NOSOL-NOT: id-
