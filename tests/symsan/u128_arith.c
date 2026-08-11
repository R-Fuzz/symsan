// 128-bit arithmetic underneath a 64-bit comparison: the widening multiply.
//
// `(unsigned __int128)a * b >> 64` is the high half of a 64x64 product, and it
// is the core of every modern 64-bit hash (wyhash, xxh3, komihash) and of
// __builtin_mul_overflow on uint64_t.  Before wide operands were representable,
// combineShadows returned a zero shadow for the i128 mul and everything
// downstream of it went concrete -- no crash, no warning, just a branch the
// session never sees.
//
// Two things are pinned here that the pure-comparison test (uint128_t.c) cannot
// reach:
//
//   The shift amount is a CONSTANT of the wide type.  `lshr i128 %mul, 64` has
//   one symbolic and one concrete operand, and the concrete 64 does not fit in
//   a zero label any more than a huge constant would -- what a zero label
//   cannot express is not "large" but "exact".  So it is materialized as a
//   __dfsan::WideConst leaf (op1 = 64, op2 = 0) just like any other wide
//   constant.  This is the small-constant case, which is easy to overlook.
//
//   jigsaw participates.  A wide SUB-EXPRESSION under a <=64-bit comparison is
//   fine and goes all the way through its JIT; only the comparison itself is
//   limited to 64 bits (see uint128_t.c).  And the check has teeth: the free
//   variable is `c`, so jigsaw's move is to write its own computed value of
//   `hi` into it, which only replays as GoodHi if its i128 mul and lshr agree
//   with the program's bit for bit.
//
// The comparison is against a SECOND tainted value ON PURPOSE.  Written as
// `hi == 0x42` instead, instcombine folds the shift into the compare and
// produces `icmp eq i128 %mul, 0x42 << 64` -- a 128-bit comparison, which
// jigsaw then correctly declines.  The test would still pass on the z3 arms and
// would silently stop covering the jigsaw path it was written for.
//
// i2s declines.  Its value match would have the exact 64-bit traced value of
// `hi`, but the rewrite goes through i2s_eval_int, which is uint64 and returns
// false as soon as it recurses into the 128-bit product.  That is a real
// limit, not a regression -- this whole shape produced no labels at all before.
// Making it work means carrying unsigned __int128 through i2s_eval_int.
//
// RUN: python -c'print("A"*24)' > %t.bin
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
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_JIGSAW=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s
//
// i2s alone: declines, see above
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
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

  uint64_t a, b, c;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&a, 1, sizeof(a), fp);
  chk_fread(&b, 1, sizeof(b), fp);
  chk_fread(&c, 1, sizeof(c), fp);
  fclose(fp);

  unsigned __int128 p = (unsigned __int128)a * (unsigned __int128)b;
  uint64_t hi = (uint64_t)(p >> 64);

  if (hi == c) {
    // CHECK-SOL: GoodHi
    printf("GoodHi\n");
  }

  // unconditional, so the seed run has something to match and no extra
  // symbolic branch is introduced
  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}

// CHECK-NOSOL-NOT: id-
