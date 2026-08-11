// Above the ceiling: _BitInt(256) must decline cleanly, not truncate.
//
// The ceiling is kMaxOperandBits in TaintPass, and 128 is not an arbitrary
// round number -- it is exactly what op1 and op2 hold together.  Anything wider
// genuinely does need a side channel or a Concat chain, and nothing observed
// needs one, so the decline is the design and not a gap.
//
// The failure this guards against is a future ceiling change made by editing
// one constant.  Raising kMaxOperandBits without giving the runtime a way to
// carry the extra bits would put us back exactly where the 128-bit case started
// (see uint128_t.c): the operands silently truncated while the label still
// claims the real width, which is a different formula rather than an
// approximation, and produces confident wrong answers instead of misses.  If
// that constant moves, this test fails, which is the point.
//
// clang-18 supports _BitInt up to 128 by default and wider under the
// BitInt extension; 256 is chosen because it is the next power of two and
// because a 32-byte load exercises __taint_union_load's contiguous path at a
// width nothing downstream can hold.
//
// RUN: python -c'print("A"*32)' > %t.bin
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

  unsigned _BitInt(256) a;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&a, 1, sizeof(a), fp);
  fclose(fp);

  if (a == (unsigned _BitInt(256))0x42) {
    printf("BadWide\n");
  }

  // unconditional, so the seed run has something to match
  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}

// CHECK-NOSOL-NOT: id-
