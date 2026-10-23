// llvm.cttz, llvm.ctlz and llvm.ctpop have to propagate taint.
//
// TaintPass dropped their shadows, so the count went concrete.  In the kernel
// these are everywhere UCSan runs: __ffs, fls, ilog2 and hweight are inline
// asm (bsf, bsr, popcnt) that UCSanPass lifts to these intrinsics, and KVM's
// fastop() indexes its stubs by __ffs(dst.bytes).  No decomposition into
// labeled operations exists (a binary search or a sum of bits ends in selects
// between constants, which carry no label), so each is a dfsan op of its own,
// like bitreverse: z3 (both stacks) expands it to an ite chain or a sum of
// bits, jigsaw JITs the native intrinsic.  i2s evaluates them but does not
// invert them -- many operands give each count -- so it is not run here.
//
// Each count against a constant the seed's count is not: only the operand can
// move, and only through the count.
//
// RUN: python -c'import sys, struct; sys.stdout.buffer.write(struct.pack("<QIIQ", 1, 0x41414141, 0, 0xff))' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-ALL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-ALL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_Z3=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-ALL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_JIGSAW=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-ALL %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint64_t d, e;
  uint32_t c, c2;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&d, 1, sizeof(d), fp);
  chk_fread(&c, 1, sizeof(c), fp);
  chk_fread(&c2, 1, sizeof(c2), fp);
  chk_fread(&e, 1, sizeof(e), fp);
  fclose(fp);

  if (d && __builtin_ctzll(d) == 37) {
    // CHECK-ALL-DAG: GoodCtz64
    printf("GoodCtz64\n");
  }
  if (c && __builtin_clz(c) == 5) {
    // CHECK-ALL-DAG: GoodClz32
    printf("GoodClz32\n");
  }
  if (e && __builtin_clzll(e) == 3) {
    // CHECK-ALL-DAG: GoodClz64
    printf("GoodClz64\n");
  }
  if (__builtin_popcount(c2) == 20) {
    // CHECK-ALL-DAG: GoodPop32
    printf("GoodPop32\n");
  }
  if (__builtin_popcountll(e) == 33) {
    // CHECK-ALL-DAG: GoodPop64
    printf("GoodPop64\n");
  }

  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}
