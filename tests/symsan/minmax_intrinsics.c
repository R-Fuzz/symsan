// llvm.umin/umax/smin/smax and llvm.abs have to propagate taint.
//
// TaintPass modeled none of them, so the result of a min()/max()/abs() lost
// its label and everything downstream of it went concrete: the kernel's
// min_t(size_t, len, PAGE_SIZE) before a copy, after instcombine.  They are
// now lowered to the icmp + select they stand for before instrumentation, so
// the result carries the label of the operand it picked and the comparison is
// traced like any select's.  __builtin_elementwise_* emits the intrinsics at
// -O0.
//
// Both operands are tainted: against a constant, instcombine folds
// umin(a, 1000) == 777 into a == 777 and the test checks nothing.  The seed
// makes the first operand the one picked.
//
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x05\x00\x00\x00" + b"\x00\x01\x00\x00" + b"\x03\x00\x00\x00" + b"\xfb\xff\xff\xff" + b"\xfd\xff\xff\xff" + b"\x07\x00\x00\x00" + b"\x02\x00\x00\x00")' > %t.bin
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint32_t a, a2, d, d2;
  int32_t b, b2, c;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&a, 1, sizeof(a), fp);
  chk_fread(&a2, 1, sizeof(a2), fp);
  chk_fread(&b, 1, sizeof(b), fp);
  chk_fread(&b2, 1, sizeof(b2), fp);
  chk_fread(&c, 1, sizeof(c), fp);
  chk_fread(&d, 1, sizeof(d), fp);
  chk_fread(&d2, 1, sizeof(d2), fp);
  fclose(fp);

  if (__builtin_elementwise_min(a, a2) == 777u) {
    // CHECK-ALL-DAG: GoodUmin
    printf("GoodUmin\n");
  }
  if (__builtin_elementwise_max(b, b2) == 100) {
    // CHECK-ALL-DAG: GoodSmax
    printf("GoodSmax\n");
  }
  if (__builtin_elementwise_abs(c) == 50) {
    // CHECK-ALL-DAG: GoodAbs
    printf("GoodAbs\n");
  }
  if (__builtin_elementwise_max(d, d2) == 9u) {
    // CHECK-ALL-DAG: GoodUmax
    printf("GoodUmax\n");
  }

  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}
