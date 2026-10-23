// llvm.fshl/fshr, the saturating and the with.overflow intrinsics have to
// propagate taint.
//
// TaintPass modeled none of them, so their results lost their labels and
// went concrete: the kernel's rol32() in jhash and siphash (fshl),
// check_add_overflow / check_mul_overflow on sizes (u*.with.overflow), and
// saturating arithmetic.  They are now lowered to the operations they stand
// for before instrumentation (see minmax_intrinsics.c for min/max/abs).
// clang emits each of them from its builtin at -O0.
//
// Each guard compares with a constant, or branches on the overflow bit: with
// the result concrete no solution reaches it.  The seed reaches none.
//
// RUN: python -c'import sys, struct; sys.stdout.buffer.write(struct.pack("<IIIIQQIIii", 1, 5, 1, 2, 3, 4, 20, 5, 0, 0))' > %t.bin
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

  uint32_t a, r, x, y, p, q, s32;
  uint64_t m, n, s64;
  int32_t sa, sb, ss;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&a, 1, sizeof(a), fp);
  chk_fread(&r, 1, sizeof(r), fp);
  chk_fread(&x, 1, sizeof(x), fp);
  chk_fread(&y, 1, sizeof(y), fp);
  chk_fread(&m, 1, sizeof(m), fp);
  chk_fread(&n, 1, sizeof(n), fp);
  chk_fread(&p, 1, sizeof(p), fp);
  chk_fread(&q, 1, sizeof(q), fp);
  chk_fread(&sa, 1, sizeof(sa), fp);
  chk_fread(&sb, 1, sizeof(sb), fp);
  fclose(fp);

  if (__builtin_rotateleft32(a, r) == 0x12345678u) {
    // CHECK-ALL-DAG: GoodRotl
    printf("GoodRotl\n");
  }
  if (__builtin_rotateright32(a, r) == 0x80000001u) {
    // CHECK-ALL-DAG: GoodRotr
    printf("GoodRotr\n");
  }
  if (__builtin_add_overflow(x, y, &s32)) {
    // CHECK-ALL-DAG: GoodUaddOvf
    printf("GoodUaddOvf\n");
  } else if (s32 == 1000u) {
    // CHECK-ALL-DAG: GoodUaddSum
    printf("GoodUaddSum\n");
  }
  if (__builtin_mul_overflow(m, n, &s64)) {
    // CHECK-ALL-DAG: GoodUmulOvf
    printf("GoodUmulOvf\n");
  }
  if (__builtin_sub_overflow(sa, sb, &ss)) {
    // CHECK-ALL-DAG: GoodSsubOvf
    printf("GoodSsubOvf\n");
  }
  if (__builtin_elementwise_sub_sat(p, q) == 0u) {
    // CHECK-ALL-DAG: GoodUsubSat
    printf("GoodUsubSat\n");
  }
  if (__builtin_elementwise_add_sat(sa, sb) == 0x7fffffff) {
    // CHECK-ALL-DAG: GoodSaddSat
    printf("GoodSaddSat\n");
  }

  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}
