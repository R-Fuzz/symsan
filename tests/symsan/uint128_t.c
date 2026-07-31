// A 128-bit comparison is past what the shadow can carry: dfsan_label_info's
// operand fields are 64-bit, and the whole RGD stack below them is 64-bit too.
// The instrumentation used to sail through anyway, because the size filter in
// combineShadows looks at the *result* type and an icmp's result is i1; the
// operands were then truncated to 64 bits while the label still claimed
// size = 128.  That is not an approximation, it is a different formula, and
// the solver would "solve" it and emit an input that does not take the branch.
//
// So the contract here is that we produce no task at all for `a == b`, and
// leave the 128-bit compare to cmplog/RedQueen.  Both solver paths are checked
// because both consume the same labels.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*16 + "B"*16)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
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
    printf("Good\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }
}

// CHECK-NOSOL-NOT: id-
