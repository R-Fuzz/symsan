// Two calls to the same function, in the same trace, stay independently
// solvable.
//
// The compare lives at one address inside foo(), and the else-if chain reaches
// it twice per run with different arguments -- first foo(y, 570), then
// foo(x, 340).  Anything that keys "have I solved this already?" on the branch
// address alone answers the first call and drops the second, so Good2 never
// gets an input.  The calling context is what has to keep them apart.
//
// This is the same-trace case; context.c is the other one, where the two call
// sites sit on mutually exclusive paths and only one runs per execution.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int __attribute__ ((noinline)) foo(uint64_t x, uint64_t y) {
  //int z = x - y + 10;
  if (x + y == 3122) return 1;
  return 0;
}

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[20];
  size_t ret;

  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  uint32_t x = 0;
  uint32_t y = 0;

  memcpy(&x, buf, 4);
  memcpy(&y, buf + 8, 4);

  if (foo(y, 570)) {
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }
  else if (foo(x, 340)) {
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
}
