// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg @@
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: cp %t.out/id-0-0-0 %t.bin1
// RUN: cp %t.out/id-0-0-1 %t.bin2
// RUN: env TAINT_OPTIONS="taint_file=%t.bin1 output_dir=%t.out" %fgtest %t.fg @@
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN12 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin2 output_dir=%t.out" %fgtest %t.fg @@
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN23 %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: cp %t.out/id-0-0-0 %t.bin1
// RUN: cp %t.out/id-0-0-1 %t.bin2
// RUN: env TAINT_OPTIONS="taint_file=%t.bin1 output_dir=%t.out" %t.z3 %t.bin1
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN12 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin2 output_dir=%t.out" %t.z3 %t.bin2
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN23 %s

#include <stdio.h>
#include <stdint.h>
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

  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  uint32_t x = 0;
  uint32_t y = 0;

  memcpy(&x, buf, 4);
  memcpy(&y, buf + 8, 4);

  if (x > 41) {
    if (foo(y, 570)) {
      if (x == 12345) {
        // CHECK-GEN23: GOOD4
        printf("GOOD4\n");
      } else {
        // CHECK-GEN2: GOOD2
        printf("GOOD2\n");
      }
    } else {
      // CHECK-ORIG: BAD
      printf("BAD\n");
    }
  } else {
    if (foo(y, 312)) {
      // CHECK-GEN12: GOOD3
      printf("GOOD3\n");
    } else {
      // CHECK-GEN1: GOOD1
      printf("GOOD1\n");
    }
  }

  return 0;
}
