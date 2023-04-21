// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

typedef struct {
  int64_t x;
  int64_t y;
} point_struct;

point_struct __attribute__((noinline)) bar(int32_t x, int32_t y) {
    point_struct p;
    p.x = x;
    p.y = y;
    return p;
}

int __attribute__((noinline)) foo(int32_t y) {
    point_struct p = bar(y, y + 1);
    return p.x * p.y == 2;
}

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[20];
  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  int32_t x = 0;

  memcpy(&x, buf + 1, 4); // x 0 - 1

  if (foo(x) == 1) {
    // CHECK-GEN: Good
    printf("Good\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }
}
