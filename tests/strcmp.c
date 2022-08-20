// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[20];
  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  char a[10];
  char b[10] = {1, 1, 1, 1, 1, 2, 3, 4, 5, 0};

  /* int dd = memcmp(buf, "12313", 5); */
  /* if (dd) { */
  /*   printf("hey, you hit it \n"); */
  /* } */

  memcpy(a, buf, 9);
  a[9] = 0;

  if (strcmp(a, b) == 0) {
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }
  else {
    // CHECK-ORIG: Bad1
    printf("Bad1\n");
  }

  a[4] += 10;
  if (strcmp(a, b) == 0) {
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }
  else {
    // CHECK-ORIG: Bad2
    printf("Bad2\n");
  }

  a[4] += 244;
  if (strcmp(a, b) == 0) {
    // CHECK-GEN3: Good3
    printf("Good3\n");
  }
  else {
    // CHECK-ORIG: Bad3
    printf("Bad3\n");
  }

  a[4] -= 99;
  if (strcmp(a, b) == 0) {
    // CHECK-GEN4: Good4
    printf("Good4:\n");
  }
  else {
    // CHECK-ORIG: Bad4
    printf("Bad4\n");
  }

  return 0;
}
