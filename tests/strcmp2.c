// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print"A"*20' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// TODO: RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// TODO: RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// TODO: RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// TODO: RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s

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

  char a[20] = {
    1, 1, 1, 1, 7,
    8, 9, 1, 45, 2,
    88, 1, 1, 2, 3,
    4, 5, 0
  };


  char b[10] = {1, 1, 1, 1,
                1, 2, 3, 4, 5, 0};

  if (strcmp(buf, a) == 0) {
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  if (strcmp(buf, b) == 0) {
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }
}
