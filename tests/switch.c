// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg @@
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: %t.uninstrumented %t.out/id-0-0-4 | FileCheck --check-prefix=CHECK-GEN5 %s
// RUN: %t.uninstrumented %t.out/id-0-0-5 | FileCheck --check-prefix=CHECK-GEN6 %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: %t.uninstrumented %t.out/id-0-0-4 | FileCheck --check-prefix=CHECK-GEN5 %s
// RUN: %t.uninstrumented %t.out/id-0-0-5 | FileCheck --check-prefix=CHECK-GEN6 %s

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

  char buf[20];
  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  int b = 0;
  memcpy(&b, buf + 2, 4);
  int x = 0;
  memcpy(&x, buf + 6, 4);

  switch (b) {
  case 12312213:
    // CHECK-GEN1: Good1
    printf("Good1\n");
    break;
  case 13201000:
    // CHECK-GEN2: Good2
    printf("Good2\n");
    break;
  case -1111:
    // CHECK-GEN3: Good3
    printf("Good3\n");
    break;
  case 3330000:
    // CHECK-GEN4: Good4
    printf("Good4\n");
    break;
  case 5888:
    // CHECK-GEN5: Good5
    printf("Good5\n");
    break;
  case -897978:
    // CHECK-GEN6: Good6
    printf("Good6\n");
    break;
  default:
    // CHECK-ORIG: Bad
    printf("Bad\n");
    break;
  }
}
