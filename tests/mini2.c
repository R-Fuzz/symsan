// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print"A"*32' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
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

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[32];
  FILE* fp = chk_fopen(argv[1], "rb");

  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  int32_t a = 0;
  int32_t b = 0;
  int32_t c = 0;
  int32_t d = 0;
  int32_t e = 0;
  int32_t f = 0;

  memcpy(&a, buf, 4);
  memcpy(&b, buf + 4, 4);
  memcpy(&c, buf + 8, 4);
  memcpy(&d, buf + 12, 4);
  memcpy(&e, buf + 16, 4);
  memcpy(&f, buf + 20, 4);

  if (a == 0xff) {
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }

  if (a < b) {
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }

  if (c + b == 10) {
    // CHECK-GEN3: Good3
    printf("Good3\n");
  }

  if (d  == 0xcc) {
    // CHECK-GEN4: Good4
    printf("Good4\n");
  }

  if (e - f == 0xdeadbeef) {
    // CHECK-GEN5: Good5
    printf("Good5\n");
  }

  if (f != b) {
    // CHECK-GEN6: Good6
    printf("Good6\n");
  }

  return 0;
}
