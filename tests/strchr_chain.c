// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// First iteration: finds first colon
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// Second iteration: finds second colon using output from first
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-0-0 output_dir=%t.out session_id=1" %fgtest %t.fg %t.out/id-0-0-0
// RUN: %t.uninstrumented %t.out/id-0-1-1 | FileCheck --check-prefix=CHECK-GEN %s

// Test chained strchr: t1 = strchr(h, c1); t2 = strchr(t1+1, c2);

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
  buf[19] = '\0';

  char *t1 = strchr(buf, ':');
  if (t1) {
    char *t2 = strchr(t1 + 1, ':');
    if (t2) {
      // CHECK-GEN: Found two colons
      printf("Found two colons\n");
    } else {
      printf("Found one colon\n");
    }
  } else {
    // CHECK-ORIG: No colons
    printf("No colons\n");
  }
  return 0;
}
