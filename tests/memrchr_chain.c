// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// First iteration: finds last colon (searching from end)
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// Second iteration: finds second-to-last colon using output from first
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-0-0 output_dir=%t.out session_id=1" %fgtest %t.fg %t.out/id-0-0-0
// RUN: %t.uninstrumented %t.out/id-0-1-1 | FileCheck --check-prefix=CHECK-GEN %s

// Test chained memrchr: t1 = memrchr(h, c, len); t2 = memrchr(h, c, t1-h);
// This tests reverse search (last_indexof) and pointer arithmetic

#define _GNU_SOURCE
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

  // First memrchr: find LAST colon (searching from end)
  char *t1 = (char *)memrchr(buf, ':', sizeof(buf));
  if (t1) {
    // Second memrchr: find second-to-last colon (search from start up to t1)
    size_t len_before_t1 = t1 - buf;
    char *t2 = (char *)memrchr(buf, ':', len_before_t1);
    if (t2) {
      // CHECK-GEN: Found two colons (last at
      printf("Found two colons (last at %ld, second-to-last at %ld)\n",
             (long)(t1 - buf), (long)(t2 - buf));
    } else {
      printf("Found one colon (at %ld)\n", (long)(t1 - buf));
    }
  } else {
    // CHECK-ORIG: No colons
    printf("No colons\n");
  }
  return 0;
}
