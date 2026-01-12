// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// First iteration: finds first colon
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// Second iteration: finds second colon using output from first
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-0-0 output_dir=%t.out session_id=1 enum_gep=0" %fgtest %t.fg %t.out/id-0-0-0
// RUN: %t.uninstrumented %t.out/id-0-1-1 | FileCheck --check-prefix=CHECK-GEN %s

// Test chained memchr with bounded length from previous result:
// t1 = memchr(buf, c1, len); t2 = memchr(buf, c2, t1-buf);
// This tests forward search (indexof) with substr constraint

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[256] = {0};
  FILE* fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    return -1;
  }
  size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
  fclose(fp);
  buf[n] = '\0';

  // First memchr: find first ';' in the buffer
  char *t1 = (char *)memchr(buf, ';', n);
  if (t1) {
    // Second memchr: find ':' that appears after the ';'
    // This uses the bounded search pattern: memchr(t1, ':', n - (t1 - buf))
    size_t len_after_t1 = n - (t1 - buf);
    char *t2 = (char *)memchr(t1, ':', len_after_t1);
    if (t2) {
      // CHECK-GEN: Found colon before semicolon
      printf("Found colon before semicolon (colon at %ld, semicolon at %ld)\n",
             (long)(t2 - buf), (long)(t1 - buf));
    } else {
      printf("Found semicolon but no colon before it (semicolon at %ld)\n",
             (long)(t1 - buf));
    }
  } else {
    // CHECK-ORIG: No semicolon
    printf("No semicolon\n");
  }
  return 0;
}
