// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// First iteration: finds semicolon with strchr
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// Second iteration: finds last colon before semicolon with memrchr
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-0-0 output_dir=%t.out session_id=1 enum_gep=0" %fgtest %t.fg %t.out/id-0-0-0
// RUN: %t.uninstrumented %t.out/id-0-1-1 | FileCheck --check-prefix=CHECK-GEN %s

// Test mixed chain: strchr followed by memrchr with bounded length
// t1 = strchr(buf, ';');        // find first semicolon (forward, null-terminated)
// t2 = memrchr(buf, ':', t1-buf); // find LAST colon before the semicolon (backward, bounded)
// This tests combining strchr (indexof) and memrchr (last_indexof with substr)

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

  // First: strchr finds first ';' (forward search, null-terminated)
  char *t1 = strchr(buf, ';');
  if (t1) {
    // Second: memrchr finds LAST ':' before the ';' (backward search, bounded)
    size_t len_before_t1 = t1 - buf;
    char *t2 = (char *)memrchr(buf, ':', len_before_t1);
    if (t2) {
      // CHECK-GEN: Found last colon before first semicolon
      printf("Found last colon before first semicolon (colon at %ld, semicolon at %ld)\n",
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
