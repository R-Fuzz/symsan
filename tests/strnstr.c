// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s -lbsd
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// First iteration finds delimiter
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-0-0 output_dir=%t.out session_id=1" %fgtest %t.fg %t.out/id-0-0-0
// RUN: %t.uninstrumented %t.out/id-0-1-1 | FileCheck --check-prefix=CHECK-GEN %s

// Test: strnstr with symbolic length from strchr result
// Pattern: find delimiter, then search for pattern only within prefix before delimiter

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char *strnstr(const char *haystack, const char *needle, size_t len);

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

  // Find delimiter - this makes len symbolic
  char *sep = strchr(buf, ':');
  if (sep) {
    size_t len = sep - buf;  // symbolic length

    // Search for "key" only within the first 'len' bytes (before delimiter)
    // This tests strnstr with symbolic n parameter
    char *found = strnstr(buf, "key", len);

    if (found != NULL) {
      // CHECK-GEN: Found key before delimiter
      printf("Found key before delimiter at position %ld\n", found - buf);
    } else {
      printf("No key in first %zu bytes\n", len);
    }
  } else {
    // CHECK-ORIG: No delimiter
    printf("No delimiter found\n");
  }
  return 0;
}
