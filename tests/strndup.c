// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// First iteration finds colon
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// Second iteration solves key constraint
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-0-0 output_dir=%t.out session_id=1" %fgtest %t.fg %t.out/id-0-0-0
// RUN: %t.uninstrumented %t.out/id-0-1-1 | FileCheck --check-prefix=CHECK-GEN %s

// Test: strndup with symbolic length from strchr result
// Pattern: find delimiter, duplicate prefix using strndup, compare

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

  // Find colon delimiter - this makes len symbolic
  char *sep = strchr(buf, ':');
  if (sep) {
    size_t len = sep - buf;  // symbolic length

    // Duplicate first 'len' bytes using strndup
    // This uses strndup with symbolic n!
    char *key = strndup(buf, len);
    if (!key) {
      fprintf(stderr, "strndup failed\n");
      return -1;
    }

    // Compare the duplicated key
    if (strcmp(key, "user") == 0) {
      // CHECK-GEN: Match found
      printf("Match found: key=%s\n", key);
    } else {
      printf("No match: key=%s (len=%zu)\n", key, len);
    }

    free(key);
  } else {
    // CHECK-ORIG: No colon found
    printf("No colon found\n");
  }
  return 0;
}
