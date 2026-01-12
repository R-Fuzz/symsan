// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// First iteration finds colon, second iteration solves prefix constraint
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-0-0 output_dir=%t.out session_id=1 enum_gep=0" %fgtest %t.fg %t.out/id-0-0-0
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-1-1 output_dir=%t.out session_id=2 enum_gep=0 debug=1" %fgtest %t.fg %t.out/id-0-1-1
// RUN: %t.uninstrumented %t.out/id-0-2-2 | FileCheck --check-prefix=CHECK-GEN %s

// Test: strchr to find delimiter, strncpy prefix, check first byte

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

  // Find colon delimiter
  char *sep = strchr(buf, ':');
  if (sep) {
    // Extract prefix before the colon
    size_t len = sep - buf;
    char prefix[20];
    strncpy(prefix, buf, len);
    prefix[len] = '\0';

    if (len > 1) {
      // Simple check: first byte equals 'X'
      if (prefix[0] == 'X') {
        // CHECK-GEN: Found X prefix
        printf("Found X prefix before colon\n");
      } else {
        // CHECK-COLON: First char is
        printf("First char is '%c' (0x%02x), not 'X'\n", prefix[0], (unsigned char)prefix[0]);
      }
    } else {
      printf("Prefix too short\n");
    }
  } else {
    // CHECK-ORIG: No colon
    printf("No colon found\n");
  }
  return 0;
}
