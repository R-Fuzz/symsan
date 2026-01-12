// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// First iteration sees colon, solves key='username'
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// Second iteration solves value='password'
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-0-0 output_dir=%t.out session_id=1 enum_gep=0" %fgtest %t.fg %t.out/id-0-0-0
// Third iteration checks both key and value constraints
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-1-1 output_dir=%t.out session_id=2 enum_gep=0 debug=1" %fgtest %t.fg %t.out/id-0-1-1
// RUN: %t.uninstrumented %t.out/id-0-2-2 | FileCheck --check-prefix=CHECK-GEN %s

// Test: key-value parsing pattern "key:value"
// strchr finds the delimiter, strncpy extracts key, pointer arithmetic extracts value
// Expectations are placed on both key and value to test symbolic strncpy length

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
  size_t nread = fread(buf, 1, sizeof(buf) - 1, fp);
  fclose(fp);
  buf[nread] = '\0';
  size_t buflen = strlen(buf);

  // Find colon delimiter (key:value separator)
  char *sep = strchr(buf, ':');
  if (sep) {
    // Extract key (prefix before the colon)
    size_t len = sep - buf;
    char key[20] = {0};  // Initialize to avoid kInitializingLabel
    char value[20] = {0};
    strncpy(key, buf, len);
    key[len] = '\0';
    strcpy(value, sep + 1);

    // Check if there's a value part after the colon
    // size_t sep_offset = sep - buf;
    // if (sep_offset + 1 < buflen) {
    //   // Safe to copy value part
    //   size_t value_len = buflen - (sep_offset + 1);
    //   strncpy(value, sep + 1, value_len);
    //   value[value_len] = '\0';
    // }
    // else: value remains empty string

    // This tests constraints on both parts of the key:value pattern
    if (strcmp(key, "username") == 0 && strcmp(value, "password") == 0) {
      // CHECK-GEN: Found
      printf("Found\n");
    } else {
      // BAD
      printf("Key='%s' (len=%zu), Value='%s'\n", key, len, value);
    }
  } else {
    // CHECK-ORIG: No colon found
    printf("No colon found\n");
  }
  return 0;
}
