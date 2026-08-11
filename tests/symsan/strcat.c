// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A_A")' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out enum_gep=0" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN %s

// Test: strcat concatenates two parts of tainted input, then compare

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

  char prefix[20] = {0};
  char suffix[20] = {0};

  char *pos = strchr(buf, '_');
  if (pos) {
    size_t prefix_len = pos - buf;
    strncpy(prefix, buf, prefix_len);
    prefix[prefix_len] = '\0';
    strcpy(suffix, pos + 1);
  } else {
    printf("No _ found in input\n");
    return -1;
  }

  // Concatenate the two parts
  char result[256] = {0};
  strcpy(result, prefix);
  strcat(result, suffix);

  // Compare concatenated result
  if (strcmp(result, "deadbeef") == 0) {
    // CHECK-GEN: Match found
    printf("Match found: %s\n", result);
  } else {
    // CHECK-ORIG: No match
    printf("No match: %s\n", result);
  }
  return 0;
}
