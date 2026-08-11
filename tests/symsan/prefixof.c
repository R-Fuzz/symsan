// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN2 %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Provide simple implementations for uninstrumented build
int prefixof(const char *str, const char *prefix) {
  size_t prefix_len = strlen(prefix);
  size_t str_len = strlen(str);
  if (str_len >= prefix_len && memcmp(str, prefix, prefix_len) == 0) {
    return 1;
  }
  return 0;
}

int suffixof(const char *str, const char *suffix) {
  size_t suffix_len = strlen(suffix);
  size_t str_len = strlen(str);
  if (str_len >= suffix_len &&
      memcmp(str + (str_len - suffix_len), suffix, suffix_len) == 0) {
    return 1;
  }
  return 0;
}

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

  if (prefixof(buf, "hello")) {
    // CHECK-GEN1: Has prefix
    printf("Has prefix\n");
  } else {
    // CHECK-ORIG: No prefix
    printf("No prefix\n");
  }

  if (suffixof(buf, "world")) {
    // CHECK-GEN2: Has suffix
    printf("Has suffix\n");
  } else {
    // CHECK-ORIG: No suffix
    printf("No suffix\n");
  }

  return 0;
}
