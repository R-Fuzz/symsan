// Test: strlen constraint in JSON context
// When shrinking, DELETE should remove bytes so JSON remains valid
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf '{"name":"HELLO WORLD HELLO WORLD","age":25}' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN %s

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return 1;
  }

  char buf[256];
  FILE *f = fopen(argv[1], "r");
  if (!f) {
    perror("fopen");
    return 1;
  }

  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  buf[n] = '\0';
  fclose(f);

  printf("Input: %s\n", buf);

  // Find name value
  char *start = strstr(buf, "\"name\":\"");
  if (!start) {
    printf("Field not found\n");
    return 0;
  }

  start += 8; // skip "name":"

  // Find closing quote
  char *end = strchr(start, '"');
  if (!end) {
    printf("Malformed JSON - no closing quote\n");
    return 0;
  }

  // Temporarily null-terminate for strlen
  *end = '\0';
  size_t len = strlen(start);
  *end = '"';

  printf("Name value: \"%.*s\" (len=%zu)\n", (int)len, start, len);

  if (len == 5) {
    // CHECK-GEN: SUCCESS
    printf("SUCCESS: Found name with exactly 5 chars!\n");
  } else {
    // CHECK-ORIG: NOT-5
    printf("NOT-5: len = %zu\n", len);
  }

  return 0;
}
