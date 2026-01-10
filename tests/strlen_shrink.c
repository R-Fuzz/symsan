// Test: shrinking strlen by deleting bytes
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf 'HELLO WORLD' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return 1;
  }

  char buf[64];
  FILE *f = fopen(argv[1], "r");
  if (!f) {
    perror("fopen");
    return 1;
  }

  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  buf[n] = '\0';
  fclose(f);

  // This is the strlen we're solving
  size_t len = strlen(buf);
  printf("strlen returned: %zu\n", len);

  // Show what bytes are actually in the buffer
  printf("Buffer contents (hex): ");
  for (size_t i = 0; i < 15 && i < n; i++) {
    printf("%02x ", (unsigned char)buf[i]);
  }
  printf("\n");

  if (len == 5) {
    // CHECK-GEN: SUCCESS
    printf("SUCCESS: Found input with strlen=5\n");
  } else {
    // CHECK-ORIG: NOT-5
    printf("NOT-5: strlen=%zu\n", len);
  }

  return 0;
}
