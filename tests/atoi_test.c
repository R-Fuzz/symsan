// Test: atoi constraints for extending and shrinking digit strings
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf '999' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 KO_DONT_OPTIMIZE=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

  int val = atoi(buf);
  printf("atoi returned: %d\n", val);

  // Test shrinking: 999 -> 42 (need fewer digits)
  if (val == 42) {
    // CHECK-GEN1: SHRINK-SUCCESS
    printf("SHRINK-SUCCESS: val == 42\n");
  }

  // Test extending: 999 -> 12345 (need more digits)
  if (val == 12345) {
    // CHECK-GEN2: EXTEND-SUCCESS
    printf("EXTEND-SUCCESS: val == 12345\n");
  }

  // Original input (999) hits neither branch
  if (val != 42 && val != 12345) {
    // CHECK-ORIG: NEITHER
    printf("NEITHER: val = %d\n", val);
  }

  return 0;
}
