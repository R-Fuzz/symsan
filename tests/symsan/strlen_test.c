// Test: strlen constraints for various length comparisons
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf 'HELLO WORLD' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 KO_DONT_OPTIMIZE=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s

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
  size_t n = fread(buf, 1, 63, f);
  buf[n] = '\0';
  fclose(f);

  size_t len = strlen(buf);
  printf("strlen = %zu\n", len);

  if (len > 10) {
    // CHECK-ORIG: Long string
    printf("Long string (> 10)!\n");
  }
  if (len == 5) {
    // CHECK-GEN2: Exact length 5
    printf("Exact length 5!\n");
  }
  if (len < 3) {
    // CHECK-GEN1: Short string
    printf("Short string (< 3)!\n");
  }
  return 0;
}
