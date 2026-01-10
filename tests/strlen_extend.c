// Test strlen extending - input needs to grow to reach target length
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf 'short\0' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) return 1;

  char buf[64];
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;

  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);

  size_t len = strlen(buf);
  printf("strlen: %zu\n", len);

  if (len == 15) {
    // CHECK-GEN: SUCCESS
    printf("SUCCESS: strlen == 15\n");
  } else {
    // CHECK-ORIG: NOT-15
    printf("NOT-15: strlen = %zu\n", len);
  }

  return 0;
}
