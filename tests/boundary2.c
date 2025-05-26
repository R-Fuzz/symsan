// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00')" > %t.bin
// RUN: clang -fsanitize=address -o %t.asan %s
// RUN: env KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not %t.asan %t.out/id-0-0-1 2>&1 | FileCheck %s
// CHECK: ERROR: AddressSanitizer: stack-buffer-overflow

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return 0;
  }

  int index = 0;
  char alphabet[26] = {0};

  for (int i = 0; i < 26; i++) {
    alphabet[i] = 'A' + i;
  }

  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(&index, sizeof(index), 1, fp);
  fclose(fp);

  // BUG: off-by-one if index == 26
  if (index > sizeof(alphabet)) {
    printf("Bad\n");
    return 0;
  }

  printf("%c\n", alphabet[index]);
}
