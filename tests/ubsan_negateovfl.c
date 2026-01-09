// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00')" > %t.bin
// RUN: clang -O0 -fsanitize=signed-integer-overflow -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 | FileCheck %s --check-prefix=NEGOVFL
// NEGOVFL: runtime error: negation of
// NEGOVFL: cannot be represented

// Test negate overflow detection
// -INT_MIN overflows because INT_MIN = -2147483648 and +2147483648 doesn't fit in int32_t

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

  FILE* fp = chk_fopen(argv[1], "rb");
  int32_t x = 0;

  chk_fread(&x, sizeof(x), 1, fp);
  fclose(fp);

  // Start with x=0 (no overflow when negating)
  // Solver should find x=INT_MIN (-2147483648) which overflows when negated
  int32_t y = -x;
  printf("%d -> %d\n", x, y);
  return 0;
}
