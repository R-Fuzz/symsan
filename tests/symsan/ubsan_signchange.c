// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00')" > %t.bin
// RUN: clang -O0 -fsanitize=implicit-integer-sign-change -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-1 2>&1 | FileCheck %s --check-prefix=SIGNCHANGE
// SIGNCHANGE: runtime error: implicit conversion from type
// SIGNCHANGE: changed the value to

// Test implicit integer sign change detection
// Sign change occurs when truncating a positive value to negative or vice versa
// Example: int32_t 128 -> int8_t -128 (sign changes from positive to negative)

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

  // Start with x=0 (no sign change when truncating to int8_t)
  // Solver should find e.g., x=128 which becomes -128 as int8_t (sign change)
  // or x=-129 which becomes 127 as int8_t (sign change)
  // Use implicit conversion (no explicit cast) to trigger ubsan
  int8_t y = x;
  printf("%d -> %d\n", x, y);
  return 0;
}
