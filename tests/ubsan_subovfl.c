// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00\x01\x00\x00\x00')" > %t.bin
// RUN: clang -O0 -fsanitize=signed-integer-overflow -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 | FileCheck %s --check-prefix=SUBOVFL
// SUBOVFL: runtime error: signed integer overflow
// SUBOVFL: SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior

// Test signed subtraction overflow detection
// Overflow occurs when:
//   - INT_MAX - (-1) wraps to negative (positive overflow)
//   - INT_MIN - 1 wraps to positive (negative overflow)

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
  int32_t a = 0, b = 0;

  chk_fread(&a, sizeof(a), 1, fp);
  chk_fread(&b, sizeof(b), 1, fp);
  fclose(fp);

  // Start with a=0, b=1 (no overflow)
  // Solver should find e.g., a=INT_MIN, b=1 (underflow)
  // or a=INT_MAX, b=-1 (overflow)
  int32_t result = a - b;
  printf("%d\n", result);
  return 0;
}
