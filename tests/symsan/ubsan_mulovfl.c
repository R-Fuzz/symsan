// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x02\x00\x00\x00\x03\x00\x00\x00')" > %t.bin
// RUN: clang -O0 -fsanitize=signed-integer-overflow,unsigned-integer-overflow -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 | FileCheck %s --check-prefix=MULOVFL
// MULOVFL: runtime error: {{signed|unsigned}} integer overflow
// MULOVFL: SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior

// Test multiplication overflow detection
// Multiplication can overflow even with small-looking numbers
// e.g., 65536 * 65536 overflows 32-bit

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

  // Start with a=2, b=3 (result=6, no overflow)
  // Solver should find values that cause overflow
  // e.g., a=0x10000, b=0x10000 -> 0x100000000 (overflows 32-bit)
  int32_t result = a * b;
  printf("%d\n", result);
  return 0;
}
