// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x02\x00\x00\x00\x00\x00\x00\x00')" > %t.bin
// RUN: clang -fsanitize=undefined -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 | FileCheck %s --check-prefix=LARGE
// LARGE: runtime error: shift exponent
// LARGE: SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-1 2>&1 | FileCheck %s --check-prefix=NEG
// NEG: runtime error: shift exponent
// NEG: SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-2 2>&1 | FileCheck %s --check-prefix=OVFL
// OVFL: runtime error: left shift
// OVFL: SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-3 2>&1 | FileCheck %s --check-prefix=NEGB
// NEGB: runtime error: left shift of negative value
// NEGB: SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior


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
  int base = 0, shift = 0;

  chk_fread(&base, sizeof(base), 1, fp);
  chk_fread(&shift, sizeof(shift), 1, fp);
  fclose(fp);
  printf("%d\n", base << shift);
}
