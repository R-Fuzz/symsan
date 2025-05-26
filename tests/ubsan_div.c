// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x01\x00\x00\x00\x01\x00\x00\x00')" > %t.bin
// RUN: clang -fsanitize=undefined -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 | FileCheck %s
// CHECK: runtime error: division by zero
// CHECK: SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior

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
  int dividend = 0, divisor = 0;

  chk_fread(&dividend, sizeof(dividend), 1, fp);
  chk_fread(&divisor, sizeof(divisor), 1, fp);
  fclose(fp);
  printf("%d\n", dividend / divisor);
}
