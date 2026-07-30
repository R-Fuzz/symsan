// Test strlen-bounded loop hoisting: when SCEV can't compute the trip
// count because the loop exit depends on a null terminator in memory,
// the pass detects the while(ptr[i]) pattern and emits a hoisted
// __taint_solve_str_bounds check. The solver should find a string length
// that overflows the destination buffer.
//
// This mimics the shellescape pattern: a while(from[i]) loop copies
// characters from a source string into a fixed-size destination buffer.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'AB\x00' + b'\x00' * 5)" > %t.bin
// RUN: env KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env TAINT_OPTIONS="debug=1 trace_bounds=1 exit_on_memerror=1" %t.fg %t.out/id-0-0-1 2>&1 | FileCheck %s
// CHECK: ERROR: OOB overflow

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

// Prevent inlining so the loop structure is preserved
__attribute__((noinline))
void copy_str(const char *src, char *dst) {
  int i = 0;
#pragma clang loop vectorize(disable) unroll(disable)
  while (src[i] != '\0') {
    dst[i] = src[i];
    i++;
  }
  dst[i] = '\0';
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return 0;
  }

  char input[8];
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(input, 1, sizeof(input), fp);
  fclose(fp);
  input[7] = '\0';

  // Small destination buffer — if strlen(input) > 3, OOB
  char dst[4];
  copy_str(input, dst);

  printf("%s\n", dst);
  return 0;
}
