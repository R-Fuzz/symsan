// Test bounds checking when both allocation size and loop count are symbolic.
// The solver should find a (size, count) pair where count > size, triggering OOB.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x1a\x00\x01\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env TAINT_OPTIONS="debug=1 trace_bounds=1 exit_on_memerror=1" %t.fg %t.out/id-0-0-1 2>&1 | FileCheck %s
// CHECK: ERROR: OOB overflow

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

  uint16_t size = 0;
  uint16_t count = 0;

  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(&size, sizeof(size), 1, fp);
  chk_fread(&count, sizeof(count), 1, fp);
  fclose(fp);

  // Both size and count are symbolic; +1 so malloc(0) can't happen
  char *buf = malloc(size + 1);
  if (!buf) return 0;

  // Variable loop count over variable-size buffer.
  // Initial input: size=26, count=1 (safe).
  // Solver should find size/count pair where count > size+1 → OOB.
#pragma clang loop vectorize(disable) unroll(disable)
  for (int i = 0; i < count; i++) {
    buf[i] = 'A' + (i % 26);
  }

  printf("%c\n", buf[0]);
  free(buf);
  return 0;
}
