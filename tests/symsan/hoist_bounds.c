// Test that bounds-check hoisting out of loops still detects OOB.
// A fixed-count loop (trip count known to SCEV) writes symbolic data
// into a heap buffer. The solver should find an allocation size that
// makes the loop go out of bounds. The hoisted summary check in the
// preheader must catch this.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x1a\x00\x00\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env TAINT_OPTIONS="debug=1 trace_bounds=1 exit_on_memerror=1" %t.fg %t.out/id-0-0-0 2>&1 | FileCheck %s
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

  int size = 0;

  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(&size, sizeof(size), 1, fp);
  fclose(fp);

  // Allocate with symbolic size
  char *buf = malloc(size);
  if (!buf) return 0;

  // Fixed-count loop — SCEV can compute trip count = 26
  // When size < 26, the hoisted bounds check should detect OOB
#pragma clang loop vectorize(disable) unroll(disable)
  for (int i = 0; i < 26; i++) {
    buf[i] = 'A' + i;
  }

  // Use last element so the loop isn't dead-code-eliminated
  printf("%c\n", buf[25]);
  free(buf);
  return 0;
}
