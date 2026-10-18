// A variable-length array's bound is its size in bytes, and so must its label
// be.  __taint_trace_alloca stored the element count's label against the byte
// bound, so __taint_solve_size compared a write's byte size with the count:
// for n ints the recorded bound (4n) against the recomputed n was a value
// mismatch.  The label is now count * element size, at 64 bits.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x04\x00\x00\x00\x08\x00\x00\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env SYMSAN_MISMATCH_DETAIL=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1 trace_bounds=1" %fgtest %t.fg %t.bin 2>&1 | FileCheck --check-prefix=SOLVE %s
// SOLVE-NOT: value mismatch

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return 0;
  }

  uint32_t n = 0, m = 0;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&n, sizeof(n), 1, fp);
  chk_fread(&m, sizeof(m), 1, fp);
  fclose(fp);
  if (n == 0 || n > 64)
    return 0;

  int a[n];
  memset(a, 0, m);
  return a[0];
}
