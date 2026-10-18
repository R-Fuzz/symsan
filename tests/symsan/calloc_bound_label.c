// calloc's bound is nmemb * size bytes, and so must its label be.  The
// wrapper gave the bound the element size's label (zero here, a constant), so
// a write into a calloc'd array of symbolic length had no symbolic bound to
// overflow: with the write's size held at most 20, fewer elements were never asked
// for.  TaintPass hints
// the product's label for a direct call; through a pointer only the wrapper's
// label is there.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x08\x00\x00\x00\x14\x00\x00\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1 trace_bounds=1" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 sh -c 'env TAINT_OPTIONS="debug=1 trace_bounds=1" %t.fg "$0" || true' 2>&1 | FileCheck %s
// CHECK: ERROR: OOB overflow

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
  if (n == 0 || n > 64 || m < 17 || m > 20)
    return 0;

  void *(*volatile alloc)(size_t, size_t) = calloc;
  int *c = alloc(n, sizeof(int));
  if (!c)
    return 0;
  memset(c, 0, m);
  int r = ((volatile int *)c)[0];
  free(c);
  return r;
}
