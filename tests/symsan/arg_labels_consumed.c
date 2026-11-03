// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x01\x00\x00\x00')" > %t.bin
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1" %t.fg %t.bin 2>&1 | FileCheck %s

// An argument's label is passed in TLS, and uninstrumented code writes none
// there: an instrumented function it calls back (qsort's comparator here,
// v8's runtime functions called by its builtins) read the labels the last
// instrumented call left.  keep()'s second argument is a pointer into a heap
// block, its label the block's bounds, and the comparator's second pointer,
// into the array qsort sorts, was checked against them: an OOB on every
// compare.  A function now zeroes its arguments' labels once it has read them.
// CHECK-NOT: OOB
// CHECK: sorted 1 2 3 4
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static char *kept;

__attribute__((noinline)) void keep(long n, char *p) {
  kept = p + n;
}

static int cmp(const void *a, const void *b) {
  return *(const int *)a - *(const int *)b;
}

int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], "rb");
  uint32_t i = 0;
  if (!f || fread(&i, 1, sizeof(i), f) != sizeof(i)) return 1;
  char *block = malloc(64);
  keep(i & 1, block);
  int a[4] = {3, 1, 4, 2};
  qsort(a, 4, sizeof(int), cmp);
  printf("sorted %d %d %d %d\n", a[0], a[1], a[2], a[3]);
  free(block);
  return 0;
}
