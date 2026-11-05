// RUN: python -c'print("ABCD")' > %t.bin
// RUN: env KO_USE_Z3=1 %ko-clang -O0 -o %t.union %s
// RUN: env KO_USE_Z3=1 %ko-clang -O0 -DSTACK -o %t.stack %s
// RUN: not env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1 shm_size=2162688" %t.union %t.bin 2>&1 | FileCheck %s
// RUN: not env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1 shm_size=2162688" %t.stack %t.bin 2>&1 | FileCheck %s

// The union labels grow up the label table, the alloca (stack bounds) labels
// down from its end.  Where they meet, the labels have run out, either way:
// a union node taken in the alloca range was accepted as a valid alloca label
// and written over a live alloca's bounds, and an alloca label taken below the
// last union label reset a live node -- silently wrong constraints.  A small
// table (shm_size: 67584 labels) meets in a few thousand iterations.
// CHECK: start
// CHECK: FATAL: Taint: out of labels
// CHECK-NOT: done
#include <stdio.h>

int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], "rb");
  unsigned char in[4];
  if (!f || fread(in, 1, 4, f) != 4) return 1;
  volatile char local[16];
  local[0] = 0;
  unsigned x = in[0];
  printf("start\n");
  fflush(stdout);
#ifndef STACK
  // distinct nodes: i is a different constant each time
  for (unsigned i = 0; i < 100000; i++)
    x = x * 3 + i;
#else
  x = x * 3 + 1;
  // one alloca label each, none released before main returns
  for (unsigned i = 0; i < 100000; i++) {
    volatile char *p = __builtin_alloca(8);
    p[0] = (char)x;
  }
#endif
  printf("done %u %d\n", x, local[0]);
  return 0;
}
