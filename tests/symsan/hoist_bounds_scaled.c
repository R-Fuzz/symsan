// A hoisted summary check's size is an expression over the loop's symbolic
// leaves -- here count ints, 4 * count bytes -- and __taint_solve_size got
// the label of the leaf alone: the recorded size (4 for count = 1) against
// the recomputed count (1) was a value mismatch, and the overflow had no
// solution (snd_hdac_setup_channel_mapping in the kernel eval).  The size's
// label is now the expression's.  The per-iteration check finds the overflow
// on its own here, so it is the mismatch that is checked.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x01\x00\x00\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env SYMSAN_MISMATCH_DETAIL=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin 2>&1 | FileCheck --check-prefix=SOLVE %s
// SOLVE-NOT: value mismatch
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

  int count = 0;

  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(&count, sizeof(count), 1, fp);
  fclose(fp);

  int *buf = malloc(4 * sizeof(int));
  if (!buf) return 0;

#pragma clang loop vectorize(disable) unroll(disable)
  for (int i = 0; i < count; i++) {
    buf[i] = i;
  }

  printf("%d\n", buf[0]);
  free(buf);
  return 0;
}
