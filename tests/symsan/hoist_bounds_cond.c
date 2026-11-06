// Test that a bounds check under a condition in the loop body is not hoisted.
// The summary check covers every iteration's access, [buf, buf + count); an
// access only some iterations make (i < 4 here) is not one of those, and
// summarized it was a false OOB on the iterations that skip it (v8's
// JumpTableAssembler::GenerateFarJumpTable reads stub_targets[index] only
// for the runtime slots of the table it fills).
//
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x08\x00\x00\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="debug=1 trace_bounds=1 exit_on_memerror=1" %t.fg %t.bin 2>&1 | FileCheck %s
// CHECK-NOT: OOB
// CHECK: sum=10

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

  char *buf = malloc(4);
  if (!buf) return 0;
  for (int i = 0; i < 4; i++) buf[i] = i + 1;

  // count (8) iterations, but buf is read only on the first 4
  int sum = 0;
#pragma clang loop vectorize(disable) unroll(disable)
  for (int i = 0; i < count; i++) {
    if (i < 4)
      sum += buf[i];
  }

  printf("sum=%d\n", sum);
  free(buf);
  return 0;
}
