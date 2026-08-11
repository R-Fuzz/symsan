// A static global that is *stored to* must not be treated as a lookup table.
//
// Detection accepts a global whose initializer is the only thing that ever
// determines its contents -- GlobalStatus::analyzeGlobal reporting NotStored,
// plus local linkage so "no stores in this module" is the whole story.  Not
// isConstant(), because at -O0 GlobalOpt never runs and the tables that matter
// (`static uint8_t hex[16]`, in test-transform) are not declared const.
//
// That predicate is the whole safety argument for shipping a snapshot of the
// table's bytes to the solver and treating them as fixed.  A global the program
// writes has no such guarantee, so it stays concrete and the guard below stays
// invisible -- exactly as it was before tlookup existed.
//
// This is a gate test, not a soundness test: it asserts that loosening the
// NotStored check would fail here loudly rather than silently widening what
// gets snapshotted.  Compare table_lookup.c, which is the same shape with a
// never-stored table and does solve.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: echo -n "a" > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: not ls %t.out/id-0-0-0

#include <stdint.h>
#include <stdio.h>
#include "lib.h"

static uint8_t tbl[16];

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t buff[1] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buff, 1, sizeof(buff), fp);
  fclose(fp);

  // the store is what disqualifies tbl[]
  for (int i = 0; i < 16; i++) tbl[i] = (uint8_t)('0' + i);

  uint8_t c = tbl[buff[0] & 0xf];
  if (c == '7') {
    // unreachable for the solver: c is concrete, so this branch is never
    // reported and no input is generated for it
    printf("Good\n");
    return 0;
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
