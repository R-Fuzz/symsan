// tlookup is an i2s-only op: jigsaw and z3 decline it rather than model it.
//
// No symbolic arrays, no ite chains over table entries, no JIT'd table loads.
// The declines need no new code -- jigsaw's codegen already ends in
// `default: throw std::invalid_argument("unhandled expression")` wrapped in a
// catch that returns -1, z3-ts's serialize already warns on an unknown label op
// and throws, and solvers/z3-solver.cpp names rgd::TLookup explicitly beside the
// FP transcendentals so the decline reads as a decision in a log rather than a
// parser bug.
//
// What this test pins is that the decline is *clean*.  The failure mode worth
// guarding against is not "no solution" -- that is the expected outcome -- but a
// solver quietly producing a wrong one, or aborting the session.  So: run the
// same table_lookup.c shape under %fgtest (the in-process z3-ts path) and assert
// the run completes and emits nothing.  table_lookup.c covers the %afltest path
// that does solve it.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: echo -n "aaaaaaaa" > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: not ls %t.out/id-0-0-0

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"

static uint8_t hex[16] = {'0','1','2','3','4','5','6','7',
                          '8','9','a','b','c','d','e','f'};

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t buff[8] = {0};
  uint8_t tmp[17];
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buff, 1, sizeof(buff), fp);
  fclose(fp);

  for (int i = 0; i < 8; i++) {
    tmp[i << 1]       = hex[buff[i] >> 4];
    tmp[(i << 1) + 1] = hex[buff[i] % 16];
  }
  tmp[16] = 0;

  if (strncmp((char *)tmp, "4142434445464748", 16) == 0) {
    printf("Good\n");
    return 0;
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
