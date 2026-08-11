// A lookup table feeding arithmetic feeding a comparison: the decode half of
// AFL's "test-transform", at offset 38.
//
//   (dehex[a] << 4) + dehex[b] == 0xab
//
// This is the case that decided the design.  An inference scheme that merely
// records "input byte i indexes table T" and matches lookups to output
// positions cannot reconstruct it -- the lookup's result is consumed by a shift
// and an add before anything is compared.  Labelling the loaded value makes the
// arithmetic around it ordinary AST.
//
// It also needs more than the flat integer i2s path.  Three binop kinds are in
// play (Sub, Shl, Add), they are nested rather than sitting directly under the
// comparison, and the top-level Add has two symbolic operands, so neither side
// is the constant a flat inversion needs.  Worse, neither side can reach 0xab
// alone: the left is always a multiple of 16 and the right is always 0..15.
// Pinning either at the value it happens to hold never finds the 0xa0 + 0x0b
// split; enumerating one operand's (table-bounded) value set does.  See
// i2s_value_domain in solvers/i2s-solver.cpp.
//
// %afltest only: tlookup is an i2s-only op.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: echo -n "00" > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: cat %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-INPUT %s
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include "lib.h"

// '0'..'9' then the gap of punctuation, then 'A'..'F' -- the same table
// test-transform uses, and deliberately non-injective (many indices map to 0)
// so the inverter has to try more than the first match.
static uint8_t dehex[] = {0,1,2,3,4,5,6,7,8,9,
                          0,0,0,0,0,0,0,
                          10,11,12,13,14,15};

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t buff[2] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buff, 1, sizeof(buff), fp);
  fclose(fp);

  // the seed is "00", so both indices start at 0 and stay in range; the only
  // other value either byte takes is one the solver picks out of the table
  uint8_t v = (uint8_t)(dehex[buff[0] - '0'] << 4) + (uint8_t)dehex[buff[1] - '0'];

  // CHECK-INPUT: AB
  if (v == 0xab) {
    // CHECK-GEN: Good
    printf("Good\n");
    return 0;
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
