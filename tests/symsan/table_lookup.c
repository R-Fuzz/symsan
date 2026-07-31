// Lookup-table load, the shape that stalls AFL's "test-transform" at offset 30.
//
// `hex[]` is a static global, so shadow memory over it is zero and the loaded
// byte would ordinarily carry label 0.  That makes `tmp` fully concrete, and
// __dfsw_strncmp takes its "both operands concrete" early return -- the session
// never learns the check exists, even though the *index* into the table is
// symbolic.  The tlookup op labels the loaded value instead, so `tmp` gets a
// real shadow, propagates through shadow memory for free, and the strncmp
// arrives at the solver as an ordinary memcmp constraint.
//
// Solving it means inverting through the table: scan `hex[]` for the wanted
// output byte and drive the index expression to its position.  Each target byte
// pins one nibble of one input byte (`>> 4` the high one, `% 16` the low one),
// so the two halves have to agree rather than overwrite each other -- see
// i2s_binop_invert in solvers/i2s-solver.cpp.
//
// %afltest only: tlookup is an i2s-only op.  jigsaw and z3 decline it (see
// table_lookup_unsupported.c), which is deliberate -- no symbolic arrays.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: echo -n "aaaaaaaa" > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

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

  // the only input satisfying this is "ABCDEFGH"
  if (strncmp((char *)tmp, "4142434445464748", 16) == 0) {
    // CHECK-GEN: Good
    printf("Good\n");
    return 0;
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
