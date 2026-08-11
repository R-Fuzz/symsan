// A NON-INJECTIVE lookup table: which matching entry i2s picks decides whether
// the answer survives the guard that gates the decode.
//
// This is fuzzer-challenges' test-transform at offset 38, reduced.  `dehex[]` is
// indexed by `c - '0'` and maps two entries onto every value above 9 -- index 22
// is 'F' and index 54 is 'f', both worth 15 -- so inverting `dehex[x] == 15` has
// two answers and nothing about the index expression separates them: 'F' and 'f'
// are each one byte write away.  Scanning the table in order and keeping the
// first hit therefore picks 'F', and the guard below accepts only [0-9a-f], so
// the "solution" bails one branch EARLIER than the branch being solved for.  The
// session reports SAT, the replay never reaches the goal, and the target reads
// as structurally unsolvable.  Nothing cracked the real one: not any symsan mode,
// not LibAFL cmplog, not afl-fuzz with -l 3ATX.
//
// Solving the decode and the guard together would need both constraints in one
// task, i.e. nested solving, which is far too slow to leave on.  i2s instead does
// what AFL++'s redqueen transforms do: keep upper and lower tables and choose by
// the case already present in the input (hex_table_up / hex_table_low, selected
// by from_up / to_up in afl-fuzz-redqueen.c), defaulting to lowercase when the
// input shows no case at all.  See i2s_table_pref in solvers/i2s-solver.cpp.
//
// The seed is deliberately all DIGITS.  A digit is valid hex, so it passes the
// guard and the trace reaches the compare -- but it carries no case evidence, so
// this exercises the lowercase default rather than the observation rule.  That is
// the harder half and the one that actually fires on test-transform, whose
// guard-passing inputs arrive full of '0'.  Both target nibbles are ambiguous
// (0xe is 'E'/'e', 0xf is 'F'/'f'), so a rule that got case right only sometimes
// would still fail here.
//
// %afltest only: tlookup is an i2s-only op.  jigsaw and z3 decline it (see
// table_lookup_unsupported.c), which is deliberate -- no symbolic arrays.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: echo -n "00" > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
//
// Replay every solution: picking 'F' still produces a file, it just prints
// BadHex, so the existence of output proves nothing and only the replay does.
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"

// the table from test-transform, verbatim: 55 entries, indexed by `c - '0'`,
// with 'A'..'F' at 17..22 and 'a'..'f' at 49..54 both mapping to 10..15
static uint8_t dehex[] = {0, 1, 2, 3,  4,  5,  6,  7,  8,  9,  0,  0,  0, 0,
                          0, 0, 0, 10, 11, 12, 13, 14, 15, 0,  0,  0,  0, 0,
                          0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,
                          0, 0, 0, 0,  0,  0,  0,  10, 11, 12, 13, 14, 15};

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t buff[2] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buff, 1, sizeof(buff), fp);
  fclose(fp);

  // The guard, and the whole point of the test: lowercase hex and digits only.
  // 'F' passes the table inversion and fails right here.
  for (int i = 0; i < 2; i++) {
    if (!((buff[i] >= 'a' && buff[i] <= 'f') ||
          (buff[i] >= '0' && buff[i] <= '9'))) {
      printf("BadHex\n");
      return 0;
    }
  }

  uint8_t v = (uint8_t)(dehex[buff[0] - '0'] << 4) + (uint8_t)dehex[buff[1] - '0'];

  // both nibbles are ambiguous entries of the table, so "ef" reaches this and
  // "EF" -- the answer a first-match scan gives -- never gets past the guard
  if (v == 0xef) {
    // CHECK-GEN: Good
    printf("Good\n");
    return 0;
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
