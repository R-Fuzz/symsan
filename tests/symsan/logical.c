// Every reachable branch of a trace full of logical operators gets an answer.
//
// One run, eight independent targets: an else-if chain, a disjunction whose
// second alternative is only reachable once the first is false, two conditions
// nested under an `||` that the seed already takes, an eight-term conjunction
// over four differently-sized reads, and a lone equality.  The point is that
// none of them shadow the others -- a trace with this many live conditions
// should yield an input per condition, not just for the first one flipped.
//
// Do NOT add KO_DONT_OPTIMIZE here.  Good7's conjunction short-circuits at -O0,
// so the later terms never make it into the trace and no input can satisfy all
// eight at once; at -O3 clang folds the chain branchlessly into a single
// condition and it solves.  This is the same reason mini.c, from which that
// block was imported, is built optimized.
//
// The generated inputs are replayed as a set rather than by name: the two arms
// disagree on both how many files they emit and which id lands on which branch,
// and it is the coverage that is under test, not the numbering.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*4*100)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-GEN %s
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  int integers[100];
  FILE* fp = chk_fopen(argv[1], "rb");
  fread(integers, 1, sizeof(integers), fp);
  fclose(fp);

  if (integers[0] == 0x41414141 && integers[1] == 2) {
    // CHECK-GEN-DAG: Good1
    printf("Good1\n");
  }
  else if (integers[0] == 0xdeadbeef) {
    // CHECK-GEN-DAG: Good2
    printf("Good2\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  if (integers[2] == 3 || integers[3] == 4) {
    // CHECK-GEN-DAG: Good3
    printf("Good3\n");
  }
  else if (integers[2] == 0xbadf00d) {
    // CHECK-GEN-DAG: Good4
    printf("Good4\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  if (integers[4] == 0x41414141 || integers[5] == 5) {
    printf("Bad\n");
    if (integers[5] == 0xcafebabe) {
      // CHECK-GEN-DAG: Good5
      printf("Good5\n");
    }
    if (integers[6] == 0xbadbad) {
      // CHECK-GEN-DAG: Good6
      printf("Good6\n");
    }
  }

  // Import from mini.c, which results in conjunction of conditions
  char *buf = (char *)&integers[7];
  uint16_t x = 0;
  int32_t y = 0;
  int32_t z = 0;
  uint32_t a = 0;

  memcpy(&x, buf + 1, 2);  // x 1 - 2
  memcpy(&y, buf + 4, 4);  // y 4 - 7
  memcpy(&z, buf + 10, 4); // 10 - 13
  memcpy(&a, buf + 14, 4); // 14 - 17

  if (x > 12300 && x < 12350 && z < -100000000 && z > -100000005 &&
      z != -100000003 && y >= 987654321 && y <= 987654325 && a == 123456789) {
    // CHECK-GEN-DAG: Good7
    printf("Good7\n");
  }

  if (a == 12345678) {
    // CHECK-GEN-DAG: Good8
    printf("Good8\n");
  }
}
