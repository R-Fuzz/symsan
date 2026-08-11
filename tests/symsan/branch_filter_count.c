// The in-process z3 runtime stops solving a branch after MAX_BRANCH_COUNT hits;
// the out-of-process tracer does not.
//
// bar() is reached 512 times through the same call chain, so all 512 hits share
// one calling context and land in just two branch addresses -- 256 on the
// x == 0xdeadbeef compare and 256 on the x == 0xbadf00d one.  Each hit tests a
// different word of the file, so all 512 are genuinely distinct questions and
// nothing but a deliberate cap keeps a solver from answering all of them.
//
// solvers/z3.cpp caps a (callstack, address) pair at MAX_BRANCH_COUNT = 16, so
// that arm answers 16 per address and quits: 32 files, Good0..Good15 from the
// first compare and Awesome256..Awesome271 from the second.  That cap is why
// SymSan stays responsive on loop-heavy targets, and it is what this pins --
// change the constant and this arm moves.
//
// fgtest has no such filter (the fuzzer it feeds does its own throttling), so
// it answers every one: 512 files, Good0 through Awesome511.  Running both arms
// off one program is the point; either count alone could be explained by the
// program rather than by the policy.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*4*2*256)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG --allow-empty %s
// CHECK-ORIG-NOT: Good
// CHECK-ORIG-NOT: Awesome
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out | wc -l | FileCheck --match-full-lines --check-prefix=CHECK-FG-N %s
// CHECK-FG-N: 512
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --match-full-lines --check-prefix=CHECK-FG %s
// CHECK-FG-DAG: Good0
// CHECK-FG-DAG: Good255
// CHECK-FG-DAG: Awesome256
// CHECK-FG-DAG: Awesome511
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out | wc -l | FileCheck --match-full-lines --check-prefix=CHECK-Z3-N %s
// CHECK-Z3-N: 32
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --match-full-lines --check-prefix=CHECK-Z3 %s
// CHECK-Z3-DAG: Good0
// CHECK-Z3-DAG: Good15
// CHECK-Z3-DAG: Awesome256
// CHECK-Z3-DAG: Awesome271

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

void __attribute__ ((noinline)) bar(uint32_t x, int i) {
  if (i < 256) {
    if (x == 0xdeadbeef) {
      printf("Good%d\n", i);
    }
  }
  else {
    if (x == 0xbadf00d) {
      printf("Awesome%d\n", i);
    }
  }
}

void __attribute__ ((noinline)) foo(uint32_t x, int i) {
  return bar(x, i);
}

void __attribute__ ((noinline)) func(uint32_t *integers) {
  for (int i = 0; i < 2*256; i++) {
    foo(integers[i], i);
  }
}

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint32_t integers[256 * 2];
  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(integers, 1, sizeof(integers), fp);
  fclose(fp);

  func(integers);
}
