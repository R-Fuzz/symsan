// The in-process z3 runtime answers a given label once, no matter how many
// times the branch is hit.
//
// The compare below runs 1024 times on the same x, so every hit carries the
// identical label -- the same question, asked 1024 times.  solvers/z3.cpp keeps
// __solved_labels and skips the repeats, so that arm emits exactly one file.
// This is a different filter from the one branch_filter_count.c pins: there the
// 512 hits are distinct questions and it is the per-(callstack, address) cap
// that stops them; here the cap never gets a chance, because dedup on the label
// fires first.  Both have to hold for a loop-heavy target to stay tractable.
//
// fgtest keeps no such state and writes an input per hit, all 1024 identical in
// content -- which is what makes the z3 arm's single file a filter rather than
// a property of the program.
//
// KO_DONT_OPTIMIZE=1 is load-bearing: at -O3 the compare is loop-invariant, gets
// hoisted out, and is reached once.  Both arms then emit one file and the test
// asserts nothing.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'A'*4)" > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG --allow-empty %s
// CHECK-ORIG-NOT: Good
// RUN: env KO_USE_FASTGEN=1 KO_DONT_OPTIMIZE=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out | wc -l | FileCheck --match-full-lines --check-prefix=CHECK-FG-N %s
// CHECK-FG-N: 1024
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: env KO_USE_Z3=1 KO_DONT_OPTIMIZE=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out | wc -l | FileCheck --match-full-lines --check-prefix=CHECK-Z3-N %s
// CHECK-Z3-N: 1
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint32_t x;
  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(&x, 1, sizeof(x), fp);
  for (int i = 0; i < 1024; i++) {
    if (x == 0xdeadbeef) {
      // The one answer has to satisfy every iteration at once, so a passing
      // input prints all 1024 lines, not just the first.
      // CHECK-GEN: Good0
      // CHECK-GEN: Good1023
      printf("Good%d\n", i);
    }
  }
  fclose(fp);
}
