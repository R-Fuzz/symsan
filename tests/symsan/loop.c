// A branch inside a loop stays solvable across iterations.
//
// The scan below breaks on the first '\n', so a single static branch decides
// `len`.  Reaching `len == 15` means driving that one branch the other way on
// the sixteenth iteration specifically: a solver that writes the branch off as
// "already flipped" after iteration 0 produces the first fifteen answers and
// never the one that matters.  The same property at the session level, where
// the fuzzer's hit counts are what keep iterations apart, is in
// bindings/rust/symsan/tests/loop_coverage.rs.
//
// KO_DONT_OPTIMIZE=1 is load-bearing, not tidiness: at -O3 clang vectorizes the
// scan into a 16-byte compare, the per-byte branch stops existing, and the
// trace has nothing left to solve.
//
// The output dir is wiped between the two arms so neither can pass on the
// other's leftovers -- the file names collide, and how far each arm gets is
// exactly what is under test.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 KO_DONT_OPTIMIZE=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-15 | FileCheck --check-prefix=CHECK-GEN %s
//
// The in-process z3 runtime caps one (callstack, address) at MAX_BRANCH_COUNT
// = 16 solves per run (solvers/z3.cpp), so it stops at id-0-0-15 -- the answer
// wanted here is the last one it is willing to produce.  Lower that cap and
// this arm goes quiet; that is the cap being pinned, not an accident to route
// around.
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: env KO_USE_Z3=1 KO_DONT_OPTIMIZE=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-15 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[20];
  FILE* fp = chk_fopen(argv[1], "rb");
  fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  int len = 0;

  for (len = 0; len < sizeof(buf); len++) {
    if (buf[len] == '\n') {
      break;
    }
  }
  if (len == 15) {
    // CHECK-GEN: Good
    printf("Good\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }
}
