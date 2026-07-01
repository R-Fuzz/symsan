// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("AABB"*10)' > %t.bin
// RUN: clang++ -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang++ -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
// NOTE: fastgen only (like the other cpp_* tests).  In-process Z3 is not used
// for C++ because the Z3 C++ API pulls in the instrumented libc++ and can loop.

// Symbolic propagation across C++ exception handling.
//
// The symbolic input value is thrown and re-acquired in a catch clause, so the
// symbolic expression must survive the whole EH path
// (__cxa_allocate_exception -> __cxa_throw -> unwind -> __cxa_begin_catch) and
// land in the catch parameter.  The branch below is only solvable if `caught`
// still carries the symbolic expression of the input; if EH drops the label the
// solver cannot flip the branch and the generated input stays "Bad".
//
// The exception runtime (__cxa_* / personality / unwinder) must run concretely:
// EH is a coupled subsystem and instrumenting any of it breaks the unwind, so a
// throw never reaches its catch.  This is handled by the build, not the test:
// the EH entry points are marked uninstrumented in done_abilist.txt, and
// ko_clang links the plain libc++abi-native/libunwind-native (see
// rebuild_native.sh).  The symbolic value still propagates through the concrete
// EH runtime via address-keyed shadow memory, so the branch is solvable.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int __attribute__((noinline)) thrower(int32_t y) {
  throw y;
  return 0;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[20];
  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  int32_t x = 0;
  memcpy(&x, buf + 1, 4); // x is bytes 1..4 of the input

  int32_t caught = -1;
  try {
    thrower(x);
  } catch (int e) {
    caught = e; // must carry x's symbolic expression
  }

  // caught == x, and caught*caught - 6*caught == -8 has integer roots 2 and 4.
  if (caught * caught - 6 * caught == -8) {
    // CHECK-GEN: Good
    printf("Good\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }
}
