// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x05\x00\x00\x00\x00\x00\x00\x00')" > %t.bin
// RUN: clang -O0 -fsanitize=unsigned-integer-overflow -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-1 2>&1 | FileCheck %s --check-prefix=UNDER
// UNDER: runtime error: unsigned integer overflow

// Subtraction's unsigned-underflow guard read `result <= orig_op1 &&
// orig_op2 != 0`.  Addition's twin guard is `... && (orig_op2 != 0 || l2 != 0)`
// -- the second arm is there because a symbolic operand that happens to be 0 at
// this seed is precisely the one worth solving for.  Sub never had it, so with
// b == 0 the unsigned check was skipped entirely and only the signed one
// produced an input.
//
// Two ids therefore have to exist, and it is the second that matters: id-0-0-1
// is the unsigned check's answer, and it has to make a - b actually wrap.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return 0;
  }

  FILE* fp = chk_fopen(argv[1], "rb");
  uint32_t a = 0, b = 0;

  chk_fread(&a, sizeof(a), 1, fp);
  chk_fread(&b, sizeof(b), 1, fp);
  fclose(fp);

  uint32_t result = a - b;
  printf("%u\n", result);
  return 0;
}
