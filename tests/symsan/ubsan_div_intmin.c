// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x05\x00\x00\x00\x03\x00\x00\x00')" > %t.bin
// RUN: clang -O0 -fsanitize=signed-integer-overflow,integer-divide-by-zero -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env SYMSAN_PARSE_ONLY=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin | FileCheck %s --check-prefix=PARSE
// PARSE: PARSE-SUMMARY conds=2 ok=2 empty=0 failed=0
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 | FileCheck %s --check-prefix=CHECK-DIV0
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-1 2>&1 | FileCheck %s --check-prefix=CHECK-OVFL
// CHECK-DIV0: runtime error: division by zero
// CHECK-OVFL: runtime error: division of -2147483648 by -1 cannot be represented in type

// A signed division has two ways to be undefined, and only one of them was
// modelled.  clang emits both from a single place --
// EmitUndefinedBehaviorIntegerDivAndRemCheck in CGExprScalar.cpp -- where the
// valid condition is `op2 != 0` AND `op1 != INT_MIN || op2 != -1`.  The runtime
// had the first and not the second, so INT_MIN / -1 was never asked for on any
// target.
//
// The UB to solve for is the negation of that second clause, i.e. the
// conjunction `op1 == INT_MIN && op2 == -1`.  Unlike Add/Sub/Mul there is no
// signedness to infer here: SDiv and SRem are distinct dfsan opcodes, so the
// site already knows, which is why this one needed no instrumentation change.
//
// Two inputs, in the order the checks are emitted: the divide-by-zero task
// first, then the overflow one.  With the overflow check missing there is no
// id-0-0-1 at all and the second RUN line fails on the missing file.

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
  int32_t a = 0, b = 0;

  chk_fread(&a, sizeof(a), 1, fp);
  chk_fread(&b, sizeof(b), 1, fp);
  fclose(fp);

  // 5 / 3 at the seed: neither undefined, so both checks are consistent
  printf("%d\n", a / b);
  return 0;
}
