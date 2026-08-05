// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x05\x00\x00\x00')" > %t.bin
// RUN: clang -O0 -fsanitize=implicit-integer-truncation -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-2 2>&1 | FileCheck %s
// CHECK: runtime error: implicit conversion from type 'int32_t' (aka 'int') of value 128

// The signed-truncation check only ever asked half the question.  It was
//
//   old_value <s signed(1 << (size - 1))      // x <s INT8_MIN
//
// which is the below-minimum half alone.  (int8_t)300 is signed-truncation UB
// just as much as (int8_t)-300 is, and the check could not express it.  clang
// uses one comparison for the whole range: sext(trunc(x)) == x is valid, so
// lossy iff they differ (EmitIntegerTruncationCheckHelper, CGExprScalar.cpp).
//
// Masking to 0x1FF is what makes the difference observable rather than merely
// argued.  m is then in [0, 511], so the old below-minimum condition `m <s
// -128` is unsatisfiable and yields no input at all, while the re-extend form
// is satisfiable exactly on [128, 255] and [384, 511] -- the above-maximum
// range the old shape could not reach.  Without the mask both forms produce
// *an* input and the test would pass either way; a plain negative seed is
// already covered by ubsan_trunc_negative.c.
//
// So three of the three checks on this conversion solve (cid 13 unsigned
// truncation, cid 14 signed truncation, cid 15 sign change) where two did
// before, and id-0-0-2 exists only with the fix.

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
  int32_t x = 0;

  chk_fread(&x, sizeof(x), 1, fp);
  fclose(fp);

  int32_t m = x & 0x1FF;
  // implicit, not a cast: -fsanitize=implicit-integer-truncation deliberately
  // ignores explicit casts, so an (int8_t) here would make the oracle silent
  int8_t a = m;
  printf("%d\n", a);
  return 0;
}
