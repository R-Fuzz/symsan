// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\xc8\x00\x00\x00\x00\x00\x00\x00')" > %t.bin
// RUN: clang -O0 -fsanitize=signed-integer-overflow,unsigned-integer-overflow -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 | FileCheck %s --check-prefix=OVFL
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-1 2>&1 | FileCheck %s --check-prefix=OVFL
// OVFL: runtime error: unsigned integer overflow
// OVFL: SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior
//
// Both ids matter: the runtime emits a signed and an unsigned check per
// multiply, and the second one is the one this seed used to lose entirely.

// ubsan_mulovfl.c seeds a=2, b=3, which every formula gets right.  This is the
// seed that separates them: b == 0, so the product is 0 and there is no
// overflow of either signedness to report yet.
//
// The old unsigned model was `result <u op1`, borrowed from addition.  At this
// seed that is `0 <u 200`, which is *already true* -- the runtime asserted it
// was false and asked a solver to satisfy it, so the whole unsigned check was
// dropped and only the signed one produced an input.  It was also wrong in the
// other direction: 2 * 0x80000001 wraps to 2 at 32 bits, and `2 <u 2` is false,
// so real overflows went unreported.  Both are now done by multiplying at twice
// the width and asking whether the product fits, which needs *both* ids below
// to exist and to trigger their own kind of overflow.

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

  uint32_t result = a * b;
  printf("%u\n", result);
  return 0;
}
