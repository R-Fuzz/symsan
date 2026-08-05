// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\xff\xff\xff\x01\x00\x00\x00')" > %t.bin
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env SYMSAN_PARSE_ONLY=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin | FileCheck %s --check-prefix=PARSE
//
// Every condition the shift checks build here has to be false at the recorded
// values, because __taint_trace_cond(cond, 0, ...) means "this is false, make
// it true".  A check whose guard reads the operand's sign at 64 bits instead of
// at its own width emits one that is already true, and z3-ts rejects it as
// `value mismatch for cond`.
// PARSE: PARSE-SUMMARY conds=1 ok=1 empty=0 failed=0

// The base is already negative *at i32* (0xFFFFFF00 == -256) while
// (int64_t)0x00000000FFFFFF00 is positive, which is what the shift-base guard
// used to test.  The shift amount is symbolic too, since the whole shift block
// is gated on the exponent being symbolic.
//
// The one surviving condition is the exponent check, `amt >=u 32`.  Both base
// checks correctly stay silent: the base is negative already (shift-base is
// true, nothing to solve for) and it has no leading zeros left to shift off
// past amt=1 (shift-overflow likewise).
//
// This used to read conds=2.  The second one was a separate `amt <s 0` task for
// the same cid 3, which is redundant -- a negative i32 is >=u 32 as an unsigned
// number, so every model of it already satisfies the check above.  It is gone
// with the exponent-check dedup; see ubsan_shift_negexp.c.  At HEAD this test
// reports conds=3 ok=2 failed=1, the failure being the shift-base check the
// 64-bit sign read wrongly let through.

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
  int32_t base = 0, amt = 0;

  chk_fread(&base, sizeof(base), 1, fp);
  chk_fread(&amt, sizeof(amt), 1, fp);
  fclose(fp);

  return (base << amt) & 1;
}
