// The ubsan overflow model is 64-bit arithmetic, and at 128 bits it is skipped.
//
// All the modeling in __taint_union builds masks as (1UL << size) - 1 and sign
// bits as 1ULL << (size - 1).  Once an operand can be wider than 64 bits those
// shifts are undefined, and on x86 the shift count is masked -- so a 128-bit
// Add computes mask == 0 and sign_bit == 1ULL << 63.  That garbage is not a
// missing check.  It is handed straight to __taint_trace_cond as a real branch
// constraint, and the specific damage is subtle enough to be worth writing
// down: the symbolic formula ((l1 ^ r) & (l2 ^ r)) <s 0 that gets built is
// actually width-correct, but `has_signed_overflow` -- computed from the
// garbage concretes -- is then permanently false, so an add that ALREADY
// overflowed is reported as not-taken.  That is a wrong claim about the trace,
// and it poisons the nested path constraint rather than just missing a bug.
// The runtime's own do_taint_union calls bypass __taint_union's wide-operand
// gate, so this needed its own width check (ub_width_ok in dfsan.cpp).
//
// Both operand widths are checked, not just the result's: a Trunc from i128 to
// i64 has size == 64 and would still evaluate 1UL << size against a value it
// only holds the low half of.
//
// The same source is built twice so the wide arm cannot pass vacuously.  A
// broken harness -- solve_ub silently off, the wrong instrumentation flags, an
// unreadable seed -- produces "no solutions" for the wide arm too, and the
// narrow arm is what tells those apart from a working decline.  The narrow arm
// must both produce inputs and produce one that ubsan agrees overflows.
//
// If the modeling is later made width-correct (unsigned __int128 concretes in
// the Add/Sub/Mul cases, which is worth doing -- ungated, this shape does find
// a genuine 128-bit overflow), the wide arm here is what must change.  That is
// intended: a decline should be pinned so that removing it is a deliberate act.
//
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00'*16 + b'\x01' + b'\x00'*15)" > %t.bin
//
// narrow control: the model still works at 64 bits and finds a real overflow
// RUN: rm -rf %t.narrow.out && mkdir -p %t.narrow.out
// RUN: clang -O0 -fsanitize=signed-integer-overflow -o %t.narrow.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.narrow.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.narrow.out solve_ub=1" %fgtest %t.narrow.fg %t.bin
// RUN: ls %t.narrow.out | FileCheck --check-prefix=CHECK-SOL %s
// RUN: ls %t.narrow.out/* | xargs -n1 env UBSAN_OPTIONS=print_summary=0 %t.narrow.ubsan 2>&1 | FileCheck --check-prefix=CHECK-OVFL %s
//
// wide arm: no UB task at all
// RUN: rm -rf %t.wide.out && mkdir -p %t.wide.out
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -DWIDE=1 -o %t.wide.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.wide.out solve_ub=1" %fgtest %t.wide.fg %t.bin
// RUN: ls %t.wide.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

#ifdef WIDE
typedef __int128 T;
#else
typedef int64_t T;
#endif

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  T a = 0, b = 0;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&a, 1, sizeof(a), fp);
  chk_fread(&b, 1, sizeof(b), fp);
  fclose(fp);

  // seed is a = 0, b = 1: no overflow yet, so the model emits the "can this
  // overflow?" constraint rather than reporting an event
  T r = a + b;
  printf("%d\n", (int)r);
  return 0;
}

// CHECK-SOL: id-
// CHECK-OVFL: runtime error: signed integer overflow
// CHECK-NOSOL-NOT: id-
