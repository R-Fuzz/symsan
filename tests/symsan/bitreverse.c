// llvm.bitreverse has to propagate taint, at every width.
//
// TaintPass used to handle llvm.bswap and nothing else in that family, so a
// bitreverse dropped its shadow and everything downstream of it went silently
// concrete -- no crash, no warning, just a branch the session never sees.  It
// is now a dfsan op of its own (__dfsan::bitreverse) rather than a
// decomposition into extracts and concats the way bswap is: reversing an i64
// costs 64 Extracts plus 63 Concats per dynamic execution, and the reflection
// loop of a reflected CRC hits it once per message byte.  Each solver expands
// it in whatever form suits it -- z3 as a concat of single-bit extracts, jigsaw
// as the native LLVM intrinsic, i2s by reversing the wanted value, which is
// exact because bit reversal is its own inverse.
//
// Four widths, because the width is what the op node carries and an off-by-one
// there reverses within the wrong window.  Two guards per width, and the shapes
// are not interchangeable:
//
//   GoodN -- an unsigned inequality against a constant.  This is the one that
//            pins the taint gap, and it is written this way ON PURPOSE: an
//            EQUALITY against a constant is folded by instcombine into
//            `icmp eq X, bitreverse(C)`, the intrinsic disappears before
//            TaintPass ever sees it, and the test passes whether or not the
//            shadow is propagated -- i.e. checks nothing.  There is no such
//            fold for icmp ult, so the intrinsic survives every -O level.
//            Solving one means actually inverting the reversal, since the
//            constant side cannot move.
//   OkN    -- an equality against a SECOND tainted value.  Also survives the
//            fold, and it is what pins the solvers' arithmetic: whichever side
//            a solver chooses to move, the replayed input only prints OkN if
//            the value it computed for the reversal is bit-for-bit right.
//
// Every rung of the ladder is exercised on its own: %fgtest and KO_USE_Z3 for
// the two z3 stacks, then %afltest three times -- i2s alone (the default),
// jigsaw alone, and RGD z3 alone.  Jigsaw gets its own expectations: it lands
// every OkN, but only the i8 and i16 inequalities.  Gradient descent steers by
// value distance, and bit reversal scrambles it into a flat plateau, so above
// 16 bits there is no gradient to follow (see the deferred edit-distance search
// idea).  Not asserted absent -- if jigsaw learns the shape, this test should
// not be what stops it.
//
// Replayed as a set rather than by name; what is asserted is which guards get
// satisfied, not the queue order.
//
// The seed's first byte is 0x24 on purpose.  0x24 is one of the sixteen bytes
// that reverse to themselves, which is the worst case for i2s's value-matching
// heuristic: the compared value equals the input byte it came from, so the
// match fires as though the byte were compared directly and the replacement is
// written unreversed.  i2s now refuses the plain value match on a reversed side
// for exactly this reason; with a non-palindromic seed byte the refusal is
// unobservable and Good8/Ok8 pass either way.
//
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x24" + b"A"*29)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-ALL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-ALL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-ALL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_Z3=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-ALL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_JIGSAW=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-JIGSAW %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t  a,  ra;
  uint16_t b,  rb;
  uint32_t c,  rc;
  uint64_t d,  rd;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&a,  1, sizeof(a),  fp);
  chk_fread(&b,  1, sizeof(b),  fp);
  chk_fread(&c,  1, sizeof(c),  fp);
  chk_fread(&d,  1, sizeof(d),  fp);
  chk_fread(&ra, 1, sizeof(ra), fp);
  chk_fread(&rb, 1, sizeof(rb), fp);
  chk_fread(&rc, 1, sizeof(rc), fp);
  chk_fread(&rd, 1, sizeof(rd), fp);
  fclose(fp);

  // the reversal against a fixed bound: only the reversed side can move
  if (__builtin_bitreverse8(a) < 0x10) {
    // CHECK-ALL-DAG: Good8
    // CHECK-JIGSAW-DAG: Good8
    printf("Good8\n");
  }
  if (__builtin_bitreverse16(b) < 0x10) {
    // CHECK-ALL-DAG: Good16
    // CHECK-JIGSAW-DAG: Good16
    printf("Good16\n");
  }
  if (__builtin_bitreverse32(c) < 0x10u) {
    // CHECK-ALL-DAG: Good32
    printf("Good32\n");
  }
  if (__builtin_bitreverse64(d) < 0x10ULL) {
    // CHECK-ALL-DAG: Good64
    printf("Good64\n");
  }

  // the reversal against a second tainted value: either side may move, and the
  // replay only prints if the solver got the reversal exactly right
  if (__builtin_bitreverse8(a) == ra) {
    // CHECK-ALL-DAG: Ok8
    // CHECK-JIGSAW-DAG: Ok8
    printf("Ok8\n");
  }
  if (__builtin_bitreverse16(b) == rb) {
    // CHECK-ALL-DAG: Ok16
    // CHECK-JIGSAW-DAG: Ok16
    printf("Ok16\n");
  }
  if (__builtin_bitreverse32(c) == rc) {
    // CHECK-ALL-DAG: Ok32
    // CHECK-JIGSAW-DAG: Ok32
    printf("Ok32\n");
  }
  if (__builtin_bitreverse64(d) == rd) {
    // CHECK-ALL-DAG: Ok64
    // CHECK-JIGSAW-DAG: Ok64
    printf("Ok64\n");
  }

  // unconditional, so the seed run has something to match and no extra
  // symbolic branch is introduced
  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}
