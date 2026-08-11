// The same gap as tests/symsan/bitreverse.c, reached the way it is reached in
// the wild: nobody writes __builtin_bitreverse8, they write the bit-serial
// reflection loop below, and clang's idiom recognizer turns it into
// @llvm.bitreverse.i8.  ko-clang optimizes regardless of the -O flag on the
// command line, so the substitution happens here at every level -- there is no
// build of this file in which the loop survives as loop.
//
// That is what makes the gap dangerous rather than obscure.  reflect() is the
// shape every reflected CRC starts with (CRC-32, CRC-16), and before the
// bitreverse op existed the shadow died at the intrinsic, the message went
// concrete, and a checksum guard downstream looked like a guard on nothing.
//
// Two guards, one per reach:
//
//   Good  -- one reflected byte against a constant.  Every rung of the ladder
//            inverts this, so all five configurations below assert it.
//   Great -- four reflected bytes shifted and or'd into a u32.  Only z3 gets
//            this one; i2s cannot push a target down the assembly chain, and
//            the assembled value is a flat plateau for jigsaw's gradient
//            descent (bit reversal makes value distance meaningless).  The
//            single-byte form solves under both, so the split is about the
//            assembly, not about bitreverse.  Deliberately NOT asserted absent
//            on the i2s and jigsaw arms -- if either learns the shape, this
//            test should not be what stops it.
//
// RUN: python -c'import sys; sys.stdout.buffer.write(b"A"*4)' > %t.bin
// RUN: clang -O3 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-BOTH %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-BOTH %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_Z3=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-BOTH %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-BYTE %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_JIGSAW=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-BYTE %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

// Reorder the bits of a byte by reflecting them about the middle position --
// the reflect() of crc.c, narrowed to the width that CRC-32 and CRC-16 use.
static uint8_t reflect8(uint8_t data) {
  uint8_t reflection = 0;

  for (int bit = 0; bit < 8; ++bit) {
    if (data & 1) {
      reflection |= (uint8_t)(1u << (7 - bit));
    }
    data >>= 1;
  }

  return reflection;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t buf[4];
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  if (reflect8(buf[0]) == 0x1e) {
    // CHECK-BOTH-DAG: Good
    // CHECK-BYTE: Good
    printf("Good\n");
  }

  uint32_t v = 0;
  for (int i = 0; i < 4; ++i) {
    v = (v << 8) | reflect8(buf[i]);
  }
  if (v == 0x12345678u) {
    // CHECK-BOTH-DAG: Great
    printf("Great\n");
  }

  // unconditional, so the seed run has something to match and no extra
  // symbolic branch is introduced
  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}
