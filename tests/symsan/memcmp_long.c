// A memcmp longer than 64 bytes.
//
// dfsan_label_info::size is a bit width for everything the instrumentation
// emits and a *byte* count for the memory-comparison ops the libc wrappers
// build.  __taint_union's two wide-operand guards read it as a width, so every
// memcmp of more than 64 bytes used to be declined as if it were a 65-bit
// operation and never reached a solver at all -- silently, since a dropped
// shadow looks exactly like an untainted buffer.  64 passes either way, which
// is why both lengths are here: the pair is the regression, not the long one.
//
// The needle is 96 distinct nonzero bytes, so a generated input has to carry
// the whole compared extent to satisfy the uninstrumented binary.  That is also
// the content round-trip check -- the bytes come over the wire in the memcmp
// record's payload rather than in op1/op2, which hold only the first 8.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python3 -c 'print("A"*96)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin 64 | FileCheck --check-prefix=CHECK-ORIG %s

// 64 bytes: the boundary that worked before, kept so the pair reads as one
// test.  65 is the first length the width gate used to swallow.
// RUN: env KO_USE_FASTGEN=1 %ko-clang -DN=64 -o %t.fg64 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg64 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 64 | FileCheck --check-prefix=CHECK-GEN %s

// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env KO_USE_FASTGEN=1 %ko-clang -DN=65 -o %t.fg65 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg65 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 65 | FileCheck --check-prefix=CHECK-GEN %s

// Well past the boundary, so a fix that only moved it shows up here.
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env KO_USE_FASTGEN=1 %ko-clang -DN=96 -o %t.fg96 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg96 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 96 | FileCheck --check-prefix=CHECK-GEN %s

// The z3 arm, which builds the same record through a different backend.
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -DN=65 -o %t.z365 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z365 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 65 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

#ifndef N
#define N 65
#endif

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file] [n]\n", argv[0]);
    return -1;
  }

  // The uninstrumented build is run at each of the three lengths, so it takes
  // the length on the command line; the instrumented builds are compiled one
  // per length, because N has to be a constant the wrapper can see.
  size_t n = N;
  if (argc > 2) n = (size_t)atoi(argv[2]);

  char buf[96];
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  // 96 distinct nonzero bytes.  Nonzero because a zero needle is satisfied by
  // a short read, and distinct so that no prefix of the answer can stand in
  // for the rest of it.
  char needle[96];
  for (size_t i = 0; i < sizeof(needle); i++)
    needle[i] = (char)(i + 1);

  if (memcmp(buf, needle, n) == 0) {
    // CHECK-GEN: Good
    printf("Good\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }
}
