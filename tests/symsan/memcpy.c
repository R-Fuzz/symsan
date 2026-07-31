// Shadow survives a memcpy, and the element a symbolic index selects is still
// symbolic on the other side of it.
//
// `copy` is never read from the file; everything it knows comes from `buf`
// through memcpy's shadow copy.  The index is symbolic too, so getting to
// "Good" needs both halves: the load has to resolve to `copy[3]`, and the four
// bytes behind `copy[3]` -- file offsets 16..19, not 12..15, because `index`
// occupies the first word -- have to be driven to 0xdeadbeef.
//
// The bounds branch above it is why the first answer of each arm is not the
// interesting one: `index >= sizeof(buf)` is a comparison against a symbolic
// index, so flipping it is the first thing either arm reports, and that input
// exits with -1 and prints nothing.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x03\x00\x00\x00' + b'\xaa\xbb\xcc\xdd'*100)" > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN %s
//
// The in-process z3 runtime additionally enumerates the symbolic GEP index over
// the whole array before it gets to the compare, so the same answer lands 99
// files later: one bounds flip, 99 alternatives to `index`, then the compare.
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-100 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return 0;
  }

  FILE *fp = chk_fopen(argv[1], "rb");
  int index = 0;
  int buf[100];
  int copy[100];

  chk_fread(&index, 1, sizeof(index), fp);
  chk_fread(buf, sizeof(buf), 1, fp);
  fclose(fp);

  memcpy(copy, buf, sizeof(buf));

  if (index >= sizeof(buf)) {
    return -1;
  }

  if (copy[index] == 0xdeadbeef) {
    // CHECK-GEN: Good
    printf("Good\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }
}
