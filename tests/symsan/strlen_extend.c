// Test strlen extending - input needs to grow to reach target length
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf 'short\0' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
//
// The RGD path (afltest = i2s/jigsaw/z3 over parsers/rgd-parser.cpp; the
// %fgtest arm above is solvers/z3-ts.cpp) reaches this too, and by the only edit
// that can: i2s cannot write a byte the file does not have, so it INSERTS the
// ten it needs.  They go in just before the terminator, which is what the second
// check is for -- "short" has to survive intact at the front and the filler has
// to land behind it.  A grow that wrote over the string, or one that appended
// past the NUL where strlen would never see it, would both still count as "an
// input was generated", so the length alone is not enough of an assertion.
// CHECK-RGD-FILE: shortAAAAAAAAAA
// RUN: rm -rf %t.rgd.out
// RUN: mkdir -p %t.rgd.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.rgd.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
// RUN: FileCheck --check-prefix=CHECK-RGD-FILE %s < %t.rgd.out/id-0-0-0

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) return 1;

  char buf[64];
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;

  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);

  size_t len = strlen(buf);
  printf("strlen: %zu\n", len);

  if (len == 15) {
    // CHECK-GEN: SUCCESS
    printf("SUCCESS: strlen == 15\n");
  } else {
    // CHECK-ORIG: NOT-15
    printf("NOT-15: strlen = %zu\n", len);
  }

  return 0;
}
