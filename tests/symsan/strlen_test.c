// Test: strlen constraints for various length comparisons
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf 'HELLO WORLD' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 KO_DONT_OPTIMIZE=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
//
// The RGD path is a separate solver stack -- afltest runs i2s/jigsaw/z3 over
// parsers/rgd-parser.cpp, fgtest runs solvers/z3-ts.cpp -- and only the RGD one
// is what a fuzzer executes.  All three lengths are reached there too, but by a
// different edit, so in a different order: z3-ts answers the two inequalities
// by shrinking the FILE to zero bytes (id-0-0-0 and id-0-0-2 above are both
// empty, both printing strlen = 0), while i2s keeps every byte and plants a NUL
// at the position the length has to be.  It lands on the LARGEST length each
// predicate allows -- 10, then 5, then 2 -- because that is the fewest bytes
// disturbed, and the bytes it leaves alone are what a sibling constraint in the
// same conjunction reads.
// CHECK-RGD0: strlen = 10
// RUN: rm -rf %t.rgd.out
// RUN: mkdir -p %t.rgd.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.rgd.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-0 | FileCheck --check-prefix=CHECK-RGD0 %s
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN1 %s

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return 1;
  }

  char buf[64];
  FILE *f = fopen(argv[1], "r");
  if (!f) {
    perror("fopen");
    return 1;
  }
  size_t n = fread(buf, 1, 63, f);
  buf[n] = '\0';
  fclose(f);

  size_t len = strlen(buf);
  printf("strlen = %zu\n", len);

  if (len > 10) {
    // CHECK-ORIG: Long string
    printf("Long string (> 10)!\n");
  }
  if (len == 5) {
    // CHECK-GEN2: Exact length 5
    printf("Exact length 5!\n");
  }
  if (len < 3) {
    // CHECK-GEN1: Short string
    printf("Short string (< 3)!\n");
  }
  return 0;
}
