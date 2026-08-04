// String-theory: plant a delimiter at a PINNED offset in a fully-filled buffer.
//
// Baseline for strchr_plant_gap.c. Here the input fills the buffer with
// non-zero bytes, so strlen() sees the whole object and the solver can place
// '"' at offset 4 with an in-place SET. This case already works; it exists so
// the gap test isolates the strlen-truncation as the single difference.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python3 -c "import sys; sys.stdout.buffer.write(b'A'*16)" > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
//
// The RGD path is a separate solver stack -- afltest runs i2s/jigsaw/z3 over
// parsers/rgd-parser.cpp, fgtest runs solvers/z3-ts.cpp -- and only the RGD one
// is what a fuzzer executes.  Its own arm, and the reason this test needs one
// even though the fgtest arm above already passes: i2s solved the conjunction's
// two constraints independently, so the "found" clause planted a needle at 0
// and the "found at 4" clause planted a second one at 4, and strchr reported
// the first.  It generated an input and still printed "no delimiter at 4".
// Own output directory, because both stacks write id-0-0-0.
// RUN: rm -rf %t.rgd.out
// RUN: mkdir -p %t.rgd.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.rgd.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[64] = {0};
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    return -1;
  }
  size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
  fclose(fp);
  buf[n] = '\0';

  // Solver must plant '"' at exactly offset 4 (first occurrence).
  char *p = strchr(buf, '"');
  if (p && (p - buf) == 4) {
    // CHECK-GEN: PLANTED at 4
    printf("PLANTED at 4\n");
  } else {
    // CHECK-ORIG: no delimiter at 4
    printf("no delimiter at 4\n");
  }
  return 0;
}
