// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x03\x00\x00\x00')" > %t.bin
// RUN: clang -O0 -fsanitize=array-bounds -o %t.ubsan %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 | FileCheck %s --check-prefix=UNDER
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-1 2>&1 | FileCheck %s --check-prefix=OVER
// UNDER: runtime error: index -{{[0-9]+}} out of bounds for type 'int[16]'
// OVER: runtime error: index {{[0-9]+}} out of bounds for type 'int[16]'

// The rest of the ubsan_* suite covers the arithmetic checks, cids 1-5 and
// 13-15.  Nothing covered __taint_solve_bounds / __taint_solve_size, cids 6-12,
// which is where the dfsan.cpp:1144 label-vs-value mixup lived: a uint64_t size
// was assigned into a dfsan_label, so the comparison got built over whatever
// unrelated expression happened to have that label id.  z3-ts caught it as a
// value mismatch, but RGD has no value check and solved the wrong formula
// silently, so a target-level test is the only thing that would have.
//
// This is the num_elems > 0 arm (bvslt / bvsge against a statically known
// count) -- the arm libpng never reaches, since it only ever takes the
// concrete-alloca path.  The two ids below are the underflow and the overflow
// condition, in the order the runtime emits them.

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
  int32_t idx = 0;

  chk_fread(&idx, sizeof(idx), 1, fp);
  fclose(fp);

  int table[16] = {0};
  for (int i = 0; i < 16; i++) table[i] = i;

  // seed index is 3, in bounds; the solver has to reach either end
  return table[idx] & 1;
}
