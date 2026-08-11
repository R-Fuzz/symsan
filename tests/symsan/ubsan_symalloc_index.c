// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x40\x00\x00\x00\x03\x00\x00\x00')" > %t.bin
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env SYMSAN_PARSE_ONLY=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin | FileCheck %s --check-prefix=PARSE
// PARSE: PARSE-SUMMARY conds=3 ok=3 empty=0 failed=0

// __taint_solve_bounds's symbolic-allocation arm, cid 11.  This is the one the
// audit started from:
//
//   size_label = offset == 0 ? size : do_taint_union(size_label, ...);
//
// `size` is a uint64_t byte count, not a label.  When offset == 0 -- an index
// off the base of the allocation, which is the common case -- it was assigned
// straight into a dfsan_label, naming whatever unrelated expression happens to
// hold that id.  The comparison then got built over someone else's AST while
// still carrying this site's recorded value, so z3-ts rejects it as `value
// mismatch for ICmp`.
//
// Both halves have to be symbolic to reach the arm at all: a symbolic malloc
// size makes bounds_info->l2 nonzero, and a symbolic index is what there is to
// solve.  idx is 3 so the mis-assigned label id is a real, populated one --
// with idx 0 the bug degenerates to label 0 and hides.

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
  uint32_t n = 0, idx = 0;

  chk_fread(&n, sizeof(n), 1, fp);
  chk_fread(&idx, sizeof(idx), 1, fp);
  fclose(fp);

  if (n > 4096) return 0;
  char *buf = malloc(n);
  if (!buf) return 0;

  buf[idx] = 1;
  printf("%d\n", buf[0]);
  free(buf);
  return 0;
}
