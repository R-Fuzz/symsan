// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x04\x00\x00\x00')" > %t.bin
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env SYMSAN_PARSE_ONLY=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin | FileCheck %s --check-prefix=PARSE
// PARSE: PARSE-SUMMARY conds=2 ok=2 empty=0 failed=0

// __taint_solve_size's cid 8, on an *interior* pointer -- which is the only
// interesting case, and the one that was always wrong.
//
//   uint64_t min_size = bounds_info->op1.i - ptr;   // lower_bound - ptr
//   size <u min_size                                // "underflow"
//
// Any pointer derived from the allocation has ptr >= lower_bound, so that
// subtraction wraps and min_size is near 2^64: `n <u huge` is true for every n,
// on every interior pointer, forever.  At ptr == lower_bound it is `n <u 0`
// instead -- false for every n, and unsatisfiable rather than inconsistent,
// which is why a base pointer never showed the bug.  The literal below is
// exactly that case; buf + 8 is the one that broke.
//
// This is why the check is on empty and not just failed.  A condition that is
// direction-inconsistent usually reaches parse_cond's root value check and is
// rejected as `value mismatch for cond`, which counts as failed.  This one does
// not get that far: n is a ZExt of 32 bits, so z3 folds `n <u 2^64-8` to true
// while simplifying and the task is dropped as a `constant condition` -- both
// cid-8 conditions land in empty, and failed stays 0.  Asserting the exact
// counts is what makes the test see it at all.
//
// The check now only fires when ptr < lower_bound, the case the original
// comment already said "shouldn't happen in valid code" -- where it is the one
// thing the condition can honestly mean.  cid 9 (`n >u upper_bound - ptr`, 56
// here) stays and is the positive control: n is 4, so it parses and is false.
//
// bcmp, not strncmp or memcmp: __dfsw_bcmp is the only wrapper that calls
// __taint_solve_size (dfsan_custom.cpp), and at -O0 clang does not rewrite
// memcmp into it.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "lib.h"

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return 0;
  }

  FILE* fp = chk_fopen(argv[1], "rb");
  uint32_t n = 0;

  chk_fread(&n, sizeof(n), 1, fp);
  fclose(fp);

  char *buf = malloc(64);
  memset(buf, 'A', 64);

  // buf + 8 is 8 bytes above the lower bound, so lower_bound - ptr wraps
  if (bcmp(buf + 8, "AAAA", n) == 0) printf("eq\n");
  free(buf);
  return 0;
}
