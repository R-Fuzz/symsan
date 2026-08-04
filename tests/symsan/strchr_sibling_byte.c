// String-theory: a strchr index constraint conjoined with a direct byte
// constraint on the SAME buffer must be solved consistently.
//
// We require BOTH:
//   strchr(buf,'@') - buf == 3   (i.e. buf[3]=='@', buf[0..2] != '@')
//   buf[2] == 'Z'
// A trivial solution exists: "AAZ@" (or "B0Z@", etc).
//
// The haystack string variable (input offsets 0..3) and the per-byte scalar
// variable (offset 2) OVERLAP; the solver links them (string<->bitvec linking
// constraints) so the indexof model and the scalar byte model agree, instead of
// returning a model where they disagree.
//
// The seed plants '@' off-target (at offset 2) so that strchr finds it and the
// conjunction branch (p && (p-buf)==3 && buf[2]=='Z') is actually reached. With
// a seed lacking '@' that branch is never executed (strchr short-circuits).
// fgtest flips the leading `p != NULL` null-check first (id-0-0-0, the
// not-found counterfactual -> "miss"); the conjunction flip is id-0-0-1, which
// must satisfy both constraints and print HIT.
//
// Direct strchr planting alone works (see strchr_plant_filled/gap.c); this test
// covers the conjunction with an overlapping scalar byte constraint.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python3 -c "import sys; sys.stdout.buffer.write(b'AA@A')" > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN %s
//
// The RGD path is a separate solver stack -- afltest runs i2s/jigsaw/z3 over
// parsers/rgd-parser.cpp, fgtest runs solvers/z3-ts.cpp -- and only the RGD one
// is what a fuzzer executes.  It has no string theory and no linking
// constraints; i2s reaches the same answer by rewriting the bytes it can see,
// which are the same bytes the scalar `buf[2] == 'Z'` clause reads, so the two
// clauses agree by construction rather than by a linking constraint.  Same
// id-0-0-1 as the fgtest arm: id-0-0-0 is the not-found counterfactual there
// too.  Own output directory, because both stacks write id-0-0-0.
// RUN: rm -rf %t.rgd.out
// RUN: mkdir -p %t.rgd.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.rgd.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN %s

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

  char *p = strchr(buf, '@');
  if (p && (p - buf) == 3 && buf[2] == 'Z') {
    // CHECK-GEN: HIT
    printf("HIT\n");
  } else {
    // CHECK-ORIG: miss
    printf("miss\n");
  }
  return 0;
}
