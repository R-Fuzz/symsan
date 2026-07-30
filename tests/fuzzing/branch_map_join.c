// Do SymSan and the fuzzer name the same branches?
//
// SymSan calls a branch by a hash of its source location; AFL++ calls an edge
// by a sequential integer.  patches/aflpp-document-ids.patch makes AFL++ export
// the source location of each edge, include/branch_map.h joins the two, and
// SharedMapCovManager uses the join to skip branches the fuzzer already
// covered.  If the join is wrong, nothing fails: SymSan just quietly stops
// solving things, and the only symptom is finding less.
//
// So the join needs its own test.  This builds the same source twice -- once
// with ko-clang, once with the fuzzer's afl-clang-lto -- runs afl-showmap on
// the fuzzer's build to get ground truth, and has covcheck confirm that every
// branch direction the SymSan trace took resolves to an edge afl-showmap saw.
//
// The second half is the one that would catch a regression: with a deliberately
// wrong map the same run has to come out INCONSISTENT.  Without it, a check
// that vacuously passes would look identical.
//
// REQUIRES: aflpp
//
// RUN: rm -f %t.map %t.wrong.map
// RUN: env KO_USE_FASTGEN=1 %ko-clang -g -o %t.symsan %s
// RUN: env AFL_LLVM_DOCUMENT_IDS=%t.map %afl-clang-lto -g -o %t.afl %s
// RUN: python -c"import sys; sys.stdout.buffer.write(b'ABCDEFGH')" > %t.bin
// RUN: %afl-showmap -o %t.showmap -- %t.afl %t.bin
// RUN: %covcheck -m %t.map -c %t.showmap -i %t.bin -- %t.symsan @@ | FileCheck %s
//
// Some directions are unmapped -- AFL++ prunes blocks that dominate their
// successors, so not every branch direction gets an edge id -- but the ones it
// does map must be right.
// CHECK: violations: 0
// CHECK: ambiguous-violations: 0
// CHECK: verdict: consistent
//
// Now point every entry at an edge id past the end of the map, so the join is
// wrong in the way that matters, and check that this is noticed.
// RUN: sed 's/edgeID=[0-9]*/edgeID=65535/' %t.map > %t.wrong.map
// RUN: not %covcheck -m %t.wrong.map -c %t.showmap -i %t.bin -- %t.symsan @@ | FileCheck %s --check-prefix=WRONG
// WRONG: verdict: INCONSISTENT

// Deliberately plain C -- no lib.h -- because afl-clang-lto has to compile it
// too, and it has none of the SymSan harness.  Two nested comparisons on
// separate input words, so the trace has more than one direction to check.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <file>\n", argv[0]);
    return -1;
  }

  unsigned char buf[16];
  memset(buf, 0, sizeof(buf));

  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    perror("fopen");
    return -1;
  }
  size_t n = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  if (n < 8) return -1;

  uint32_t x = 0, y = 0;
  memcpy(&x, buf + 0, 4);
  memcpy(&y, buf + 4, 4);

  if (x == 0xdeadbeefu) {
    if (y == 0x12345678u) {
      printf("Good\n");
      return 2;
    }
    printf("Halfway\n");
    return 1;
  }

  printf("Bad\n");
  return 0;
}
