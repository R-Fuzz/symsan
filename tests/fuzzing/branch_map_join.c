// Does the branch map point at the edges the fuzzer actually walks?
//
// SymSan and the fuzzer now share one branch namespace by construction: a
// single afl-clang-lto link yields both the coverage binary and the merged
// AFL++-instrumented module the concolic binary is built from, so a branch's
// SymSan id *is* one of AFL++'s edge ids and there is no join left to get
// wrong.  What still has to be right is the map TaintPass writes beside it --
// which edge each side of each branch reaches -- because SharedMapCovManager
// reads it to decide whether flipping a branch would show the fuzzer anything
// new.  If it is wrong, nothing fails: SymSan just quietly stops solving
// things, and the only symptom is finding less.
//
// So the map needs its own test.  This builds the target both ways out of one
// link, runs afl-showmap on the AFL++ arm to get ground truth, and has covcheck
// confirm that every branch direction the SymSan trace took resolves to an edge
// afl-showmap saw.
//
// The second half is the one that would catch a regression: with a deliberately
// wrong map the same run has to come out INCONSISTENT.  Without it, a check
// that vacuously passes would look identical.
//
// REQUIRES: aflpp
//
// One link, two artefacts: the coverage binary, and <out>.0.5.precodegen.bc --
// the merged module as it stands after AFL++'s LTO pass has numbered its edges.
// AFL_LLVM_LTO_STARTID is symsan::AFL_ID_BASE (include/branch_id.h), which holds
// the bottom of the numbering back for SymSan's own non-edge branch ids.
// RUN: rm -f %t.bmap %t.wrong.bmap %t.afl.0.5.precodegen.bc
// RUN: env AFL_LLVM_LTO_STARTID=4096 %afl-clang-lto -g -flto -fuse-ld=lld \
// RUN:   -Wl,--save-temps=precodegen -o %t.afl %s
//
// The same module again, taint-instrumented, lowered, and linked by the real
// ko-clang so the runtime comes along.
// RUN: %taint-opt -taint-with-afl=1 -taint-branch-map=%t.bmap \
// RUN:   %t.afl.0.5.precodegen.bc -o %t.taint.bc
// RUN: llc -relocation-model=pic -filetype=obj %t.taint.bc -o %t.taint.o
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.symsan %t.taint.o
//
// The map has to describe the two nested branches before anything below is
// worth running; a map of nothing passes every check there is.  Exact ids
// depend on AFL++'s numbering order, so what is pinned is the shape: the reserved
// base, one branch with both sides numbered, and one with a side AFL++ pruned.
// RUN: FileCheck %s --check-prefix=MAP --input-file=%t.bmap
// MAP-DAG: # symsan branch map v1 base=4096 edges=
// MAP-DAG: C {{[0-9]+}} {{[0-9]+}} {{[0-9]+}}
// MAP-DAG: C {{[0-9]+}} {{[0-9]+}} -1
//
// 'ABCDEFGH' matches neither comparison, so the trace takes the outer branch's
// false side -- an edge afl-showmap must confirm.
// RUN: python -c"import sys; sys.stdout.buffer.write(b'ABCDEFGH')" > %t.bin
// RUN: %afl-showmap -o %t.showmap -- %t.afl %t.bin
// RUN: %covcheck -m %t.bmap -c %t.showmap -i %t.bin -- %t.symsan @@ | FileCheck %s
// CHECK: checked: 1
// CHECK: violations: 0
// CHECK: pruned: 0
// CHECK: verdict: consistent
//
// 0xdeadbeef in the first word takes the outer branch's true side instead --
// which AFL++ pruned, because the block behind it is a full dominator and
// reaching it is already implied by an edge AFL++ does record.  That is the
// point of this second input: "pruned" is an answer the map gives ("this side
// is never interesting"), not a gap, and it has to be counted apart from the
// branches the map has simply never heard of.
// RUN: python -c"import sys; sys.stdout.buffer.write(bytes([0xef,0xbe,0xad,0xde]) + b'EFGH')" > %t.deep.bin
// RUN: %afl-showmap -o %t.deep.showmap -- %t.afl %t.deep.bin
// RUN: %covcheck -m %t.bmap -c %t.deep.showmap -i %t.deep.bin -- %t.symsan @@ | FileCheck %s --check-prefix=DEEP
// DEEP: executed: 2
// DEEP: checked: 1
// DEEP: violations: 0
// DEEP: pruned: 1
// DEEP: unmapped: 0
// DEEP: verdict: consistent
//
// Now point every branch at edge 4096: inside the range the header declares, so
// the reader keeps it, but one below where AFL++ started numbering and therefore
// an edge no run can ever have covered.  (An out-of-range id would not do -- the
// reader drops those, and a dropped entry reads as "unknown branch", which is
// not a contradiction.)
// RUN: sed -E 's/^([CX]) ([0-9]+) .*/\1 \2 4096 4096/' %t.bmap > %t.wrong.bmap
// RUN: not %covcheck -m %t.wrong.bmap -c %t.showmap -i %t.bin -- %t.symsan @@ | FileCheck %s --check-prefix=WRONG
// WRONG: violations: 1
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
