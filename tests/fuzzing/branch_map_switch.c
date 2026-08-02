// Does the branch map point a *switch case* at the edge the fuzzer walks?
//
// tests/fuzzing/branch_map_join.c asks this of if-branches.  A case is harder,
// and used not to work at all: SymSan gave every case of a switch the switch's
// own id, so a case could not be named.  A case is still not a block AFL++ has
// any name for -- it numbers the edges out of the switch, not the values that
// select them -- so the two are tied together by the one thing that identifies
// a case in both worlds: the switch's id plus the case value, hashed by
// symsan::switch_case_cid.  TaintPass writes an `S <switch cid> <value> <edge>`
// line per case and the reader keys it the same way, so the backend can look up
// "if this case were taken, which edge would that be" for a case it did not
// take.
//
// The failure this guards against is silent in exactly the same way as in the
// if-branch test: a wrong target does not crash anything, it just means SymSan
// keeps solving cases the fuzzer has already reached.  So the second half is
// the real test -- corrupt *only* the lines carrying a case value and require
// the verdict to flip.  If cases quietly stopped being keyed at all, the first
// run would still say "consistent" and this run would too, and the test fails.
//
// REQUIRES: aflpp
//
// RUN: rm -f %t.bmap %t.wrong.bmap %t.afl.0.5.precodegen.bc
// RUN: env AFL_LLVM_LTO_STARTID=4096 %afl-clang-lto -g -flto -fuse-ld=lld \
// RUN:   -Wl,--save-temps=precodegen -o %t.afl %s
// RUN: %taint-opt -taint-with-afl=1 -taint-branch-map=%t.bmap \
// RUN:   %t.afl.0.5.precodegen.bc -o %t.taint.bc
// RUN: llc -relocation-model=pic -filetype=obj %t.taint.bc -o %t.taint.o
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.symsan %t.taint.o
//
// The map has to describe all three cases before comparing anything is worth
// doing; a missing line would make everything below pass by describing nothing.
// The default is there too, under its own letter, as the direction that means
// "no case matched".  Note that the two cases sharing a body still get distinct
// edges: AFL++ splits the critical edge out of the switch per case value.
// RUN: FileCheck %s --check-prefix=MAP --input-file=%t.bmap
// MAP-DAG: S {{[0-9]+}} 3735928559 {{[0-9]+}}
// MAP-DAG: S {{[0-9]+}} 305419896 {{[0-9]+}}
// MAP-DAG: S {{[0-9]+}} 7 {{[0-9]+}}
// MAP-DAG: D {{[0-9]+}} {{[0-9]+}}
//
// 0xdeadbeef little-endian, so the run below takes the first case: the trace
// has a case it took, whose edge afl-showmap must confirm, and two it did not.
// RUN: python -c"import sys; sys.stdout.buffer.write(bytes([0xef,0xbe,0xad,0xde]) + b'EFGH')" > %t.bin
// RUN: %afl-showmap -o %t.showmap -- %t.afl %t.bin
// RUN: %covcheck -m %t.bmap -c %t.showmap -i %t.bin -- %t.symsan @@ | FileCheck %s
//
// The two cases the trace did not take come back unmapped, and stay that way by
// design: SymSan asks about the *negation* of the direction it took, and "do
// not take this case" is not one edge but everywhere else the switch could go.
// Only the true direction of a case has a target, which is the direction worth
// asking about anyway.
// CHECK: executed: 3
// CHECK: checked: 1
// CHECK: violations: 0
// CHECK: unmapped: 2
// CHECK: verdict: consistent
//
// Only the case lines, pointed at edge 4096: in range, so the reader keeps it,
// but one below where AFL++ started numbering and so an edge no run covers.
// RUN: sed -E 's/^(S) ([0-9]+) ([0-9]+) .*/\1 \2 \3 4096/' %t.bmap > %t.wrong.bmap
// RUN: not %covcheck -m %t.wrong.bmap -c %t.showmap -i %t.bin -- %t.symsan @@ | FileCheck %s --check-prefix=WRONG
// WRONG: violations: 1
// WRONG: verdict: INCONSISTENT

// Plain C, no lib.h: afl-clang-lto compiles this too and has none of the
// SymSan harness.  Two of the cases share a body, which is how a switch most
// often gets two case values pointing at one destination block.
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

  uint32_t x = 0;
  memcpy(&x, buf + 0, 4);

  switch (x) {
    case 0xdeadbeefu:
      printf("one\n");
      return 1;
    case 0x12345678u:
    case 7u:
      printf("two or three\n");
      return 2;
    default:
      printf("other\n");
      break;
  }
  return 0;
}
