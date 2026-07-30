// Do SymSan and the fuzzer name the same *switch case*?
//
// tests/fuzzing/branch_map_join.c asks this of if-branches.  A case is harder, and used
// not to work at all: SymSan gave every case of a switch the switch's own id,
// so a case could not be named, and AFL++ wrote no src= for a case block at
// all.  Both sides now key a case on the switch's location plus the case value
// (symsan::switch_case_cid), which is the only thing they both know about it.
//
// The failure this guards against is silent in exactly the same way: a broken
// join does not crash anything, it just means SymSan keeps solving cases the
// fuzzer has already reached.  So the second half is the real test -- corrupt
// *only* the lines carrying a case value and require the verdict to flip.  If
// cases quietly stopped joining, the first run would still say "consistent"
// and this run would too, and the test fails.
//
// REQUIRES: aflpp
//
// RUN: rm -f %t.map %t.wrong.map %t.ids
// RUN: env SYMSAN_DOCUMENT_IDS=%t.ids KO_USE_FASTGEN=1 %ko-clang -g -o %t.symsan %s
// RUN: env AFL_LLVM_DOCUMENT_IDS=%t.map %afl-clang-lto -g -o %t.afl %s
//
// Both id tables have to describe all three cases before comparing them is
// worth anything; a missing line on either side would make everything below
// pass by describing nothing.  The switch itself is documented too, as the
// thing that is deliberately *not* joinable.
// RUN: FileCheck %s --check-prefix=IDS --input-file=%t.ids
// IDS-DAG: kind=switch src=
// IDS-DAG: kind=switch-case case=3735928559 src=
// IDS-DAG: kind=switch-case case=305419896 src=
// IDS-DAG: kind=switch-case case=7 src=
//
// RUN: FileCheck %s --check-prefix=MAP --input-file=%t.map
// MAP-DAG: dir=1 case=3735928559 src=
// MAP-DAG: dir=1 case=305419896 src=
// MAP-DAG: dir=1 case=7 src=
//
// 0xdeadbeef little-endian, so the run below takes the first case: the trace
// has a case it took, whose edge afl-showmap must confirm, and two it did not.
// RUN: python -c"import sys; sys.stdout.buffer.write(bytes([0xef,0xbe,0xad,0xde]) + b'EFGH')" > %t.bin
// RUN: %afl-showmap -o %t.showmap -- %t.afl %t.bin
// RUN: %covcheck -m %t.map -c %t.showmap -i %t.bin -- %t.symsan @@ | FileCheck %s
//
// The two cases the trace did not take are unmapped, and stay that way by
// design: "do not take this case" is not one edge but everywhere else the
// switch could go.  Only dir=1 exists for a case, which is the direction worth
// asking about anyway.
// CHECK: violations: 0
// CHECK: ambiguous-violations: 0
// CHECK: unmapped: 2
// CHECK: verdict: consistent
//
// RUN: sed '/case=/s/edgeID=[0-9]*/edgeID=65535/' %t.map > %t.wrong.map
// RUN: not %covcheck -m %t.wrong.map -c %t.showmap -i %t.bin -- %t.symsan @@ | FileCheck %s --check-prefix=WRONG
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
