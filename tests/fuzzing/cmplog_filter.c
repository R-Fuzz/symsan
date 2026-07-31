// Does the fuzzer let SymSan's taint decide what cmplog still has to do?
//
// With `--symsan` and `--cmplog` both given, the two run the same
// input-to-state technique over the same corpus entry.  The filter tells the
// second what the first already did: SymSanStage publishes a byte
// classification per traced entry, SymSanColorizationStage turns it into a
// colorized input in two executions instead of one per two input bytes, and an
// entry whose every byte is settled skips the cmplog group outright.
//
// Nothing observable fails when the filter misfires -- the fuzzer just does
// more work, or less, than it should -- so the log lines are the interface
// under test here.  The second half is what makes the first non-vacuous:
// `--no-symsan-cmplog-filter` has to produce a run with none of it.
//
// REQUIRES: aflpp, aflpp-cmplog, symsan-fuzz
//
// RUN: rm -rf %t.in %t.out %t.stock.out
// RUN: mkdir -p %t.in
// RUN: env KO_USE_FASTGEN=1 %ko-clang -g -o %t.symsan %s
// RUN: %afl-clang-fast -g -o %t.afl %s
// RUN: env AFL_LLVM_CMPLOG=1 %afl-clang-fast -g -o %t.cmplog %s
// RUN: python -c"import sys; sys.stdout.buffer.write(b'AAAAAAAA')" > %t.in/seed
//
// The fuzzer never exits on its own, so cap it; the whole corpus of this target
// is reached in well under a second.  `not` because timeout reports 124.
// RUN: not timeout 20 env RUST_LOG=debug AFL_MAP_SIZE=65536 %symsan-fuzz -i %t.in -o %t.out -t 5000 --symsan %t.symsan --cmplog %t.cmplog -- %t.afl @@ > %t.log 2>&1
// RUN: FileCheck %s < %t.log
//
// CHECK-DAG: cmplog: filtered by SymSan's taint
// The interesting entries are the ones SymSan solved outright: every byte
// settled, so the whole cmplog group is pointless for them.
// CHECK-DAG: symsan: skipping cmplog for entry {{[0-9]+}}: every byte is settled
// ...and the ones it did not, which get a colorized input for two executions.
// CHECK-DAG: symsan: colorized entry {{[0-9]+}} in 2 execs
//
// Now the stock pipeline, which must show none of it.  Same everything else, so
// a difference can only come from the flag.
// RUN: not timeout 20 env RUST_LOG=debug AFL_MAP_SIZE=65536 %symsan-fuzz -i %t.in -o %t.stock.out -t 5000 --symsan %t.symsan --cmplog %t.cmplog --no-symsan-cmplog-filter -- %t.afl @@ > %t.stock.log 2>&1
// RUN: FileCheck %s --check-prefix=STOCK --implicit-check-not="symsan: skipping cmplog" --implicit-check-not="symsan: colorized entry" < %t.stock.log
//
// STOCK: cmplog: tracing with

// Deliberately plain C -- no lib.h -- because afl-clang-fast has to compile it
// too, and it has none of the SymSan harness.  Two magic-value checks on
// separate input words: SymSan cracks both, so an entry that has been through
// the concolic stage has every one of its eight read bytes settled, which is
// exactly the case the filter exists for.
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
