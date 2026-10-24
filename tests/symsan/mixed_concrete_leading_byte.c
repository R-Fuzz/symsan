// A wide load combines a fixed nonzero low byte with a symbolic later byte.
// The initial concrete byte must survive __taint_union_load's slow path;
// otherwise the parser sees 0 where the traced comparison saw 8 and rejects
// the branch with "value mismatch for ICmp".
//
// RUN: python -c "import sys; sys.stdout.buffer.write(b'\x00')" > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=ORIG %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env SYMSAN_PARSE_ONLY=1 TAINT_OPTIONS="taint_file=%t.bin" %fgtest %t.fg %t.bin | FileCheck --check-prefix=PARSE %s
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=GEN %s
//
// ORIG: Bad
// PARSE: PARSE-SUMMARY conds=1 ok=1 empty=0 failed=0
// GEN: Good

#include <stdint.h>
#include <stdio.h>
#include "lib.h"

union echo_prefix {
  uint64_t word;
  unsigned char bytes[8];
};

int main(int argc, char **argv) {
  if (argc < 2) return 2;

  unsigned char input = 0;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&input, 1, 1, fp);
  fclose(fp);

  union echo_prefix request = { .bytes = { 8, 0 } };
  request.bytes[2] = input;
  if ((request.word & 0xffffffULL) == 0x010008ULL)
    puts("Good");
  else
    puts("Bad");
  return 0;
}
