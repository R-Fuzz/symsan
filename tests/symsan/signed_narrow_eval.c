// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x9c\xff\xff\xff" * 5)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

// Signed division and arithmetic shift of a negative value narrower than 64
// bits.  The parser checks each expression against the concrete value the
// target recorded, and it evaluated sdiv/srem/ashr on the zero-extended cached
// value: a 32-bit -100 read as 4294967196, so v / 5 came out 0x3333331f, not
// -20, and the branch was rejected as a value mismatch -- no input generated.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[20];
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  int32_t v;
  memcpy(&v, buf, 4);  // -100 in the seed

  int32_t sum = (v / 5) + (v >> 4) + (v % 7);
  // CHECK-ORIG: sum -29
  printf("sum %d\n", sum);
  if (sum == -30) {
    // CHECK-ORIG-NOT: Good
    // CHECK-GEN: Good
    printf("Good\n");
  }
  return 0;
}
