// trunc(zext(icmp)) must not fold to the icmp.
//
// __taint_union folds trunc(zext(x)) back to x when the trunc's width is x's
// size.  A comparison label's size is its operands' width, not its i1
// result's, so a compare of two i16s stored through an int into a 16-bit
// bitfield -- zext i1 to i32, trunc to i16, shl, and, or -- came back as the
// compare itself, and z3 got a bool where a bitvector goes: "operator is
// applied to arguments of the wrong sort" (the kernel's snd_intel8x0_probe).
//
// RUN: printf 'AA' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

struct flags { uint16_t lo : 12, f : 1, hi : 3; };

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint16_t x;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&x, 1, sizeof(x), fp);
  fclose(fp);

  volatile int b = (x == 0x1ab8);
  volatile struct flags s = {0};
  s.f = b;
  if (s.f) {
    // CHECK-GEN: Good
    printf("Good\n");
  }
  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}
