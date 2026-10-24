// RUN: printf '\014A' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O0 -o %t.fg %s
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s

// A shift by at least its width is poison, and what the machine computes for
// it depends on codegen: x86 masks a count to 5 bits even for an 8-bit shift,
// which it does in a 32-bit register, so `1 << 12` as an i8 is 0 here; the
// kernel's `1U << page_order` (vm_reset_perms) was done in a 64-bit register,
// 0 again for 36, where a native 32-bit shift gives 16.  The parser
// recomputed the shift with the count taken modulo the width -- 16 here --
// and rejected the comparison below as a value mismatch; now the value is
// unknown.  _BitInt(8) is not promoted to int, so this is a real i8 shift.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t n, c;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&n, 1, sizeof(n), fp);
  chk_fread(&c, 1, sizeof(c), fp);
  fclose(fp);

  unsigned _BitInt(8) one = 1;
  unsigned _BitInt(8) bit = one << (unsigned _BitInt(8))n;  // n = 12 in the seed
  int v = (int)bit + c;
  // CHECK-ORIG: v 65
  printf("v %d\n", v);
  if (v == 100) {
    // CHECK-ORIG-NOT: Good
    // CHECK-SOL: Good
    printf("Good\n");
  }
  return 0;
}
