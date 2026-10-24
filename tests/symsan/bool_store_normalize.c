// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00\x00\x01\x00")' > %t.bin
// RUN: clang -O2 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O2 -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN %s
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -O2 -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN %s

// A bool global GlobalOpt shrank to i1 is stored as `store i1 %cmp`.  Its
// load is an i8 load and `!= 0` (bool_load_normalize.c), so the store must
// write an 8-bit label too: stored as is, the comparison's 1-bit label went
// through a per-byte Extract of 8 bits from a 1-bit value, and the `if (flag)`
// below failed to parse (fastgen) or was a z3 sort error, never solved.

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static bool flag = true;

__attribute__((noinline)) void setf(uint32_t x) {
  if (x & 0x100000)
    flag = false;
  else if (x & 0x10000)
    flag = true;
}

int main(int argc, char **argv) {
  uint32_t x = 0;
  FILE *f = fopen(argv[1], "rb");
  fread(&x, 1, sizeof(x), f);
  fclose(f);
  setf(x);
  // CHECK-ORIG: on
  // CHECK-GEN: off
  if (flag)
    puts("on");
  else
    puts("off");
  return 0;
}
