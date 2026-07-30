// String-theory: plant a delimiter at a pinned offset when the buffer starts
// with an early NUL (extension required).
//
// Identical to strchr_plant_filled.c EXCEPT the input is all-zero, so the
// concrete strlen() is 0. __dfsw_strchr bounds the symbolic haystack by strlen
// (dfsan_custom.cpp get_str_label), yet the solver still plants '"' at offset 5
// here -- it exposes enough of the object extent (Alloca bounds from the stack
// buffer) and extends the string. This locks in that capability: a regression
// would show up as the gen input failing to reach offset 5.
//
// Contrast with memchr_plant_offset.c: memchr is length-bounded (not
// strlen-bounded) and also succeeds on the same zero buffer.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python3 -c "import sys; sys.stdout.buffer.write(b'\x00'*16)" > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[64] = {0};
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    return -1;
  }
  size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
  fclose(fp);
  buf[n] = '\0';

  // Solver must plant '"' at exactly offset 5, extending past the early NUL.
  char *p = strchr(buf, '"');
  if (p && (p - buf) == 5) {
    // CHECK-GEN: PLANTED at 5
    printf("PLANTED at 5\n");
  } else {
    // CHECK-ORIG: no delimiter at 5
    printf("no delimiter at 5\n");
  }
  return 0;
}
