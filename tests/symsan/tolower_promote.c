// __dfsw_tolower on its own, with the argument promotion in front of it.
//
// tolower takes an int, so the caller widens the loaded byte first and the
// wrapper's c_label is a 32-bit ZExt of the real 8-bit value; the fold is
// modelled as a mask over it.  The point of the test is the end-to-end
// property, not the node shape: isupper() is a __ctype_b_loc table load and
// therefore concrete to us, so the solver gets no say in it, while
// Or(x, 0x20) == 'q' admits both 'Q' and 'q'.  Answering 'q' would satisfy the
// constraint and then fail the gate it cannot see.  CHECK-GEN is what pins that
// down.
//
// Note this does NOT discriminate the width of the mask node: building it at 8
// bits over a 32-bit operand, as the wrapper used to, gets the same answer here
// because both solver front ends re-extend the operand and the mask fits in 8
// bits.  See case_fold_label in dfsan_custom.cpp for why the width was fixed
// anyway, and tolower_strncmp.c for the defect on this path that did bite.
//
// KO_DONT_OPTIMIZE=1 is required: ko-clang otherwise raises the optimization
// level to -O3, which defines __OPTIMIZE__, and glibc's ctype.h then expands
// tolower() to (*__ctype_tolower_loc())[c] -- a constant-table load at a
// symbolic index, which never reaches the wrapper this test is about.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python3 -c "import sys; sys.stdout.buffer.write(b'A'*8)" > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 KO_DONT_OPTIMIZE=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  unsigned char buf[8];
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    return -1;
  }
  size_t n = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  if (n != sizeof(buf)) return -1;

  if (!isupper(buf[0])) {
    printf("Bad case\n");
    return 0;
  }

  if (tolower(buf[0]) == 'q') {
    // CHECK-GEN: Good
    printf("Good\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  return 0;
}
