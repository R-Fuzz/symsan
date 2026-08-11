// String-theory DIAGNOSTIC: plant a byte at a pinned offset in an all-zero
// buffer using memchr (length-bounded, NOT strlen-bounded).
//
// memchr(buf, c, n) searches a fixed n bytes regardless of NULs, so the
// symbolic haystack covers the full range even on a zero buffer. This test
// should PASS where strchr_plant_gap.c (same zero buffer) fails, pinpointing
// the strchr failure to strlen-truncation of the haystack rather than to the
// solver's string theory in general.
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

  // Solver must plant '@' at exactly offset 5 within the first 16 bytes.
  char *p = (char *)memchr(buf, '@', 16);
  if (p && (p - buf) == 5) {
    // CHECK-GEN: PLANTED at 5
    printf("PLANTED at 5\n");
  } else {
    // CHECK-ORIG: no byte at 5
    printf("no byte at 5\n");
  }
  return 0;
}
