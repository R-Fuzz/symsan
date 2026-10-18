// A memchr over more than 4096 symbolic bytes is declined: z3's sequence
// theory grows with the string, and on 16 KB took gigabytes (kMaxSeqLength).
// The same search over 4096 bytes still solves.
// RUN: rm -rf %t.out %t.short.out
// RUN: mkdir -p %t.out %t.short.out
// RUN: python -c'print("A"*4999)' > %t.bin
// RUN: python -c'print("A"*4095)' > %t.short.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out | count 0
// RUN: env TAINT_OPTIONS="taint_file=%t.short.bin output_dir=%t.short.out" %fgtest %t.fg %t.short.bin
// RUN: %t.uninstrumented %t.short.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  static char buf[8192];
  FILE* fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    return -1;
  }
  size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
  fclose(fp);

  void *p = memchr(buf, 0x7f, n);
  if (p != NULL) {
    // CHECK-GEN: Found byte
    printf("Found byte\n");
  } else {
    // CHECK-ORIG: No byte
    printf("No byte\n");
  }
  return 0;
}
