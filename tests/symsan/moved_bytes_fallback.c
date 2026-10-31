// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'xy')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 KO_DONT_OPTIMIZE=1 %ko-clang -O0 -fno-builtin -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin" timeout 60 %t.fg %t.bin 2>&1 | FileCheck %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" timeout 60 %fgtest %t.fg %t.bin
// RUN: %t.fg %t.out/id-0-0-0 | FileCheck --check-prefix=FLIP %s

// An argument the caller left no bytes' labels for (a call's result, passed
// on) is stored as a value is, each byte its part of the label: check_eq()
// spills r at -O0 (to memory, as its address escapes, and as UCSan keeps every
// frame), so r is moved, and its label, memcmp's, is narrower than its bytes.
// The label copied to every byte instead made each byte one of 2 bits, and the
// next load of r never got past the first, making labels until there were
// none -- v8's CHECK_EQ(0, memcmp(...)) (minutes: hence the timeouts).
// CHECK: r -1
// FLIP: equal
#include <stdio.h>
#include <string.h>

__attribute__((noinline)) void sink(int *p) { (void)p; }

__attribute__((noinline)) int check_eq(int expected, int r) {
  sink(&r);
  if (r == expected)
    printf("equal\n");
  return r;
}

int main(int argc, char **argv) {
  char buf[2];
  FILE *fp = fopen(argv[1], "rb");
  if (!fp)
    return 1;
  if (fread(buf, 1, 2, fp) != 2)
    return 1;
  fclose(fp);
  int r = check_eq(0, memcmp(buf, "zz", 2));
  printf("r %d\n", r < 0 ? -1 : r > 0);
  return 0;
}
