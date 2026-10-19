// The parser models memcmp as 0/1, while the program sees a byte difference,
// so a memcmp's cached value is a placeholder.  As a direct ICmp operand it
// took the runtime value; nested deeper -- counter_set's
// `(x & 8) | memcmp(...)` -- the value check compared against the
// placeholder and refused the branch as a value mismatch.
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*16)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char buf[16] = {0};
  FILE *fp = fopen(argv[1], "rb");
  if (!fp)
    return 1;
  fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  int r = memcmp(buf, "enable", 6);
  if (((buf[10] & 8) | r) == 0) {
    // CHECK-GEN: matched
    printf("matched\n");
  } else {
    // CHECK-ORIG: no match
    printf("no match\n");
  }
  return 0;
}
