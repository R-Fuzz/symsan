// A unary FP intrinsic on an x86_fp80 (`fabsl`, as absl's long double
// formatting does) must give valid IR.  TaintPass's FP-intrinsic path bitcast
// half, float and double to an integer for the union call's operand slot, and
// anything else went straight to a trunc -- `trunc x86_fp80 to i64`, which llc
// rejects ("invalid cast opcode").  Any FP type is now bitcast to its
// same-width integer first, as combineShadows() does.
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: head -c 16 /dev/zero > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lm
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.fg %t.bin | FileCheck %s
// CHECK: small

#include <math.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  unsigned char buf[16] = {0};
  FILE *f = fopen(argv[1], "rb");
  if (!f || fread(buf, 1, sizeof(buf), f) != sizeof(buf))
    return 1;
  fclose(f);
  long double x;
  memcpy(&x, buf, sizeof(long double) < 16 ? sizeof(long double) : 16);
  if (fabsl(x) > 2.0L)
    printf("big\n");
  else
    printf("small\n");
  return 0;
}
