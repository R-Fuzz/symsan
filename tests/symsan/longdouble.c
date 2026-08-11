// x86_fp80 is not a type we can carry: there is no bitcast from it to an
// integer that fits the 64-bit union.  combineShadows used to fall through its
// half/float/double chain and emit `trunc x86_fp80 to i64`, which is not valid
// IR to select -- clang died with
//
//   fatal error: error in backend: Cannot select: i64 = truncate (f80 load)
//
// so a target using long double could not be built at all.  We do not support
// fp80; the contract is only that it compiles and drops the shadow, which
// leaves the comparison concrete and produces no task.  A `long double` at
// -O0 also reaches the compare through an fcmp on x86_fp80 and an fpext of the
// double constant, so both directions of the type filter get exercised.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*32)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[32];
  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  long double x = 0;
  memcpy(&x, buf, sizeof x);

  if (x == 3.141592653589793116L) {
    printf("Good\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  return 0;
}

// CHECK-NOSOL-NOT: id-
