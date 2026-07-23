// FP equality solving (in-process z3 solver only; the RGD/fastgen path does not
// model FP, so there are no KO_USE_FASTGEN RUN lines here).  An else-if chain
// selects on an exact double match (x == 1.2) or an exact float match
// (y == 2.1f).  The seed ("A"*20) misses both, so a single concolic run flips
// both comparisons and emits one input per branch.  Note: the solver emits the
// nested (else-if) float solution first, so id-0-0-0 hits Good2 and id-0-0-1
// hits Good1.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN-FLT %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN-DBL %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[20];
  size_t ret;

  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  double x = 0;
  float y = 0;
  memcpy(&x, buf, sizeof x);
  memcpy(&y, buf + 10, sizeof y);

  if (x == 1.2) {
    // CHECK-GEN-DBL: Good1
    printf("Good1\n");
  } else if (y == 2.1f) {
    // CHECK-GEN-FLT: Good2
    printf("Good2\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  return 0;
}
