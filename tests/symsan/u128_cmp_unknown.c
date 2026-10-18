// RUN: python -c'print("A"*40)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s

// The parser checks every expression against the value the target recorded,
// except where its recomputation cannot be trusted: a value wider than 64
// bits is marked unknown, and so is a comparison of two -- a narrow unknown,
// a bool.  What was computed from that bool was not: the zext of it recorded
// the comparison's placeholder 0, and the sum below, 1 + 'A' at runtime, was
// rejected as a value mismatch (SLUB's cmpxchg-double, `zext(Equal[128])`).

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  unsigned __int128 a, b;
  uint8_t c;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&a, 1, sizeof(a), fp);
  chk_fread(&b, 1, sizeof(b), fp);
  chk_fread(&c, 1, sizeof(c), fp);
  fclose(fp);

  int sum = (a == b) + c;  // 1 + 'A' in the seed
  // CHECK-ORIG: sum 66
  printf("sum %d\n", sum);
  if (sum == 5) {
    // CHECK-ORIG-NOT: Good
    // CHECK-SOL: Good
    printf("Good\n");
  }
  return 0;
}
