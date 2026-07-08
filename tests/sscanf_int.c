// Test: sscanf numeric specifiers (%d %i %u %x %X %o) drive the solver via the
// fatoi (string-to-int) op, covering all supported bases (10/16/8). The %d
// field is single-digit, exercising the len==1 fatoi path. The other fields
// extend from one digit, exercising the "no NUL after an embedded field"
// solution path (a trailing NUL would clobber the space separators).
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf '0 0 0 0 0 0' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return 1;
  }

  char buf[128] = {0};
  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    perror("fopen");
    return 1;
  }
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  buf[n] = '\0';
  fclose(f);

  int d = 0, i = 0;
  unsigned u = 0, x = 0, X = 0, o = 0;
  sscanf(buf, "%d %i %u %x %X %o", &d, &i, &u, &x, &X, &o);

  // Bitwise & (no short-circuit) makes a single branch depending on all six
  // parsed values, so the solver produces one input (id-0-0-0). Bases:
  // d/i/u=10, x/X=16, o=8; d==7 is a single-digit (len==1) field.
  int ok = (d == 7) & (i == 22) & (u == 33) & (x == 0x44) & (X == 0x5a) &
           (o == 0666);
  if (ok) {
    // CHECK-GEN: SCANF-INT-OK
    printf("SCANF-INT-OK\n");
  } else {
    // CHECK-ORIG: SCANF-INT-NO
    printf("SCANF-INT-NO\n");
  }
  return 0;
}
