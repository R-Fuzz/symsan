// A memcmp/bcmp over more bytes than a label can describe, symbolic at only a
// few positions.
//
// An operand label is a Concat of its n bytes, n * 8 bits wide, and a label's
// width is 16 bits: past 8191 bytes it wraps.  Building it was also one Concat
// per byte, concrete or not -- v8's BitVector::Equals, a bcmp of two 16 MB
// liveness vectors with a symbolic word at either end, made 2 x 16.8M labels,
// and the solver serialized every one of them in one call.  The comparison is
// decided by the first position where the sides differ, so the runtime keeps
// only the positions that can be it (a symbolic byte on either side, or the
// first concrete difference) and compares those.
//
// Here 1 MB: the two input bytes go to either end of a zeroed buffer, compared
// with "X...Y".  Generating "XY" needs both ends in the constraint, at the
// right width.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python3 -c 'print("AB", end="")' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -fno-builtin -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env KO_USE_FASTGEN=1 %ko-clang -fno-builtin -DBCMP -o %t.fgb %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fgb %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
// CHECK-ORIG: differ
// CHECK-GEN: equal

#include <stdio.h>
#include <string.h>
#include <strings.h>

#define N (1 << 20)
static unsigned char a[N], b[N];

int main(int argc, char **argv) {
  if (argc < 2) return 1;
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) return 1;
  unsigned char in[2];
  if (fread(in, 1, 2, fp) != 2) return 1;
  fclose(fp);

  a[0] = in[0];
  a[N - 1] = in[1];
  b[0] = 'X';
  b[N - 1] = 'Y';
#ifdef BCMP
  int r = bcmp(a, b, N);
#else
  int r = memcmp(a, b, N);
#endif
  printf("%s\n", r == 0 ? "equal" : "differ");
  return 0;
}
