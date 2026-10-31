// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -fno-builtin -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1" %t.fg %t.bin 2>&1 | FileCheck %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.fg %t.out/id-0-0-0 | FileCheck --check-prefix=FLIP %s

// A byval argument's copy is made by the backend, on the stack: it copies
// the bytes, not their shadow, so the copy's shadow was whatever an earlier
// frame left there.  Under trace_bounds that is kInitializingLabel when the
// earlier frame had an array there, and dereferencing a pointer field of the
// copy Die()d as uninitialized memory -- v8's CanonicalHashing::Add, which
// takes a CanonicalType by value.  And a field that was symbolic in the
// caller was concrete in the callee, so its branch could not be flipped.
// CHECK-NOT: uninitialized
// CHECK: seven 0
// FLIP: flipped
#include <stdio.h>
#include <stdlib.h>

struct pair {
  const int *p;
  int tag;
  int pad[4];
};

static const int seven = 7;

// leaves kInitializingLabel on the stack below main's frame
__attribute__((noinline)) int scribble(int n) {
  volatile int a[32];
  for (int i = 0; i < n; ++i)
    a[i] = i;
  return a[n - 1];
}

__attribute__((noinline)) int take(struct pair v) {
  if (v.tag == 0x41424344)
    printf("flipped\n");
  return *v.p;
}

int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], "rb");
  if (!f)
    return 1;
  struct pair v = {&seven, 0, {0}};
  if (fread(&v.tag, 1, sizeof(v.tag), f) != sizeof(v.tag))
    return 1;
  fclose(f);
  scribble(2);
  printf("seven %d\n", take(v) - 7);
  return 0;
}
