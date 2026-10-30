// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1" %t.fg %t.bin | FileCheck %s

// One load of a word read for fields of different widths, the shape of
// libc++'s short string: is_long is bit 0 of byte 0, the bytes after the
// terminator are never written, and an optimized append() loads the first 8
// bytes once for is_long (and 1) and the long capacity (and -2).  Under
// trace_bounds a stack object's bytes start labeled kInitializingLabel, and
// the load's shadow covers the bytes all its users read: the capacity's are
// uninitialized, so is_long was too, the select on it made the result
// uninitialized, and the branch on that Die()d (exit_on_memerror).  is_long
// now gets the shadow of byte 0 alone.
// CHECK: short
#include <stdio.h>
#include <string.h>

struct rep {
  unsigned char hdr;  // bit 0: is_long
  char data[7];
};

__attribute__((noinline)) unsigned long capacity(struct rep *r) {
  unsigned long w;
  memcpy(&w, r, sizeof(w));
  return (w & 1) ? (w & ~1UL) : 22;
}

int main(int argc, char **argv) {
  struct rep r;
  r.hdr = 2 << 1;  // short, size 2
  r.data[0] = 'h';
  r.data[1] = 'i';
  r.data[2] = 0;  // data[3..6] are never written
  if (capacity(&r) == 22)
    printf("short\n");
  return 0;
}
