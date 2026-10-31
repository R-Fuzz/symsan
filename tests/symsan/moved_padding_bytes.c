// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -fno-builtin -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1" %t.fg %t.bin 2>&1 | FileCheck %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.fg %t.out/id-0-0-0 | FileCheck --check-prefix=FLIP %s

// A padded struct moved as words: the second word holds len, engaged and 3
// bytes of padding, and padding is uninitialized.  The word's one label is
// the union of its bytes', kInitializingLabel, and the store gave it to every
// byte it wrote: len was uninitialized in the copy, and the branch on it
// Die()d -- v8's ExternalEntityTable::TryExtend, moving an
// optional<pair<Segment, FreelistHead>>.  A move now copies each byte's
// label, so len is initialized, and symbolic: its branch can be flipped.
// CHECK-NOT: uninitialized
// CHECK: len 0
// FLIP: flipped
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct head {
  uint32_t segment;
  uint32_t next;
  uint32_t len;
  uint8_t engaged;  // then 3 bytes of padding
};

__attribute__((noinline)) void move(void *dst, const void *src) {
  uint64_t *d = (uint64_t *)dst;
  const uint64_t *s = (const uint64_t *)src;
  d[0] = s[0];
  d[1] = s[1];
}

__attribute__((noinline)) int check(struct head *h) {
  if (h->len == 0x41424344)
    printf("flipped\n");
  return h->len;
}

int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], "rb");
  if (!f)
    return 1;
  struct head src, dst;
  src.segment = 1;
  src.next = 2;
  src.engaged = 1;
  if (fread(&src.len, 1, sizeof(src.len), f) != sizeof(src.len))
    return 1;
  fclose(f);
  move(&dst, &src);
  printf("len %d\n", check(&dst));
  return 0;
}
