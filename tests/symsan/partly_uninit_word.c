// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x07')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -fno-builtin -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1" %t.fg %t.bin 2>&1 | FileCheck %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out trace_bounds=1" %fgtest %t.fg %t.bin
// RUN: %t.fg %t.out/id-0-0-0 | FileCheck --check-prefix=FLIP %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -fno-builtin -DREAD_PADDING -o %t.pad %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1" not %t.pad %t.bin 2>&1 | FileCheck --allow-empty --check-prefix=PAD %s

// A padded struct passed as a word: {u8, 3 bytes of padding, i32, 4 x u8}
// goes in an i64 and an i32, and the callee reads its first field off the
// argument, `and i64 %c, 255` -- v8's GCConfig, read so in
// Heap::StartGarbageCollection.  The word's bytes are the field, the padding
// and state: some bits uninitialized and the rest not (see Uninit in
// dfsan.h), and the field's bits are none of the padding's, so the field is
// initialized -- and symbolic: its branch can be flipped.  Before, the word
// had one label, the union of its bytes', kInitializingLabel, and the
// branch died (exit_on_memerror).  A use that does read the padding (the
// first 4 bytes as an int) still does.
// CHECK: state 1
// CHECK: kind 7
// FLIP: flipped
// PAD-NOT: kind
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct cfg {
  uint8_t kind;  // then 3 bytes of padding
  int32_t state;
  uint8_t m, s, f, g;
};

// at -O0, as the test's own code is in v8: in its frame, padding and all
__attribute__((noinline, optnone)) struct cfg make(uint8_t kind) {
  struct cfg c;
  c.kind = kind;
  c.state = 1;
  c.m = c.s = c.f = c.g = 0;
  return c;
}

__attribute__((noinline)) int check(struct cfg c) {
#ifdef READ_PADDING
  uint32_t head;
  memcpy(&head, &c, sizeof(head));
  if (head == 0x41)
    printf("flipped\n");
#else
  if (c.kind == 0x41)
    printf("flipped\n");
#endif
  // the second half of the first word: initialized too
  printf("state %d\n", c.state);
  return c.kind;
}

int main(int argc, char **argv) {
  FILE *fp = fopen(argv[1], "rb");
  if (!fp)
    return 1;
  uint8_t kind;
  if (fread(&kind, 1, 1, fp) != 1)
    return 1;
  fclose(fp);
  printf("kind %d\n", check(make(kind)));
  return 0;
}
