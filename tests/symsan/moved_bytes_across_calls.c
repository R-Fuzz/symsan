// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x07')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -fno-builtin -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1" %t.fg %t.bin 2>&1 | FileCheck %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.fg %t.out/id-0-0-0 | FileCheck --check-prefix=FLIP %s

// A padded struct moved as words across calls: make() returns it as two i64s,
// loaded from its frame, and the second -- kind, syntax and 2 bytes of
// padding -- goes on as an argument to info_init(), which stores it.  The
// word's one label is the union of its bytes', kInitializingLabel, so the
// store marked kind uninitialized -- v8's UnoptimizedCompileFlags, returned by
// ForFunctionCompile and passed to ParseInfo's constructor.  A move keeps each
// byte's label across a return and an argument too, so kind is initialized,
// and symbolic: its branch can be flipped.
// CHECK-NOT: uninitialized
// CHECK: kind 7
// FLIP: flipped
#include <stdint.h>
#include <stdio.h>

struct flags {
  uint32_t bits;
  int32_t id;
  uint8_t kind;
  uint8_t syntax;  // then 2 bytes of padding
  int32_t mode;
};

struct info {
  struct flags flags;
  int extra;
};

__attribute__((noinline)) void init(struct flags *f) {
  f->bits = 0;
  f->id = 1;
  f->syntax = 0;
  f->mode = 0;
}

__attribute__((noinline)) struct flags make(uint8_t kind) {
  struct flags f;
  init(&f);
  f.kind = kind;
  return f;
}

__attribute__((noinline)) void info_init(struct info *i, struct flags f) {
  i->flags = f;
  i->extra = 0;
}

__attribute__((noinline)) int check(struct info *i) {
  if (i->flags.kind == 0x41)
    printf("flipped\n");
  return i->flags.kind;
}

int main(int argc, char **argv) {
  FILE *fp = fopen(argv[1], "rb");
  if (!fp)
    return 1;
  uint8_t kind;
  if (fread(&kind, 1, 1, fp) != 1)
    return 1;
  fclose(fp);
  struct info i;
  info_init(&i, make(kind));
  printf("kind %d\n", check(&i));
  return 0;
}
