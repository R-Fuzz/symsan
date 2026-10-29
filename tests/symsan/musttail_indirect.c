// A musttail call must stay right before its ret.  TaintPass's function exit
// code -- the call-stack context restore, and the stack-frame pop -- went in
// front of the ret, after the call, and the verifier rejects that ("musttail
// call must precede a ret").  partition_alloc's allocator-shim dispatch
// (DelegatedAllocFn) ends in one.  The exit code now goes before the call.
//
// RUN: printf '\005' > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin" %t.fg %t.bin | FileCheck %s
// CHECK: 15

#include <stdio.h>

typedef int (*fn_t)(int);

__attribute__((noinline)) static int triple(int x) { return 3 * x; }

static fn_t volatile dispatch = triple;

__attribute__((noinline)) int delegate(int x) {
  fn_t f = dispatch;
  __attribute__((musttail)) return f(x);
}

int main(int argc, char **argv) {
  unsigned char c = 0;
  FILE *f = fopen(argv[1], "rb");
  if (!f || fread(&c, 1, 1, f) != 1)
    return 1;
  fclose(f);
  printf("%d\n", delegate(c));
  return 0;
}
