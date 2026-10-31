// RUN: rm -rf %t.d && mkdir -p %t.d
// RUN: clang-18 -O0 -DGENERATED -c -o %t.d/gen.o %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O0 -o %t.fg %s %t.d/gen.o
// RUN: env TAINT_OPTIONS="trace_bounds=1" %t.fg 2>&1 | FileCheck %s

// Uninstrumented code writes the stack without its shadow, so what it writes
// has the shadow of whatever frame was there before, and under trace_bounds a
// frame's locals are marked uninitialized when it is entered.  An instrumented
// callee that reads its caller's frame read that dead frame's marking -- v8's
// builtins (generated code) put a runtime function's arguments on the stack,
// and Runtime_DeclareGlobals's first look at them was a UBI.  A frame's
// locals' shadow is now cleared when it returns.
// CHECK-NOT: uninitialized
// CHECK: sum 64
#include <stdio.h>

#ifdef GENERATED
// stands for generated code: fills its frame, and calls instrumented code with
// a pointer into it (by the name instrumented callers call it by)
int call_with_frame(int (*cb)(const int *)) __asm__("call_with_frame.taint");
int call_with_frame(int (*cb)(const int *)) {
  volatile int slots[64];
  for (int i = 0; i < 64; i++)
    slots[i] = i;
  return cb((const int *)slots);
}
#else
int call_with_frame(int (*cb)(const int *));

// its locals are marked uninitialized, and left where call_with_frame's go
__attribute__((noinline)) int deep(int n) {
  volatile int locals[256];
  locals[n] = n;
  return locals[n];
}

static int s;
__attribute__((noinline)) void hit(void) { s++; }

__attribute__((noinline)) int runtime_fn(const int *args) {
  for (int i = 0; i < 64; i++)
    if (args[i] == i)
      hit();
  return s;
}

int main(void) {
  deep(1);
  printf("sum %d\n", call_with_frame(runtime_fn));
  return 0;
}
#endif
