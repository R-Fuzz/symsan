// RUN: rm -rf %t.d && mkdir -p %t.d
// RUN: clang-18 -O0 -DGENERATED -c -o %t.d/gen.o %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O0 -o %t.fg %s %t.d/gen.o
// RUN: env TAINT_OPTIONS="trace_bounds=1" %t.fg 2>&1 | FileCheck %s

// A byval argument's copy is on the stack, in the caller's outgoing
// arguments, and the callee gives it its source's shadow (__taint_byval_copy):
// a padding byte the source never wrote is uninitialized there.  Like a dead
// frame's locals (dead_frame_shadow.c), the marking outlived the call, and
// uninstrumented code that later wrote that stack wrote no shadow: v8's
// builtins put a runtime function's arguments where CppHeap's constructor's
// byval copy had been, and Runtime_JSReceiverGetPrototypeOf's look at them
// was a UBI.  A frame clears its byval copies' shadow when it returns.
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

// passed in memory (byval), with 7 bytes of padding after c
struct big {
  char c;
  long a[8];
};

static long t;
__attribute__((noinline)) void take(struct big b) { t += b.c + b.a[7]; }

// b's padding is marked uninitialized, and its copy left where
// call_with_frame's frame goes
__attribute__((noinline)) void pass(int n) {
  struct big b;
  b.c = (char)n;
  for (int i = 0; i < 8; i++)
    b.a[i] = i;
  for (int i = 0; i < 4; i++)
    take(b);
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
  pass(1);
  printf("sum %d\n", call_with_frame(runtime_fn));
  return 0;
}
#endif
