// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -o %t.fg %s
// RUN: env TAINT_OPTIONS="trace_bounds=1" %t.fg 2>&1 | FileCheck %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -DNO_UNPOISON -o %t.nu %s
// RUN: env TAINT_OPTIONS="trace_bounds=1" not %t.nu 2>&1 | FileCheck --allow-empty --check-prefix=NU %s

// __symsan_unpoison (what v8's MSAN_MEMORY_IS_INITIALIZED calls in a
// SymSan/UCSan build) says a range is initialized.  A conservative GC's stack
// scan reads every slot, live or not, copies it to a local and says so of
// the copy: under trace_bounds the never-written slots are kInitializingLabel,
// and the branch on the copy died (exit_on_memerror) without the call.
// CHECK: hits
// NU-NOT: hits
#include <stdio.h>

void __symsan_unpoison(const void *addr, unsigned long size);

static int hits;
__attribute__((noinline)) void hit(void) { hits++; }

__attribute__((noinline)) int scan(void) {
  volatile long slots[4];  // volatile: no fold of the unwritten loads
  slots[1] = 0;
  for (int i = 0; i < 4; i++) {
    long v = slots[i];
#ifndef NO_UNPOISON
    __symsan_unpoison(&v, sizeof(v));
#endif
    if (v == 0)  // a branch: where a UBI is checked
      hit();
  }
  return hits;
}

int main(void) {
  printf("hits %d\n", scan());
  return 0;
}
