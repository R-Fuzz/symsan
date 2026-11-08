// METADATA: unpoison.yaml
// ABSENT: 150
// FLAG: 200

/*
 * __symsan_unpoison (what v8's MSAN_MEMORY_IS_INITIALIZED calls in a
 * SymSan/UCSan build) says a range is initialized.  A conservative GC's stack
 * scan (v8's heap::base::Stack::IteratePointersUntilMarker) reads every slot,
 * live or not, copies it to a local and says so of the copy, so testing the
 * copy is no use of an uninitialized value.  Without the call, the branch on
 * the never-written slots is a UBI (150).
 */
#include <stdlib.h>

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

int cal(int n) {
  scan();
  exit(200);
}
