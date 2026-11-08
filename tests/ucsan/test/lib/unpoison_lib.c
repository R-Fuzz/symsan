// Library code (TaintPass alone, -taint-ucsan-lib) for unpoison_lib.c: the
// stack scan of unpoison.c.
void __symsan_unpoison(const void *addr, unsigned long size);

static int hits;
__attribute__((noinline)) void hit(void) { hits++; }

__attribute__((noinline)) int lib_scan(void) {
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
