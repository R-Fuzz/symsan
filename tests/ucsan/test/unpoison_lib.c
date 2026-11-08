// METADATA: lib_free.yaml
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/unpoison_lib.abilist
// LIB: unpoison_lib.c
// ENV: trace_bounds
// ABSENT: 150
// FLAG: 200

/*
 * unpoison.c's stack scan in library code, as v8's is in a UT build (the
 * prebuilt archive): there SymSan's shadow marks the never-written slots
 * (trace_bounds), and __symsan_unpoison clears them in the copy.
 */
#include <stdlib.h>

int lib_scan(void);

int cal(int n) {
  lib_scan();
  exit(200);
}
