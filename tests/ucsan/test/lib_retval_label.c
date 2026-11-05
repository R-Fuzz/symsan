// METADATA: lib_retval_label.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_retval_label.abilist
// LIB: lib_retval_label_lib.c
// FLAG: 200
// ABSENT: 152

/*
 * A call to library code (a prebuilt archive's, TaintPass's alone) reads its
 * result's UCSan label from __ucsan_retval_tls, which the library never
 * wrote: it got what the last in-scope call returned, the label of block's
 * 16-byte object, and the library's global was an OOB of the block (v8's
 * TRACE_EVENT0 caches GetCategoryGroupEnabled()'s pointer, a virtual call
 * into the archive, after a call that returned a handle block).  A call to a
 * callee that may write no label, through a pointer or to a declaration,
 * zeroes its return slot first.
 *
 *   *lib_getter()() == 1, after block = mk(16) -> exit(200), no 152
 */
#include <stdlib.h>

char *(*lib_getter(void))(void);

__attribute__((noinline)) char *mk(int n) { return malloc(n); }

int cal(int *a) {
    char *block = mk(16);
    block[0] = (char)*a;
    char *(*get)(void) = lib_getter();
    char *f = get();
    if (*f == 1)
        exit(200);
    free(block);
    return 0;
}
