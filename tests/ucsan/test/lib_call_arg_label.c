// METADATA: lib_call_arg_label.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_call_arg_label.abilist
// LIB: lib_call_arg_label_lib.c
// FLAG: 200
// ABSENT: 152

/*
 * Library code from a separately built object (test/lib/, -taint-ucsan-lib
 * alone, as a prebuilt archive's objects are) calls a function the scope
 * keeps, with a pointer of its own.  Its arguments are concrete, so their
 * UCSan labels are 0, but UCSan code reads them from __ucsan_arg_tls, which
 * the library never wrote: use() got the label cal's call to touch() left
 * in slot 0, the 16-byte block's, and its in-bounds big[40] was an OOB (v8's
 * Isolate::New, from the prebuilt v8 archive, calling
 * Isolate::InitializeCounters).  In the module UCSanPass zeroes the slots
 * of library code's calls into the scope; an object built on its own does
 * not know the scope, and zeroes them before every call.
 *
 *   use(big): big[40] in the library's 64-byte block -> exit(200), no 152
 */
#include <stdlib.h>

void lib_run(void);

__attribute__((noinline)) void touch(char *p) { p[1] = 1; }

void use(char *p) {
    p[40] = 1;
    if (p[40] == 1)
        exit(200);
}

int cal(int *a) {
    char *small = malloc(16);
    small[0] = (char)*a;
    touch(small);
    lib_run();
    return 0;
}
