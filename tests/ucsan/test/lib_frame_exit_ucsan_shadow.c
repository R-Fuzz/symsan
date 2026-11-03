// METADATA: lib_frame_exit_ucsan_shadow.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_frame_exit_ucsan_shadow.abilist
// LIB: lib_frame_exit_ucsan_shadow_lib.c
// FLAG: 200
// ABSENT: 152

/*
 * A library frame's local outlived the frame in UCSan's shadow.  Library code
 * passed &x to posix_memalign, whose UCSan wrapper labels x with the new
 * 520-byte block's object; at return TaintPass cleared x's SymSan shadow but
 * not UCSan's.  Code that reuses the stack without instrumentation writes no
 * shadow: here an asm store of another pointer into the same slot, in v8 the
 * builtins putting a runtime function's arguments there (LdaGlobalHandler's
 * frame over a dead AllocateSlotSet's AlignedAlloc local).  The in-scope
 * reader then checked that pointer against the dead block's bounds, an OOB
 * (modules-unittest, Runtime_LoadNoFeedbackIC_Miss -> LookupIterator).
 * Library frames now clear UCSan's shadow at exit (__ucsan_lib_frame_exit).
 *
 *   lib_step(0): x = posix_memalign(520); return
 *   lib_step(1): x = &elsewhere (asm); use(&x): (*pp)[8] -> exit(200), no 152
 */
#include <stdlib.h>

void lib_step(int mode);

void use(void **pp) {
    char *p = *pp;
    p[8] = 1;
    if (p[8] == 1)
        exit(200);
}

int cal(int *a) {
    lib_step(0);
    if (*a == 0)
        lib_step(1);
    lib_step(1);
    return 0;
}
