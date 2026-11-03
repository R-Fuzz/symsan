/*
 * Library code built on its own (KO_UCSAN_LIB: TaintPass -taint-ucsan-lib,
 * no UCSanPass).  One frame, called twice at the same depth, so its local x
 * is the same stack slot both times.  See ../lib_frame_exit_ucsan_shadow.c.
 */
#include <stdlib.h>

void use(void **pp);

static char elsewhere[64];

__attribute__((noinline)) void lib_step(int mode) {
    void *x;
    if (mode == 0) {
        // UCSan's posix_memalign gives &x the new block's object label
        if (posix_memalign(&x, 8, 520) != 0)
            abort();
        return;
    }
    // a store no instrumentation sees (v8's builtins writing a runtime
    // function's arguments): x's bytes change, its shadow does not
    char *v = elsewhere;
    __asm__ volatile("movq %1, %0" : "=m"(x) : "r"(v));
    use(&x);
}
