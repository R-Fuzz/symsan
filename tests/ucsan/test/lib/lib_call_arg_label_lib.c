/*
 * Library code built on its own (KO_UCSAN_LIB: TaintPass -taint-ucsan-lib,
 * no UCSanPass), as a prebuilt archive's is: it does not know which of its
 * callees a test keeps in scope.  See ../lib_call_arg_label.c.
 */
#include <stdlib.h>

void use(char *p);

void lib_run(void) {
    char *big = malloc(64);
    use(big);
}
