/*
 * Library code built on its own (KO_UCSAN_LIB: TaintPass -taint-ucsan-lib,
 * no UCSanPass), as a prebuilt archive's is: it writes no UCSan return
 * label.  See ../lib_retval_label.c.
 */
static char flag[4] = {1, 0, 0, 0};

static char *lib_flag(void) { return flag; }

/* the callee as a vtable slot is: an address the test's module never sees */
char *(*lib_getter(void))(void) { return lib_flag; }
