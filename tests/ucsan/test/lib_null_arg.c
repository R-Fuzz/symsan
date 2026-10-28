// METADATA: lib_null_arg.yaml
// FLAG: 200
// ABSENT: 153
// ENV: checker_nullderef

// A null pointer handed to a function out of scope is not dereferenced by
// handing it on: the callee decides, and null is a value it takes.  Here
// snprintf's "%p" and "%s" print a null pointer ("(nil)", "(null)"): p is
// null (stored, so unlabeled) when a[0] == 42, and was a false 153 at the
// call.  (A constant null was never checked.)
#include <stdio.h>
#include <stdlib.h>

int entry(int *a) {
    char buf[32];
    void *p = buf;
    if (a[0] == 42)
        p = NULL;
    snprintf(buf, sizeof(buf), "%p%s", p, (char *)p);
    if (a[0] == 42)
        exit(200);
    return 0;
}
