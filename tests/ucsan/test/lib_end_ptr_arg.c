// METADATA: lib_end_ptr_arg.yaml
// ENV: trace_bounds
// FLAG: 200
// ABSENT: 152

// A pointer one past its object's end is a value, an end iterator's: handed
// to a function out of scope it is checked for no size, as the callee
// decides what it reads, and pointing at the end was an OOB (152).  v8's
// ~HandleScope calls CloseScope(isolate, prev_next, prev_limit), prev_limit
// a handle block's end.  Here snprintf's "%p" prints it.
#include <stdio.h>
#include <stdlib.h>

int entry(int *a) {
    char out[32];
    char *buf = malloc(16);
    char *end = buf + 16;
    snprintf(out, sizeof(out), "%p", (void *)end);
    if (a[0] == 42)
        exit(200);
    free(buf);
    return 0;
}
