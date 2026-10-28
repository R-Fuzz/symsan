// METADATA: snprintf_writes.yaml
// FLAG: 200
// ABSENT: 150
// ENV: KO_CHECKER_UBI trace_bounds

// snprintf is out of scope, but what it writes into an in-scope buffer is
// written: buf is this frame's (uninit) stack object, and the branch on the
// characters snprintf formatted into it was a false UBI while snprintf was a
// stub that (without resign) left buf uninitialized.  Now the sprintf family
// runs TaintPass's wrappers, which mark what they write.  (v8's
// operator<<(ostream&, const AsHex&): snprintf into a char[], then os << buf.)
#include <stdio.h>
#include <stdlib.h>

int entry(int *a) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%x", 0xabc);
    if (buf[0] == 'a' && a[0] == 42)
        exit(200);
    return 0;
}
