// METADATA: snprintf_chk_writes.yaml
// FLAG: 200
// ABSENT: 150
// ENV: KO_CHECKER_UBI trace_bounds
// CFLAGS: -O2 -D_FORTIFY_SOURCE=2

// snprintf_writes.c, fortified: at -O2 with _FORTIFY_SOURCE, glibc's
// bits/stdio2.h makes snprintf/vsnprintf into a known-size buffer
// __snprintf_chk/__vsnprintf_chk, which were stubs (UCSan) and uninstrumented
// (TaintPass): buf stayed uninitialized, a false UBI.  (v8's OS::SNPrintF
// is __vsnprintf_chk; FormattedString's DCHECK_EQ('\0', message[n]) read it.)
// buf2[n] is the terminating NUL, which format_buffer left with the label the
// buffer had (kInitializingLabel): a UBI for SymSan even after UCSan's shadow
// was marked.
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) static int fmt(char *buf, size_t n,
                                         const char *f, ...) {
    va_list ap;
    va_start(ap, f);
    int r = vsnprintf(buf, n, f, ap);
    va_end(ap);
    return r;
}

int entry(int *a) {
    char buf[16], buf2[16];
    snprintf(buf, sizeof(buf), "%x", 0xabc);
    int n = fmt(buf2, sizeof(buf2), "%d", 42);
    if (buf[0] == 'a' && buf2[n] == '\0' && a[0] == 42)
        exit(200);
    return 0;
}
