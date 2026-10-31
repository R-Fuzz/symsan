// RUN: env KO_USE_FASTGEN=1 %ko-clang -O0 -o %t.fg %s
// RUN: env TAINT_OPTIONS="trace_bounds=1" %t.fg 2>&1 | FileCheck %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O2 -D_FORTIFY_SOURCE=2 -o %t.fort %s
// RUN: env TAINT_OPTIONS="trace_bounds=1" %t.fort 2>&1 | FileCheck %s

// What the sprintf family writes is concrete, its terminating NUL included:
// format_buffer labelled each formatted chunk 0 but not the NUL after them,
// which kept the label the buffer had -- under trace_bounds a fresh stack
// buffer's is kInitializingLabel -- so a branch on it was a UBI (v8's
// FormattedString: DCHECK_EQ('\0', message[n])).  An empty format writes
// only the NUL.  At -O2 with _FORTIFY_SOURCE these calls are
// __snprintf_chk/__vsnprintf_chk, which had no wrapper at all.
// CHECK-NOT: uninitialized
// CHECK: n 2 3 0
#include <stdarg.h>
#include <stdio.h>

__attribute__((noinline)) static int fmt(char *buf, size_t size,
                                         const char *f, ...) {
  va_list ap;
  va_start(ap, f);
  int r = vsnprintf(buf, size, f, ap);
  va_end(ap);
  return r;
}

int main(void) {
  char a[16], b[16], c[4];
  int n = snprintf(a, sizeof(a), "%d", 42);
  int m = fmt(b, sizeof(b), "%x", 0xabc);
  const char *empty = "";
  int k = snprintf(c, sizeof(c), empty, 0);
  if (a[n] == '\0' && b[m] == '\0' && c[0] == '\0')
    printf("n %d %d %d\n", n, m, k);
  return 0;
}
