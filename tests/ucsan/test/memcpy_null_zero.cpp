// METADATA: memcpy_null_zero_cpp.yaml
// FLAG: 200
// ENV: KO_USE_NATIVE_LIBCXX trace_bounds

// A copy of no bytes from a null pointer dereferences nothing: libc++
// relocates an empty std::vector with memcpy(dst, begin(), 0), its begin()
// still null, and that was a null dereference (v8's VLQ tests).  Only a
// length that copies something is one; nothing branches on n here, so the
// solver is never asked for one, and the seed's n == 0 exits(200).
#include <cstdlib>
#include <cstring>

int entry(int *x) {
    char buf[8];
    const char *src = nullptr;
    size_t n = (size_t)*x & 7;
    memcpy(buf, src, n);
    exit(200);
}
