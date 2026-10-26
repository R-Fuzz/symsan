// METADATA: byval_bounds_cpp.yaml
// FLAG: 200
// ABSENT: 152
// ENV: KO_USE_NATIVE_LIBCXX trace_bounds

// An aggregate passed byval is copied by the call into the callee's own
// frame, and the callee's pointer is to that copy.  TaintPass handed the
// callee the caller's bounds label for its own object, so the first field
// read through the copy was checked against the original's bounds: an OOB
// (152) on an access that is in bounds.  In v8's BitVector::CopyFrom the
// object is a lambda passed by value to ForRange (a {ptr, ptr} closure the
// linker typed as std::pair, which clang passes byval).
#include <cstdlib>

struct Big {
    int *p;
    long pad[2];  // 24 bytes: passed byval on x86-64
};

__attribute__((noinline)) int use(Big b) { return *b.p + (int)b.pad[1]; }

int entry(int *x) {
    Big b = {x, {0, 0}};
    if (use(b) == 0x1234)
        exit(200);
    return 0;
}
