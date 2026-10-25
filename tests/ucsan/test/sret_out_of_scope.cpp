// METADATA: sret_out_of_scope_cpp.yaml
// FLAG: 200
// ENV: KO_USE_NATIVE_LIBCXX trace_bounds

// An out-of-scope function returning a struct too big for registers writes it
// through a hidden sret pointer, the caller's temporary.  Its stub never wrote
// it, so the temporary stayed uninitialized and the first read of a field was
// a UBI -- in v8's unit tests, NewDefaultPlatform's unique_ptr and gtest's
// std::string messages.  Out of scope, what the function returns is
// under-constrained: the branch on it must be solvable.
#include <cstdlib>

struct Big {
    long a, b, c;  // 24 bytes: returned through sret on x86-64
};

__attribute__((noinline)) Big make_big(int x) { return Big{x, 2L * x, 3L * x}; }

int entry(int *x) {
    Big b = make_big(*x);  // make_big is out of scope
    if (b.b == 0x123456)
        exit(200);
    return 0;
}
