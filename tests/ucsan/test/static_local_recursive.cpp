// METADATA: static_local_recursive_cpp.yaml
// FLAG: 171 200
// ENV: KO_USE_NATIVE_LIBCXX trace_bounds concrete_globals

// A function-local static whose constructor reaches the same static again:
// libc++abi's __cxa_guard_acquire finds the guard pending and aborts
// ("detected recursive initialization").  The guard wrappers keep the pending
// byte as libc++abi does, so that is a PANIC (171), and only on the path that
// recurses:
//   *a == 5  -> Registry() calls reg() again   -> 171
//   *a == 7  -> constructed once               -> exit(200)
#include <cstdlib>

static int *input;

struct Registry {
    int v;
    Registry();
};

static Registry &reg() {
    static Registry r;
    return r;
}

Registry::Registry() : v(42) {
    if (*input == 5)
        v = reg().v;
}

int entry(int *a) {
    input = a;
    Registry &r = reg();
    if (r.v == 42 && *a == 7)
        exit(200);
    return 0;
}
