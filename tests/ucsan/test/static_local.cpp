// METADATA: static_local_cpp.yaml
// FLAG: 200
// ABSENT: 153 1
// ENV: KO_USE_NATIVE_LIBCXX trace_bounds concrete_globals

// A function-local static is constructed once, under the Itanium guard
// (__cxa_guard_acquire/release).  The guard functions are libc++abi's, so out
// of scope, and their stubs returned a symbolic value: a seed where
// __cxa_guard_acquire returned 0 skipped the constructor, and the static was
// used zero-initialized -- v8's ZoneVectorTest live_set<T>() then inserted into
// a std::set whose end node was never set up (a NULL dereference, 153).
// concrete_globals as in that harness: otherwise the guard variable is itself
// an input, and a seed that sets it skips the constructor just the same.
//
// The constructor always runs, so:
//   reg().head is always &reg().sentinel     (else exit(1), or a 153 below)
//   *a == 7                                  -> exit(200)
#include <cstdlib>

struct Node {
    Node *next;
    int v;
};

struct Registry {
    Node sentinel;
    Node *head;
    Registry() : sentinel{nullptr, 42}, head(&sentinel) {}
};

static Registry &reg() {
    static Registry r;
    return r;
}

int entry(int *a) {
    Registry &r = reg();
    if (r.head != &r.sentinel)
        exit(1);
    if (r.head->v == 42 && *a == 7)
        exit(200);
    return 0;
}
