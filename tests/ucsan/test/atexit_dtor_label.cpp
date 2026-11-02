// METADATA: atexit_dtor_label_cpp.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/atexit_dtor_label.abilist
// FLAG: 200
// ABSENT: 151 152

// A static object's destructor is registered with __cxa_atexit and called
// by exit, which is not instrumented.  In-scope code's registration went to
// UCSan's out-of-scope stub, and counter()'s ~Counter never ran.  Library
// code's (gauge(), listed uninstrumented) went to libc, and ~Gauge, in
// scope, read its `this` label from whatever the last call left in UCSan's
// argument TLS -- touch(&local)'s, a stack label freed when cal returned,
// or since reused: its read of `n` was an OOB (152) here, a stack UAF (151)
// in v8's unit tests (gtest's g_argvs, a std::vector its static initializer
// constructs), after the run was over.  Both are registered through a
// trampoline that hands the destructor the label it was registered with
// (library code's reaches it only as dfsan's `custom` too: as `discard` it
// called libc).  (exit runs after the trace has ended, so the destructors'
// branches are not explored: any run reaching ~Counter exits 200.)
//
// All paths must be reached:
//   any input:   ~Gauge reads its count, then ~Counter    -> exit(200)
#include <cstdlib>

struct Counter {
    int n = 0;
    ~Counter();
};

struct Gauge {
    int n = 0;
    ~Gauge();
};

static volatile int sink;

Counter::~Counter() {
    if (n != 12345)
        exit(200);
}

Gauge::~Gauge() { sink = n; }

Counter &counter() {
    static Counter c;
    return c;
}

// library code: registered last, so destroyed first
__attribute__((noinline)) Gauge &gauge() {
    static Gauge g;
    return g;
}

__attribute__((noinline)) void touch(int *p) { *p += 1; }

int cal(int *a) {
    int local = *a;
    counter().n = *a;
    gauge().n = *a;
    touch(&local);
    return local;
}
