// METADATA: padded_return_cpp.yaml
// FLAG: 200
// ENV: KO_USE_NATIVE_LIBCXX trace_bounds

// A 16-byte struct is returned in two registers, each loaded from the
// callee's local a word at a time, padding included: Magic's second word is
// s, a and three bytes nothing writes (v8's MagicNumbersForDivision).  The
// padding made the whole word, s too, uninitialized, and the caller's
// comparison of s a UBI.  Both functions are in scope, and the branch on s
// is reached: exit(200).
#include <cstdlib>

struct Magic {
    unsigned long m;
    unsigned s;
    bool a;
};

__attribute__((noinline)) Magic make(unsigned long d) {
    Magic r;
    r.m = d * 3;
    r.s = 2;
    r.a = false;
    return r;
}

int entry(int *x) {
    Magic g = make(*x);
    if (g.s == 2 && !g.a)
        exit(200);
    return 0;
}
