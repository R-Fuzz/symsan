// METADATA: struct_cpp.yaml
// FLAG: 200
// ENV: KO_USE_NATIVE_LIBCXX

// C++ port of struct.c: replaces the plain struct+func with a class
// that has a constructor and a const member function.
// Tests: member function on symbolic object, constructor instrumentation.
//
// Design note: uses Pair* entry arg (like cal(Node*) in linklist) to
// introduce symbolic labels via __taint_check_pointer, avoiding the
// struct-return field-shadow zeroing issue in external wrappers.

#include <cstdlib>

class Pair {
public:
    unsigned long long a, b;
    Pair(unsigned long long x, unsigned long long y) : a(x), b(y) {}
    int sum() const { return (int)(a + b); }
};

// Entry: p is a symbolic pointer; its fields get fresh labels via
// __taint_check_pointer on first access.
int wrapper(Pair* p) {
    int c = p->sum();
    if (c > 10) {
        std::exit(200);
    }
    return c;
}
