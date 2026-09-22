// METADATA: virtual_cpp.yaml
// FLAG: 200 201 202
// ENV: KO_USE_NATIVE_LIBCXX KO_WRAP_INDIRECT_CALL

// C++ port of indirect.c: tests virtual dispatch via a class hierarchy.
// DeltaProcessor is instantiated inside cal so its vtable and methods
// are emitted to the module. The virtual call p->apply(0) resolves to
// 0 + delta = delta via virtual dispatch.
//
// No virtual destructor: avoids EH cleanup basic blocks that cause
// a crash in TaintPass's exception-handling preparation pass on LLVM 12.

#include <cstdlib>

class Processor {
public:
    virtual int apply(int x) = 0;
    // No virtual destructor: DeltaProcessor is stack-allocated,
    // never deleted through base pointer.
};

class DeltaProcessor : public Processor {
    int delta;
public:
    DeltaProcessor(int d) : delta(d) {}
    int apply(int x) override { return x + delta; }
};

static int helper(int x) { return x + 5; }

int cal(int delta) {
    DeltaProcessor proc(delta);
    Processor* p = static_cast<Processor*>(&proc);

    int sum = 0;
    if (sum > 0) __builtin_trap();

    // Virtual dispatch: sum = proc.apply(0) = 0 + delta = delta
    sum = p->apply(sum);

    if (sum > 10) std::exit(200);       // delta > 10
    if (sum > 5)  std::exit(201);       // 5 < delta <= 10
    // helper(sum) = sum+5; >= 9 means sum >= 4
    if (helper(sum) >= 9) {
        if (sum == 3) std::exit(199);   // 3+5=8 < 9, unreachable
        if (sum == 4) std::exit(202);   // 4+5=9 >= 9, reachable
    }
    return sum;
}
