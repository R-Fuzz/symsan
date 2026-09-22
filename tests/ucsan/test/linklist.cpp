// METADATA: cpp.yaml
// FLAG: 200
// ENV: KO_USE_NATIVE_LIBCXX

#include <cstdlib>
#include <stdexcept>

// Using a class with a constructor and private members 
// to test how the engine handles object initialization.
class Node {
public:
    unsigned int v;
    Node* next;

    Node(unsigned int val) : v(val), next(nullptr) {}
};

// A template function to test symbolic arithmetic and 
// type-based dispatch in concolic execution.
template <typename T>
T bar(T value) {
    return value + 5;
}

// A function using references, which are handled differently 
// than pointers in the C++ AST.
void foo(unsigned int& val) {
    // Always call bar to exercise template instantiation.
    // Avoiding a conditional here prevents an over-constraining path
    // condition (v <= 10) that would make the sum > 100 constraint unsolvable.
    val = bar(val);
    if (val > 100) {
        throw std::runtime_error("val > 100");
    }
}

/**
 * Target function for Under-Constrained Execution.
 * The engine will likely start here with 'head' as a symbolic pointer.
 */
int cal(Node* head) {
    int sum = 0;
    int count = 0;

    // UCCE must handle the 'head' pointer being potentially NULL
    // or pointing to a symbolic memory region.
    while (head != nullptr) {
        // Test: Can the engine handle deep paths or infinite loops?
        if (count++ > 10) break; 
        try{
            foo(head->v);
        }catch(...){
            return -1;
        }
        
        sum += head->v;

        // Path constraint: head->v <= 100 (matches foo's throw threshold)
        // Note: using > 40 here would give the branch LLVM loop-flags=6,
        // causing the Python termination manager to drop its constraint from
        // __branch_deps, making sum>200 unsolvable.
        if (head->v > 100) return -1;

        head = head->next;
    }

    // Branching logic to trigger specific exit codes
    if (sum > 100) {
        if (sum > 200) {
            // Under-constrained engines try to find a memory layout 
            // for the linked list that satisfies this condition.
            std::exit(200);
        }
    }

    return sum;
}