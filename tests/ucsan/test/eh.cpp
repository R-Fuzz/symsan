// METADATA: eh_cpp.yaml
// FLAG: 200
// ENV: KO_USE_NATIVE_LIBCXX

#include <cstdlib>
#include <stdexcept>

// In-scope function that conditionally throws based on symbolic input.
// Tests that the engine can explore both the throw and no-throw paths.
int safe_transform(int val) {
    if (val > 50) {
        throw std::runtime_error("value too large");
    }
    return val * 2;
}

// Entry function: *a and *b are independently symbolic integer pointers.
//
// Two paths to exit(200):
//   No-throw: *a <= 50  → x = *a * 2 ∈ [0, 100]  → need *b > 200 - x
//   Throw:    *a > 50   → exception caught, x = 0  → need *b > 200
//
// The test verifies that taint tracking on *b is intact after the EH unwind.
// If taint on *b is lost, the solver cannot constrain it and exit(200) is never
// reached on the throw path, causing the test to fail.
int entry(int* a, int* b) {
    int x = 0;

    try {
        x = safe_transform(*a);
    } catch (...) {
        // Exception caught; *a taint and *b taint must still be live here.
        x = 0;
    }

    // Taint from *b must survive across the EH unwind on both paths.
    int sum = x + *b;

    if (sum > 200) {
        std::exit(200);
    }

    return sum;
}
