// METADATA: custom_invalid_input_cpp.yaml
// FLAG: 122 200
// ENV: KO_USE_NATIVE_LIBCXX

// A fatal check made by a unit test's harness, not by the code under test: a
// fixture CHECKs what an out-of-scope dependency gave it.  Mapped to
// ucsan_invalid_input, a seed that fails it ends the run as invalid input
// (122), which is no finding (the manager keeps the exit status, as for
// asm_call_entry, but saves no seed and reports nothing), and the other paths
// are still explored.
//
//   *a >  100: the harness's assumption fails  -> 122, not a bug
//   *a <= 100: the code under test runs        -> exit(200) when *a == 7
#include <cstdlib>

extern "C" void harness_check_failed(const char *what);

int entry(int *a) {
    if (*a > 100)
        harness_check_failed("a <= 100");
    if (*a == 7)
        exit(200);
    return 0;
}
