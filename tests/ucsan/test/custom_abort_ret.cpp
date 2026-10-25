// METADATA: custom_abort_ret_cpp.yaml
// FLAG: 171 200
// ENV: KO_USE_NATIVE_LIBCXX
// CFLAGS: -fverify-intermediate-code

// A value-returning failure reporter mapped to abort in the YAML custom
// section: v8's CHECK_LT(a, b) calls MakeCheckOpString(a, b, "a < b") when the
// check fails, which formats the message (an ostringstream) and returns it
// for V8_Fatal.  Mapped to abort, the failed check is a PANIC (171) at the
// call, and the formatting is never run.  The wrapper passed abort the return
// value's shadow slot and returned its void result: invalid IR.  And
// MakeCheckOpString is a template, defined in the module in a comdat: its
// body was dropped, leaving a declaration in a comdat, which the verifier
// rejects (a release clang skips the verifier; llc on ucsan_opt's output
// does not, hence -fverify-intermediate-code).
//
// All paths must be reached:
//   *a >= 16:       the check fails (declared reporter)  -> PANIC (171)
//   *a <  -16:      the check fails (template reporter)  -> PANIC (171)
//   otherwise:      the checked value is used            -> exit(200) when *a == 7
#include <cstdlib>
#include <string>

extern "C" std::string *make_check_op_string(int lhs, int rhs,
                                             const char *msg);

template <typename T> std::string *check_op_message(T lhs, T rhs) {
    return new std::string(std::to_string(lhs) + " vs " + std::to_string(rhs));
}

int entry(int *a) {
    if (*a >= 16) {
        std::string *m = make_check_op_string(*a, 16, "a < 16");
        return (int)m->size();
    }
    if (*a < -16) {
        std::string *m = check_op_message<int>(*a, -16);
        return (int)m->size();
    }
    if (*a == 7)
        exit(200);
    return 0;
}
