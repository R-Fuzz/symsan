// METADATA: libcxx_writes_cpp.yaml
// FLAG: 200
// ABSENT: 150
// ENV: KO_CHECKER_UBI trace_bounds

// libc++.a's functions run as its taint-instrumented copy (ko-clang's
// ucsan_libcxx_abilist.txt), which UCSanPass does not instrument: what they
// write into an in-scope object must still count as written.  t is this
// frame's (uninit) stack object, and std::to_string, libc++.a's, constructs
// the string it returns in it; the digits, in t's inline buffer (libc++'s
// short-string layout: the size byte, then the characters), are read here
// directly.  They were a false UBI: libc++'s stores left UCSan's shadow
// uninitialized, until libc++-ucsan.a (-taint-ucsan-lib) marks what they
// write.  (KO_CHECKER_UBI: the branch on raw[1] is the use; trace_bounds
// paints t uninitialized.)
#include <cstdlib>
#include <string>

int entry(int *a) {
    std::string t = std::to_string(12345);
    const char *raw = reinterpret_cast<const char *>(&t);
    if (raw[1] == '1' && a[0] == 42)
        exit(200);
    return 0;
}
