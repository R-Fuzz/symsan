// METADATA: libcxx_verbose_abort_cpp.yaml
// FLAG: 171
// ABSENT: 1 153 180

// Without exceptions (v8 builds -fno-exceptions) a libc++ header's throw is
// a call to std::__libcpp_verbose_abort, libc++'s abort:
// vector::__vallocate's __throw_length_error, for a length past max_size().
// libc++.a defines it, so ucsan_libcxx_abilist.txt left the call to its
// body, which formats to stderr: v8's ZoneAllocatorTest.UseWithStdContainers
// segfaulted in it, reported as a null dereference (153).  It is an abort,
// a PANIC as __dfsw_abort's (ucsan_abilist.txt lists it custom).
#include <cstdlib>

namespace std { inline namespace __1 {
[[noreturn]] void __libcpp_verbose_abort(const char *format, ...);
} }

int entry(int *a) {
    if (a[0] == 42)
        std::__libcpp_verbose_abort("%s\n", "vector");
    return 0;
}
