// METADATA: libcxx_malloc_cpp.yaml
// FLAG: 200
// ABSENT: 1

// libc++.a's code is TaintPass's alone, and allocates through operator new,
// which calls malloc: under UCSan the runtime's __dfsw_malloc is
// ucsan_custom.cpp's, which takes UCSan's 16-bit labels, and libc++'s call
// (dfsan's ABI) got the 16-bit label of the result in the low half of a
// 32-bit one.  With a stale high half that was a label past the table --
// 0xffff000b in v8's Ostream.AsHexBytes -- and __taint_union segfaulted; with
// a zero one, here, it was UCSan's object label read as an input byte's, and
// operator new's null check a symbolic branch.  libc++ calls the
// __dfsl_malloc adapter now (TaintPass -taint-ucsan-abilist; the calls are
// checked by tests/symsan/ucsan_lib_dfsl.c).  The string grows long, so
// append, in libc++.a, allocates its buffer.  (Only libc++.a's code: an
// inline header function is an out-of-scope stub here, and writes nothing.)
#include <cstdlib>
#include <string>

int entry(int *a) {
    std::string s = std::to_string(1);
    s.append(100, 'y');
    if (a[0] == 42)
        exit(200);
    return 0;
}
