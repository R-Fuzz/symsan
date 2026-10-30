// METADATA: libcxx_malloc_cpp.yaml
// FLAG: 200
// ABSENT: 201

// Library code's file I/O is real, unless the handle is UCSan's own.  libc++'s
// random_device, in libc++.a, opens and reads /dev/urandom.  It used to reach
// UCSan's simulated file through the __dfsl_ adapters, and its bytes were
// symbolic -- v8's fixture seeds its RandomNumberGenerator so, and the solver
// spent its time on mmap hints -- and v == 0x5eed5eed was solvable (201).
// Now v is concrete.  (stdin is still UCSan's file, but std::cin is no probe
// for it here: cin is a global, lazily symbolic in this suite, and its get()
// aborts on the paths the solver gives its state.)
// The default constructor is an inline header function, an out-of-scope stub
// here that opens nothing; the one taking a token is libc++.a's, and the
// token is laid out as libc++'s short string (the size << 1 in byte 0, then
// the characters), since std::string's constructors are header stubs too.
#include <cstdlib>
#include <random>
#include <string>

int entry(int *a) {
    alignas(std::string) char tok[sizeof(std::string)] = {
        12 << 1, '/', 'd', 'e', 'v', '/', 'u', 'r', 'a', 'n', 'd', 'o', 'm'};
    std::random_device rd(*reinterpret_cast<const std::string *>(tok));
    unsigned v = rd();
    if (v == 0x5eed5eedu)
        exit(201);
    if (a[0] == 42)
        exit(200);
    return 0;
}
