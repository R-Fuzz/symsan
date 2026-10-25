// METADATA: vector_select_cpp.yaml
// FLAG: 200
// ENV: KO_USE_NATIVE_LIBCXX

// A select on a vector condition picks per lane, while a vector's shadow is
// one label.  UCSanPass selected the scalar shadows on the vector condition,
// which is not valid IR: llc refused the module ("selected values for vector
// select must be vectors").  The lanes' labels are combined instead.
//
// The exit branches on the input itself, after the select: what is tested is
// that the module builds and runs.  (A branch on r[0] is not solved: the input
// label does not reach a lane through the vector built from it.)
#include <cstdlib>

typedef int v4si __attribute__((vector_size(16)));

int entry(int *a) {
    v4si x = {a[0], a[1], a[2], a[3]};
    v4si y = {1, 2, 3, 4};
    v4si r = x > y ? x : y;
    if (a[0] == 42)
        exit(200);
    return r[0] + r[1];
}
