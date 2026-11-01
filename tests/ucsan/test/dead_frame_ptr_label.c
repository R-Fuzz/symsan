// METADATA: dead_frame_ptr_label.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/dead_frame_ptr_label.abilist
// FLAG: 200
// ABSENT: 151 152

/*
 * A frame's locals' UCSan shadow dies with it.  leave() (in scope) fills its
 * frame with a pointer to its own local, whose label is a stack label, freed
 * when leave returns.  lib() (library code: the abilist lists it
 * uninstrumented, so only TaintPass instruments it) reuses that stack: its
 * stores mark the bytes they write initialized, but keep any other label
 * there, a pointer it only moved.  So use() (in scope) loaded lib's pointer
 * to its own local with leave's dead label: a stack UAF (151), or, the label
 * since reused, an OOB (152) -- v8's torque ToString, library code under a
 * unit test, streamed into a std::stringstream on its stack, and libc++'s
 * in-scope __pad_and_output found the stream's rdbuf out of bounds.
 *
 * All paths must be reached:
 *   *a == 7:   use() reads lib's local through lib's pointer -> exit(200)
 */
#include <stdlib.h>

#define N 8

__attribute__((noinline)) int leave(int v) {
    int y = v;
    int *slots[N];
    for (int i = 0; i < N; i++)
        slots[i] = &y;
    return *slots[v & (N - 1)];
}

__attribute__((noinline)) int use(int **p) { return **p; }

__attribute__((noinline)) int lib(int v) {
    int x = v;
    int *slots[N];
    for (int i = 0; i < N; i++)
        slots[i] = &x;
    int r = 0;
    for (int i = 0; i < N; i++)
        r += use(&slots[i]);
    return r / N;
}

int cal(int *a) {
    leave(*a);
    if (lib(*a) == 7)
        exit(200);
    return 0;
}
