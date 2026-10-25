// METADATA: new_invoke_cpp.yaml
// FLAG: 151 200
// ENV: KO_USE_NATIVE_LIBCXX trace_bounds

// operator new called through an invoke: a local with a destructor is alive
// across it, so if new throws, the destructor still has to run.  The custom
// wrappers handled only plain calls, so this new went to the real operator
// new, whose object UCSan never saw: the read of the deleted node below was no
// use after free (151).
//
// Both paths must be reached:
//   *a >  100: the deleted node is read          -> UAF (151)
//   *a <= 100: the copied value is checked        -> exit(200) when *a == 42
#include <cstdlib>

struct Node {
    int v;
    Node *next;
};

struct Guard {
    int *p;
    ~Guard() { *p = 0; }
};

int entry(int *a) {
    int flag = 1;
    Guard g{&flag};
    Node *n = new Node{*a, nullptr};
    int v = n->v;
    delete n;
    if (v > 100)
        return n->v;  // n was deleted
    if (v == 42)
        exit(200);
    return flag;
}
