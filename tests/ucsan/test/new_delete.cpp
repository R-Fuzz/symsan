// METADATA: new_delete_cpp.yaml
// FLAG: 151 200
// ENV: KO_USE_NATIVE_LIBCXX trace_bounds

// operator new/delete are malloc/free: new gives a real object, delete frees
// it.  They used to be out-of-scope declarations with dangle stubs, so new
// returned an under-constrained pseudo-pointer and delete did nothing: the
// read of the deleted node below was never a use after free (151).
//
// Both paths must be reached:
//   *a >  100: the deleted node is read          -> UAF (151)
//   *a <= 100: the live node's value is checked   -> exit(200) when *a == 42
#include <cstdlib>

struct Node {
    int v;
    Node *next;
};

int entry(int *a) {
    Node *n = new Node{*a, nullptr};
    Node *m = new Node{*a + 1, n};
    int v = m->next->v;
    delete n;
    if (v > 100)
        return m->next->v;  // n was deleted
    if (m->v == 43)
        exit(200);
    delete m;
    return 0;
}
