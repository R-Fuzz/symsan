// METADATA: note.yaml
// FLAG: 200
int cal(int* a, int b) {
    int orig = __atomic_fetch_add(a, b, __ATOMIC_RELAXED);
    if (*a == 3 && b == 1 ) {
        exit(200);
    }
}