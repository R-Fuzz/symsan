// METADATA: note.yaml
// FLAG: 151,2
// ENV: trace_bounds

int* foo(void) {
    int a[100];
    int b;
    int *p = a + 4;
    return p;
}

int * bar(void) {
    struct {int a;} s;
    int *p = &s.a;
    return p;
}

int cal(int option) {
        int *a = foo();
    if (option == 1) {
        a[2] = 3; // stack uar
    } else {
        * bar() = 5; // stack uar
    }
}