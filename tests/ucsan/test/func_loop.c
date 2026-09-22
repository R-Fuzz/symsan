// METADATA: note.yaml
// FLAG: 123 201
// ENV: trace_bb
extern int a;
int* b = &a;

unsigned int foo(unsigned int* arr) {
    unsigned int i = 0;
    while (arr[i] != 0xbb) {
        i++;
    }
    return i;
}

int cal(unsigned int* arr, unsigned int* arr2) {
    if (arr != (void*)0xdeadbeef) {
        return 0;
    }
    unsigned int i = 0;
    unsigned int counter = 0;
    while (arr[i] != 0xbb) {
        counter += foo(arr2);
        i++;
    }
    if (counter > 30) {
        exit(201);
    }
    return counter;
}
