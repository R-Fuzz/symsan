// METADATA: note.yaml
// FLAG: 123 201
// ENV: trace_bb
extern int a;
int* b = &a;
int cal(unsigned int* arr, unsigned int* arr2) {
    if (arr != (void*)0xdeadbeef) {
        return 0;
    }
    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int counter = 0;
    while (arr[i] != 0xbb) {
        while (arr2[j] != 0xcc) {
            counter++;
            j++;
            // if (j == 100)
                // goto out;
        }
        i++;
        j = 0;
        // if (counter > 50) {
            // exit(200);
        // }
    }
// out:
    if (counter > 30) {
        exit(201);
    }
    return counter;
}

