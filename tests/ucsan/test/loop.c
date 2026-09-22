// METADATA: note.yaml
// FLAG: 123 200 201
// ENV: KO_TRACE_BB
extern int a;
int* b = &a;
int cal(unsigned int* arr) {
    if (arr != (void*)0xdeadbeef) {
        return 0;
    }
    unsigned int i = 0;
    unsigned int sum = 0;
    while (arr[i] != 0xbb) {
        if (arr[i] > 6) goto next;
        sum += arr[i];
next:
        i++;
    }
    if (i < 6 && sum == 0x1e) {
         exit(200);
    }
    if (i == 7 && sum == 0x1e) {
         exit(201);
    }
    if (i == 11 && sum == 0x1e) {
         exit(202); // should not be reached
    }
    return sum;
}

