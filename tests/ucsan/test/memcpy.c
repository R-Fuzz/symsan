// METADATA: note.yaml
// FLAG: 100 152
// DISCARD: 1
// ENV: trace_bounds


int cal(unsigned int* payload, int size){
    char* sum = malloc(10);
    memcpy(sum, payload, 8);
    if (sum[2] == 'a') {
        exit(100); // memcpy propogate functional
    }

    char* sum2 = malloc(size);
    char* sum3 = malloc(size);
    if (sum2 == 0 || sum3 == 0) {
        return 0; // alloca failed
    }
    memcpy(sum2, sum3, *payload); // should be OOB along with segfault if checkpointer allows continue after oob detected
    return 0;
}
