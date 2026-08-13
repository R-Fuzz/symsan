// METADATA: note.yaml
// FLAG: 152,1 151,1
// ENV: trace_bounds
void * custom_malloc(unsigned long size) {
    return (void *)0xaaaaaaaa;
}

int cal(unsigned int* payload, unsigned int length){
    unsigned int* sum = malloc(sizeof(unsigned int));
    if(*payload == 1) {
        sum[0] = 0; // Not OOB
        sum[1] = 1; // OOB 152
        sum[-1] = 1; // OOB 152
    }
    if (*payload == 2) {
        free(sum);
        sum[0] = 1; // UAF
    }
    return *sum;
}