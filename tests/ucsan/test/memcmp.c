// METADATA: note.yaml
// FLAG: 100 101
// ENV: trace_bounds


int cal(unsigned int* payload, unsigned char* content){
    if (memcmp(payload, "abcd", 4) == 0) {
        exit(100); // memcpy propogate functional
    }
    if (memcmp(payload, "bbbb", 4) == 0 && memcmp(payload, content, 4) == 0) {
        exit(101);
    }
    return 0;
}