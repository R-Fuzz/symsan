// METADATA: note.yaml
// FLAG: 200,0
// ENV: trace_bounds

int cal(int size) {
    char * a = malloc(size);
    if (size > 1 << 30) {
        exit(200); // should not happen
    }
}