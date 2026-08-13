// METADATA: note.yaml
// FLAG: 200 124

int cal(int a, char* buf) {
    if (a > 4096 * 100) {
        a += 5;
    }
    if (buf[a] == 'A') { // should trigger oob if a > 4096
        exit(200);
    }
}