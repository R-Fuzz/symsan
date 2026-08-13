// METADATA: note.yaml
// ENV: no_upcast
// FLAG: 161,1

int cal(char* buf) {
    if (buf[-1] == 'A') { // should trigger no_upcast
        exit(200); // should not trigger
    }
}