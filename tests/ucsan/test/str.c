// METADATA: note.yaml
// #FLAG: 200 201

int cal(char* c, int p) {
    // if (p == 1){
        // if (strlen(c) == 0x10) {
            // exit(200);
        // }
    // }
    // if (p == 2) {
        // concat [c[0]] [c[1]] [c[2]] [c[3]] [c[4]] [c[5]] str
        // Fixed: changed '&&' (multi-char constant 9766) to '&' (single char 38)
        if (strchr(c, '-') == 5 && c[5] == '&' ) {
            exit(201);
        }
    // }
    return 0;
}