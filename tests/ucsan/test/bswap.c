// METADATA: note.yaml
// FLAG: 200
int cal(int a){
    // if (a == 0xaabbccdd) {
        if (__builtin_bswap32(a) == 0xddccbbaa) {
            exit(200);
        }
    // }
}