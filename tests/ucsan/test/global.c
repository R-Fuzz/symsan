// METADATA: note.yaml
// FLAG: 201 202 203
// ENV: KO_WRAP_INDIRECT_CALL
static int a;
static int *b;
static struct {
    int a;
    int b;
} c;
static int (*calls[10])(int) ;

int cal() {
    if (a == 0xaaaaaaaa){
        if (*b == 0xbbbbbbbb) exit(201);
        exit(0);
    }
    if (c.a == 0xcacacaca && c.b == 0xcbcbcbcb){
        exit(202);
    }
    if (calls[2](0) == 0xffffffff) {
        exit(203);
    }
}