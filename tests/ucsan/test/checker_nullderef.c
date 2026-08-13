// METADATA: note.yaml
// ENV: checker_nullderef
// FLAG: 153,2
struct s{
    int a;
    int b;
};

int val = 0;

int unused(int **p) {
    *p = &val;
}

int cal(int branch){
    int *p=0;
    unused(&p);
    if (branch){
        if (*p == 0) { // NULL dereference should triggered
            return 1;
        }
    } else {
        p = (int*)0x8888;
        if (*p == 0) { // NULL dereference should triggered
            return 2;
        }
    }
    return 0;
}