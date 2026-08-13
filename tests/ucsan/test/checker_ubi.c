// METADATA: note.yaml
// ENV: KO_CHECKER_UBI
// FLAG: 150,4
struct s{
    int a;
    int b;
};

int unused(int *p) {
    return 0;
}

int cal(int branch){
    int *p;
    int a, b, c;
    int d = 233;
    long e;
    if (branch == 3) {
        unused((int*)e); // UBI should triggered
        return 0;
    }
    if (branch == 2) {
        p = &e;
        if (e + branch){ // UBI should triggered
            return 0;
        }
        return 0;
    }
    if (branch > 0) {
        *p = 1; // UBI should triggered
    } else {
        c = b + 1;
    }
    if (branch + d) { // UBI should not triggered in this case
        d += 5;
    } else if (c) { // UBI should triggered
        return 1;
    } else {
        return 0;
    }

}
