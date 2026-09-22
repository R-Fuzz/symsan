// METADATA: struct.yaml
// FLAG: 200
typedef struct {
    unsigned long long field1;
    unsigned long long field2;
} Ret; // i64, i64 = 16 bytes

Ret func(unsigned long long arg1, unsigned long long arg2) {
    Ret ret;
    ret.field1 = arg1;
    ret.field2 = arg2;
    return ret;
}

int wrapper(int a, int b){
    Ret ret = func(a, b);
    int c = ret.field1 + ret.field2;
    if (c > 10) {
        exit(200);
    }
    return c;
}

int main(int argc, char** argv) {
    return wrapper(0,0); // will be dangling function
}