// METADATA: recursive_cpp.yaml
// FLAG: 125
// ENV: KO_USE_NATIVE_LIBCXX

// C++ port of recursive.c: wraps the recursive function inside a class
// method to test that the engine correctly handles recursive method calls
// via 'this' pointer and stack frame tracking.

class Walker {
public:
    void walk(int* args) {
        if (args[0] == 0) {
            walk(args + 1);
        }
    }
};

int cal(int* args) {
    Walker w;
    w.walk(args);
    return 0;
}
