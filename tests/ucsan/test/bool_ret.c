// METADATA: note.yaml
// FLAG: 200
typedef enum { false, true } bool;
bool external(){
    return false;
}

int cal(int a, int b) {
    if (external()){
        exit(200);
    }
}