// METADATA: note.yaml
// FLAG: 200
int cal(unsigned int* payload, unsigned int length){
    unsigned int sum = 0;
    if (length > 9) return 0;
    for(int i = 0; i < length; i++) {
        sum += payload[i];
        if (payload[i] > 51) return 0;
    }
    if (sum > 100){
        if (sum > 200) {
            exit(200);
        }
    }

    return sum;
}

// int main(){
//     printf("sum = %d\n" , cal((void*)0,0));
// }