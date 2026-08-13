// METADATA: note.yaml
// FLAG: 200

/*
    This testcase is used to test the constraint on pseudo-pointer feature.
    The pseudo-pointer is a pointer that is not a real pointer, but is used to
    represent a pointer to a memory location.
    The constraint is applied on the value of the pseudo-pointer itself.
    We should make sure after a pointer arithmetic, the pseudo-pointer base need to be carried when solving the constraint.
   
*/

int cal(int *a) {
    if ((unsigned long)(a+5) == 0x12345678 + 5 * sizeof(int)) {
        if (a == 0x12345678) { // a should be equal to 0x12345678
            exit(200);
        }
    }
    return 0;
}