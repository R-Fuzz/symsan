// METADATA: note.yaml
//-- FLAG: 200
// NOTE: Uses %rbx (64-bit) not %ebx (32-bit) because UCSan uses
//       64-bit shadow memory addresses on x86-64
int cal(int *a, int b) {
    int x = 500, y = 200, z;

    asm("addl (%%rbx), %%eax;"
        "movl %%eax, %%ecx;"
        : "=c"  (z)
        : "a"   (b), "b" (a)
        :                   /* empty clobber-list */
    );

    if (z == 700)
        exit(200);

    return 0;
}