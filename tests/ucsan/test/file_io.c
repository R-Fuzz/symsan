// METADATA: note.yaml
// FLAG: 200 201 202

#include <stdio.h>
#include <stdlib.h>

int cal(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) return 0;

    int a = fgetc(fp);
    int b = fgetc(fp);
    unsigned char buf[4];
    if (fread(buf, 1, 4, fp) != 4) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    if (a == 0xab) {
        if (b == 0xcd) {
            exit(200);
        }
        exit(201);
    }
    if (buf[0] == 0x11 && buf[3] == 0x44) {
        exit(202);
    }
    return 0;
}
