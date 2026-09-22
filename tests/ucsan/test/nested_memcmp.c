// METADATA: note.yaml
// FLAG: 200
// FLAG: 123

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char header[] = "MAGIC";

int foo(unsigned char *data) {
    if (memcmp(data, header, 5) != 0) {
        return 0;
    }
    exit(200);
}

int cal(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return 0;
    unsigned char buf[16];
    int found = 0;
    while (fread(buf, 1, 8, fp) == 8) {
        if (memcmp(buf, "MAG", 3) != 0)
            continue;
        found = 1;
        break;
    }
    fclose(fp);
    if (found)
        foo(buf);
    return 0;
}
