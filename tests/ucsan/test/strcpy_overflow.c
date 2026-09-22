// METADATA: note.yaml
// FLAG: 152
// ENV: trace_bounds

#include <string.h>
#include <stdlib.h>

#define MAXSTRING 64

int cal(char *path) {
    char dataPath[MAXSTRING];
    if (path == NULL) return 0;
    strcpy(dataPath, path);
    return 0;
}
