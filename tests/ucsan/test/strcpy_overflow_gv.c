// METADATA: note.yaml
// FLAG: 152
// ENV: trace_bounds

#include <string.h>
#include <stdlib.h>

#define FILENAMESIZE 64

static char initialLogFileName[FILENAMESIZE] = "";

int cal(char *fileName) {
    if (fileName == NULL) return 0;
    if (initialLogFileName[0] == 0) strcpy(initialLogFileName, fileName);
    return 0;
}
