// METADATA: note.yaml
// FLAG: 202
//
// String-theory DIAGNOSTIC under UC exploration: plant a byte at a pinned offset
// using memchr (length-bounded, not strlen/NUL-bounded).
//
// memchr(c, '@', 8) searches a fixed 8-byte window, so the UC buffer is
// materialized at size 8 up front. The solver may still emit a shorter str-
// model (e.g. 8->6); next-seed DELETE + pack_len must round-trip that size so
// replay hits exit(202) with '@' at offset 5.
//
// Pairs with strchr_plant.c (growth path). Both need indexof labels to survive
// pointer spill/reload without Extract/Concat decomposition.

#include <stdlib.h>
#include <string.h>

int cal(char *c) {
    char *p = (char *)memchr(c, '@', 8);
    if (p && (p - c) == 5) {
        exit(202);
    }
    return 0;
}
