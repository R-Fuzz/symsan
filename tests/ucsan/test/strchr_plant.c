// METADATA: note.yaml
// FLAG: 201
//
// String-theory under under-constrained exploration: plant a delimiter at a
// pinned offset in a UC-materialized buffer.
//
// `c` is a UC char* — its backing bytes are materialized lazily (assume_allocated
// path). The solver must plant '@' at exactly offset 5 so strchr finds it there,
// driving exploration into the exit(201) path. Mirrors the symsan-level
// tests/strchr_plant_filled.c, but here the buffer is UC-materialized rather than
// fread-backed, which exercises a different provenance path.
//
// Relies on __taint_union_store/load keeping indexof (strchr) labels intact
// across pointer spills so z3-ts's existing Int-sort folds still see the
// search result, and on next-seed INSERT + pack_len growing the UC object.

#include <stdlib.h>
#include <string.h>

int cal(char *c) {
    char *p = strchr(c, '@');
    if (p && (p - c) == 5) {
        exit(201);
    }
    return 0;
}
