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
// EXPECT-FAIL (string-theory gap, 2026-06): the solver computes the correct
// model — debug shows `str-1-0-1: ... new=6, raw='ACDEB@'` ('@' at offset 5) —
// but exit(201) is never reached. The string-variable solution changes the
// buffer length (here 1->6), and length-changing str- solutions (INSERT/DELETE/
// shrink) do not round-trip into a UC-materialized object. The plumbing is fine
// (a non-string UC branch reaching exit() passes), and the fread-backed symsan
// version (tests/strchr_plant_gap.c) passes; only the UC object path fails.
// See memchr_plant.c — it fails the same way even with no growth needed.

#include <stdlib.h>
#include <string.h>

int cal(char *c) {
    char *p = strchr(c, '@');
    if (p && (p - c) == 5) {
        exit(201);
    }
    return 0;
}
