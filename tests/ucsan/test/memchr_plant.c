// METADATA: note.yaml
// FLAG: 202
//
// String-theory DIAGNOSTIC under UC exploration: plant a byte at a pinned offset
// using memchr (length-bounded, not strlen/NUL-bounded).
//
// memchr(c, '@', 8) searches a fixed 8-byte window, so the UC buffer is
// materialized at size 8 up front and no growth is required.
//
// EXPECT-FAIL (string-theory gap, 2026-06): it fails anyway. The solver computes
// a correct model — debug shows `str-1-0-8: ... new=6, raw='DBACE@'` ('@' at
// offset 5) — but it shrinks the buffer 8->6, and length-changing str- solutions
// don't round-trip into the UC object, so exit(202) is never reached. This rules
// OUT "growth-only": even a pre-sized buffer with a same-or-shorter solution
// fails. The shared root cause with strchr_plant.c is length-changing string
// solutions vs fixed-size UC-materialized objects.
//
// Fix hint: the solver prefers a minimal-length model (it shrinks to 6 even
// though "DBACE@XX" would satisfy the constraint at the original length 8). For a
// UC-materialized object of fixed size, generate_solution should prefer a
// SAME-LENGTH in-place SET over INSERT/DELETE/shrink.

#include <stdlib.h>
#include <string.h>

int cal(char *c) {
    char *p = (char *)memchr(c, '@', 8);
    if (p && (p - c) == 5) {
        exit(202);
    }
    return 0;
}
