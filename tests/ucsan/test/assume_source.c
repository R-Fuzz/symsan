// METADATA: assume_source.yaml
// FLAG: 200
// ABSENT: 122 201

// An assumption the source states itself (a unit-test harness's
// ucsan_ut::assume, a spec's precondition), not one UCSanPass inserts: the
// solver must keep it.  TaintPass gave the solver only the ones UCSanPass
// made (nosanitize), so a source-level __dfsw_ucsan_assume rejected seeds
// (122) without constraining them: here the solver flipped *a == 1000 to a
// seed that broke 0 <= *a <= 100, and every flip of a branch on *a was free
// to do the same.
//
//   0 <= *a <= 100: assumed            -> no seed for *a == 1000 (no 122, 201)
//   *a == 77:                          -> exit(200)
#include <stdlib.h>

extern void __dfsw_ucsan_assume(_Bool holds);

int entry(int *a) {
    __dfsw_ucsan_assume((*a >= 0) & (*a <= 100));
    if (*a > 50) {
        if (*a == 77)
            exit(200);
    }
    if (*a == 1000)
        exit(201);
    return 0;
}
