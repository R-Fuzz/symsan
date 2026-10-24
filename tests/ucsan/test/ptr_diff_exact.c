// METADATA: ptr_diff_exact.yaml
// CFLAGS: -O2
// ABSENT: 1 200 159
// FLAG: 201
// SOLVER-ERROR-ABSENT

#include <stdlib.h>

/*
 * A pointer difference is an `sdiv exact` by the element size, which the
 * compiled code does by shifting and multiplying by the inverse: the quotient
 * only when the pointers are a whole number of elements apart
 * (intel_pmu_drain_pebs_core's (top - at) / 144).  The exactness is assumed
 * on the path, so q - p == 3 means a byte difference of 36 (201), and with
 * any other (200) it is infeasible.  Without the assumption the solver
 * answered off in 37..47, which the binary divides to 3 for 37..39 (200) and
 * to something else above (a value mismatch).  A seed solved for a point
 * before the division, which knows nothing of it, may break it: the pseudo
 * pointer p is part of the difference, so that is its placement, not the
 * program's UB -- not reported (159, INEXACT_DIV) but solved back to hold.
 */
struct rec {
	int a, b, c;
};

int cal(struct rec *p, long off)
{
	struct rec *q = (struct rec *)((char *)p + off);
	/* volatile: compared directly, q - p == 3 folds to a byte difference */
	volatile long d = q - p;

	if (d == 3) {
		if (off != 36)
			exit(200);
		exit(201);
	}
	return 0;
}
