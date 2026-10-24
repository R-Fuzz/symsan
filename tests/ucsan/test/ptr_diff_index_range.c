// METADATA: asm_cal.yaml
// CFLAGS: -O2
// ABSENT: 1 124
// DISCARD: 203
// FLAG: 204

#include <stdlib.h>

/*
 * The element index of two unrelated pointers is a fresh value i, and p is
 * bound to q[i] -- in q's object, which is no larger than UCSan's object
 * size limit, so i is within it too.  Unassumed, the solver took any i that
 * flipped a branch on one of its bits (i915's do_bit_17_swizzle, pfn bit
 * 5), and the first access through p ended the run, the object too large
 * (124).  An index past any object is infeasible: only an optimistic
 * solution (the branch alone, when the path makes it unsat) has one, and
 * then p is not bound -- its own object, as before the binding -- and the
 * seed is solved for an index that is (203 may be reached that way).  A bit
 * an index in an object has is feasible (204).
 */
struct rec {
	long x[8];
};

int cal(struct rec *p, struct rec *q)
{
	volatile long i = p - q;

	if (i > (1L << 40)) {
		p->x[0] = 1;
		exit(203);
	}
	if ((i >> 5) & 1) {
		p->x[0] = 1;
		exit(204);
	}
	return 0;
}
