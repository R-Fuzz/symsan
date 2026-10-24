// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * A struct passed by value is a byval pointer argument, and the caller makes
 * the copy through it: through *q, a UC pointer, that copied through the
 * pseudo-pointer and faulted before 200 was reachable (mr_mfc_find_parent's
 * *mrt->ops.rht_params).  40 bytes, so that x86-64 passes it in memory.
 */
#include <stdlib.h>

struct params {
	long a, b, c, d, e;
};

long use(struct params p);

int cal(struct params *q, int x)
{
	long v = use(*q);

	if (x == 5)
		exit(200);
	return (int)v;
}
