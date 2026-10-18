// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * A heap allocation's symbolic size -- its bound's l2, set from the label
 * TaintPass hands __taint_minimize_label -- is compared in bytes by the size
 * UB checks.  calloc(n, sizeof(int)) handed n alone: the memset size below,
 * 4 * m bytes, was checked against n where the bound said 4 * n, a value
 * mismatch.  The label is now the product's.
 */
#include <stdlib.h>
#include <string.h>

int cal(unsigned int n, unsigned int m)
{
	int *a;

	if (n == 0 || n > 16 || m > n)
		return 0;
	a = calloc(n, sizeof(int));
	if (!a)
		return 0;
	memset(a, 1, m * sizeof(int));
	if (m == 5)
		exit(200);
	return 1;
}
