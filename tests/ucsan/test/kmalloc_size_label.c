// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * The allocation's symbolic size (its bound's l2) comes from the label of
 * the size argument TaintPass hands __taint_minimize_label, and for
 * kmalloc(size, flags) it took the flags: a size check into the buffer then
 * compared bytes with gfp, a value mismatch (i915_deps_grow's memcpy into
 * its kmalloc_array).  Here gfp is symbolic and the size concrete.
 */
#include <stdlib.h>
#include <string.h>

void *__kmalloc(unsigned long size, unsigned int flags);

int cal(unsigned int gfp, unsigned int m)
{
	char *p = __kmalloc(64, gfp);

	if (!p)
		return 0;
	if (m > 8)
		return 0;
	memset(p, 0, m * 8);
	if (m == 5)
		exit(200);
	return 1;
}
