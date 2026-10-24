// METADATA: asm_cal.yaml
// FLAG: 200
// ABSENT: 1

/*
 * __memcpy_flushcache copies through integer addresses with movq/movnti.
 * The lifter knew mov but not movnti, so the whole asm ran natively and
 * its load dereferenced the source pseudo-pointer (NULL): a SIGSEGV, exit 1.
 * movnti is a store; the non-temporal hint means nothing here.
 */
#include <stdlib.h>

int cal(long *src)
{
	long dst = 0;
	unsigned long s = (unsigned long)src, d = (unsigned long)&dst;

	asm("movq    (%0), %%r8\n"
	    "movnti  %%r8, (%1)\n"
	    :: "r" (s), "r" (d)
	    : "memory", "r8");
	if (dst == 0x1234)
		exit(200);
	return 0;
}
