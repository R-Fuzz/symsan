// METADATA: asm_cal.yaml
// FLAG: 200
// SOLVER-ERROR-ABSENT
// CFLAGS: -O2

/*
 * The kernel's memset32 is `rep stosl` (memset16/64: stosw/stosq), which ran
 * as is on a pseudo-pointer (gen6_ppgtt_clear_range): a fault.  It is now a
 * memset of the range, checking the pointer and setting the shadow, then the
 * element pattern written through the checked pointer.
 */
#include <stdlib.h>

static inline void *memset32(unsigned int *s, unsigned int v, unsigned long n)
{
	long d0, d1;
	asm volatile("rep\n\t"
		     "stosl"
		     : "=&c" (d0), "=&D" (d1)
		     : "a" (v), "1" (s), "0" (n)
		     : "memory");
	return s;
}

int cal(unsigned int *p, unsigned int n, int x)
{
	if (n < 4 || n > 6)
		return 0;
	/* p + 8: not the pointer the read below checks, which would be */
	/* reused for the asm; n: a count the lifter cannot unroll */
	memset32(p + 8, 0x11223344u, n);
	if (p[11] == 0x11223344u && x == 7)
		exit(200);
	return 0;
}
