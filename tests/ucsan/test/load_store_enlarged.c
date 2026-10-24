// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * A load whose bytes are an input's consecutive offsets, but not its
 * consecutive labels, must not be taken for a Load(label0, n): a store of it
 * breaks it up as label0 + i.  p's object is created one byte long by p[0],
 * and reading p[12] enlarges it, labelling offsets 1..12 only then, after
 * the labels the first test made.  The 8-byte load of offsets 0..7 became a Load of the
 * first byte's label, the store of it at p + 16 wrote the labels that
 * followed it -- the first test's comparison among them -- and the reload was
 * a Concat of that comparison's low bits: a value mismatch, and 200
 * unsolvable (bprm_execve's container_of pointer in the kernel eval).
 */
#include <stdlib.h>

int cal(unsigned char *p)
{
	unsigned long *src = (unsigned long *)p;
	unsigned long *dst = (unsigned long *)(p + 16);

	if (p[0] != 1)
		return 0;
	(void)*(volatile unsigned char *)(p + 12);	/* enlarges, in this run */
	*dst = *src;
	if (*dst == 0x0807060504030201UL)
		exit(200);
	return 1;
}
