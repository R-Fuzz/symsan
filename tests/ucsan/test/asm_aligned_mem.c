// METADATA: asm_cal.yaml
// FLAG: 200

/*
 * A legacy SSE instruction's 16-byte memory operand must be 16-byte aligned,
 * and an asm memory ("m") operand was checked with no alignment, so the
 * runtime placed its object without one: the pxor faulted.  The operand's
 * check now asks for what the instructions naming it need (see
 * asm_aligned_access.c for a register pointer).
 */
#include <stdlib.h>

typedef struct { char b[16]; } v16;

int cal(char *src)
{
	unsigned long a = (unsigned long)src;
	char *p = src + (((a + 15) & ~15UL) - a);

	if ((a & 15) != 3)
		return 0;

	asm volatile("pxor %0, %%xmm0" :: "m"(*(v16 *)p) : "xmm0");
	if (p[0] == 'x')
		exit(200);
	return 0;
}
