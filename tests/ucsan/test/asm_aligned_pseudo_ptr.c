// METADATA: asm_cal.yaml
// FLAG: 200

/*
 * A lazily created object's offset 0 sat at a page-aligned address whatever
 * the pseudo pointer's value, so a pointer aligned by its value was not
 * aligned in memory.  i915_unaligned_memcpy_from_wc rounds src up to 16
 * bytes and then reads it with movntdqa, which needs that alignment: a
 * general protection fault.  The real address is now the pseudo one's equal
 * modulo the page.
 */
#include <stdlib.h>

int cal(char *src)
{
	unsigned long a = (unsigned long)src;
	char *p = src + (((a + 15) & ~15UL) - a);

	if ((a & 15) != 3)
		return 0;

	asm volatile("movntdqa (%0), %%xmm0" :: "r"(p) : "xmm0", "memory");
	if (p[0] == 'x')
		exit(200);
	return 0;
}
