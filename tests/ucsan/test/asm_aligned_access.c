// METADATA: asm_cal.yaml
// FLAG: 200

/*
 * An asm's aligned vector move through a register pointer needs the real
 * address aligned, and the pointer was checked with no alignment, so the
 * runtime placed its object without one.  i915_unaligned_memcpy_from_wc
 * rounds src up to 16 bytes by its (pseudo) value and reads it with
 * movntdqa: a general protection fault.  The check now asks for the move's
 * alignment, and the runtime places the object so the pointer's offset in it
 * is aligned -- by the offset, never the pseudo value.
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
