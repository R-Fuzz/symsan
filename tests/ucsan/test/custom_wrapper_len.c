// METADATA: asm_cal.yaml
// FLAG: 124
// ABSENT: 1 200

/*
 * A wrapper with a byte count (abilist sizeN, here _copy_from_user=size2)
 * copies that many bytes behind its pointer arguments, and the call site
 * checked them for the pointee's size (0 for a void * buffer) instead: the
 * object size limit never saw the count, and the wrapper copied it past the
 * object, data and both shadows (200 here; i915_gem_execbuffer2_ioctl went
 * over 6 GB).  The count is now the checked size, and one above the limit
 * ends the run (REASON_OBJ_OOB, 124).
 */
#include <stdlib.h>

unsigned long _copy_from_user(void *to, const void *from, unsigned long n);

int cal(void *to, const void *from, unsigned long n)
{
	if (n > (1 << 20)) {
		_copy_from_user(to, from, n);
		exit(200);
	}
	return 0;
}
