// METADATA: asm_cal.yaml
// ENV: trace_bounds KO_RESIGN_PTRARGS
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * Resign must not write memory to find out whether it may.  touch() is out
 * of scope, so its pointer argument is resigned; the pointer has no UCSan
 * label and its size is not known (it went through an integer), so there is
 * nothing to overlay.  The writability probe that ran first read /dev/zero
 * into it all the same, and the global it points to -- already symbolized,
 * and holding the seed's 0x1234 -- lost its low byte behind its SymSan label:
 * the second test was a value mismatch and 200 unreachable
 * (init_hugetlbfs_fs's default_hstate_idx in the kernel eval).  What resign
 * may write is now decided from what the pointer is, not by trying.
 */
#include <stdlib.h>

int g;

void touch(void *p);

int cal(int n)
{
	volatile long z = 0;

	if (g != 0x1234)
		return 0;
	touch((void *)((unsigned long)&g + z));
	if (g == 0x1234)
		exit(200);
	return n;
}
