// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 152 200

/*
 * A memset of a stack object for a length from the seed set the UCSan
 * shadow for that length before SymSan's bounds check (memzero_explicit of
 * a stack shash_desc, jent_hash_time): with a wild length the shadow write
 * faulted first, exit status 1.  UCSan now checks such a write's bounds.
 */
#include <stdlib.h>
#include <string.h>

int cal(unsigned long n)
{
	volatile char d[16];

	if (n == 7)
		exit(200);
	if (n > (1UL << 40))
		memset((char *)d, 0, n);
	return d[0];
}
