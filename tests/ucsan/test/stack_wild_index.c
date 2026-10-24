// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 152 200

/*
 * A stack array indexed by a value from the seed was left to SymSan's
 * bounds check, which comes after the access's UCSan shadow store.  A wild
 * index (sata_pmp_error_handler's link_tries[link->pmp]) made that store
 * fault first wherever the stack sat: exit status 1, not an OOB.  A
 * variable index into a stack object is now checked by UCSan before it.
 */
#include <stdlib.h>

int cal(long idx)
{
	volatile int tries[15];

	if (idx == 7)
		exit(200);
	if (idx > (1L << 40))
		tries[idx] = 3;
	return tries[0];
}
