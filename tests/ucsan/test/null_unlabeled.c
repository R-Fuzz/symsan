// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 153 200

/*
 * A NULL that never came from the input -- a local initialized to it -- has
 * no label, and SymSan's memory-error message for dereferencing it was
 * dropped with the other unlabeled ones.  The Die() after it was a bare exit
 * status 1, a failure with nothing to say why (sata_pmp_error_handler); it
 * is a NULL dereference (153).
 */
#include <stdlib.h>

int cal(int x)
{
	int *volatile p = 0;

	if (x == 7)
		exit(200);
	if (x == 9)
		*p = 1;
	return 0;
}
