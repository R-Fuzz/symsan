// METADATA: asm_cal.yaml
// ABSENT: 1
// FLAG: 200

#include <stdlib.h>

/*
 * An array declared without a size and defined in another file, as
 * io_uring's `extern const struct io_cold_def io_cold_defs[]`.  Its weak
 * definition has no bytes, and read past it the entries were whatever lay
 * there, unlabeled: a branch on a field could not be flipped, and a function
 * pointer found there was called (io_req_prep_async, exit status 1).  It is
 * an under-constrained object: its entries come from the seed, and grow with
 * use.
 */
struct def {
	int x;
	void (*fn)(void);
};

extern const struct def defs[];

int cal(int i)
{
	if (i < 0 || i > 8)
		return 0;
	if (defs[i].fn)
		defs[i].fn();
	if (defs[i].x == 0x55)
		exit(200);
	return 0;
}
