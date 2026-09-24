// METADATA: asm_cal.yaml
// FLAG: 200 201

#include <stdlib.h>

/*
 * TaintPass gives every inline asm result a zero label, so a branch on an
 * asm result is never solvable.  Two kernel shapes:
 *
 * - a register-to-register asm (__ffs's `rep; bsf`, arch_hweight's popcnt):
 *   the result depends only on the register operands, so unioning their
 *   labels (what upstream DFSan does) is enough;
 * - a flag output read from a memory operand (variable_test_bit's `bt` with
 *   "=@ccc"): the label has to come from the memory operand's content.
 */
struct obj {
	unsigned long flags;
};

int cal(int x, struct obj *o)
{
	int y;
	_Bool bit;

	__asm__ __volatile__("movl %1, %0" : "=r"(y) : "r"(x));
	if (y == 42)
		exit(200);

	__asm__ __volatile__("btq %2, %1"
			     : "=@ccc"(bit)
			     : "m"(o->flags), "Ir"(3L));
	if (bit)
		exit(201);
	return 0;
}
