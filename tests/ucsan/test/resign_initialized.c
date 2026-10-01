// METADATA: asm_cal.yaml
// ENV: KO_RESIGN_PTRARGS
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * Resigning a pointer whose object is already initialized keeps that object.
 * p's object exists by the time touch() (out of scope) is called with p.
 * Resign used to mark p uninitialized again, but lazy init had reused the
 * fields the object is found by -- (parent, offset) -- for (obj_label,
 * pseudo_base), so the read of p->b made a new object from a label number and
 * a pseudo pointer.  A kernel pointer is past INT32_MAX as an offset, and
 * lookup_object gave up on it: the object had no id the seed knows, and the
 * solution for p->b never reached it (200), or a branch on it was a value
 * mismatch.  The `|` gives p such a value, as a kernel address would be.
 */
#include <stdlib.h>

struct s {
	int a;
	int b;
};

void touch(struct s *p);

int cal(struct s *p)
{
	p = (struct s *)((unsigned long)p | 0xffff888000000000UL);
	if (p->a != 7)
		return 0;
	touch(p);
	if (p->b == 0x1234)
		exit(200);
	return 1;
}
