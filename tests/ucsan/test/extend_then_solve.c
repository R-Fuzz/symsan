// METADATA: asm_cal.yaml
// ABSENT: 210
// FLAG: 200

#include <stddef.h>
#include <stdlib.h>

/*
 * A branch solved in the run that extends its object backwards (container_of
 * reaching before the member the function was handed): the solution has to
 * land on the bytes the branch read.  The manager used to convert solver
 * offsets with the object's lower length *after* the extension, so the answer
 * for p->b landed 8 bytes low, on p->a (210 in the next run).  The check reads
 * p->a through an empty asm, whose result has no label, so the solver has no
 * branch of its own to put K there.
 */
#define K 0x4142434445464748L

struct s {
	long a;
	long b;
};

struct outer {
	long pre;
	struct s in;
};

int cal(struct s *p)
{
	struct outer *o = (struct outer *)((char *)p - offsetof(struct outer, in));
	long x = p->b;	/* materializes the object, offset 0 at p */
	long a;

	o->pre = 1;	/* before the object: extends it backwards */
	if (p->b == K)
		exit(200);
	a = p->a;
	__asm__ __volatile__("" : "+r"(a));	/* drops the label */
	if (a == K)
		exit(210);
	return (int)x;
}
