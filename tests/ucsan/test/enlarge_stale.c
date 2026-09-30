// METADATA: asm_cal.yaml
// CFLAGS: -O2
// ABSENT: 1 210
// FLAG: 200

#include <stddef.h>
#include <stdlib.h>

/*
 * The pass reuses a checked pointer (CheckedPtrMap) for later accesses
 * through the same pointer in a function, and a lazily created object used
 * to move when an access through another pointer enlarged it: the reused
 * address then pointed into the old buffer, so a write through one pointer
 * was not seen through the other (210).  The kernel shape is container_of
 * reaching before the member a function was handed.  Only optimized code
 * keeps the pointer in a register across the enlargement, hence -O2.
 */
struct s {
	long a;
	long b;
};

struct outer {
	long pre;
	struct s in;
};

/* 1, in a way the compiler cannot fold: pa[one] is p->b through another
 * pointer.  Not an argument: the check has to run in the first run, the one
 * that enlarges the object (later seeds start with it enlarged). */
static volatile long one = 1;

int cal(struct s *p)
{
	volatile long *pb = &p->b;
	volatile long *pa = &p->a;
	struct outer *o = (struct outer *)((char *)p - offsetof(struct outer, in));
	long v;

	v = *pb;	/* materializes the object; the store below reuses this check */
	*(volatile long *)&o->pre = 5;	/* before the object: enlarges it */
	*pb = v + 1;
	if (pa[one] != v + 1)
		exit(210);
	exit(200);
}
