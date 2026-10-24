// METADATA: asm_cal.yaml
// SOLVER-ERROR-ABSENT
// ABSENT: 201 202 203
// DISCARD: 200

#include <stdlib.h>

/*
 * An inline asm memory output ("=m"/"+m") is written concretely, so any
 * symbolic label the memory held before the asm is stale afterwards.  The
 * passes must drop it (the value becomes concrete); otherwise the next
 * comparison is built on the pre-asm input byte and the solver rejects it
 * ("value mismatch") or answers a question the program no longer asks.
 *
 * Three owners of the memory, each read *before* the asm so it is already
 * symbolic when the asm runs: a BSS global, a field of a symbolic argument
 * struct (the kernel's atomic_inc on a refcount), and a stack local.
 */
struct obj {
	int refcnt;
	int flags;
};

static int preempt_count;

int cal(struct obj *o, int x)
{
	int old, y;

	if (preempt_count == 7)
		exit(200);
	__asm__ __volatile__("movl $1, %0" : "=m"(preempt_count) :: "memory");
	if (preempt_count != 1)
		exit(201);

	old = o->refcnt;
	__asm__ __volatile__("lock; incl %0" : "+m"(o->refcnt) :: "memory");
	if (o->refcnt != old + 1)
		exit(202);

	y = x;
	if (y == 7)
		exit(200);
	__asm__ __volatile__("movl $3, %0" : "=m"(y) :: "memory");
	if (y != 3)
		exit(203);
	return 0;
}
