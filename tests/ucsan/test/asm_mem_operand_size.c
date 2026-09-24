// METADATA: asm_cal.yaml
// ENV: trace_bounds
// SOLVER-ERROR-ABSENT
// ABSENT: 152 201
// DISCARD: 200

#include <stdlib.h>

/*
 * A checked inline asm memory operand must be checked with the size of the
 * access, i.e. the operand's elementtype, not a size derived from the
 * underlying object.  Two ways the size goes wrong:
 *
 * - through an argument/heap pointer the size is 0.  When the asm is the
 *   first access, no bytes are symbolized for it; they are symbolized later,
 *   from the seed, at the first C read -- after the asm already wrote them --
 *   so the solver's value for the byte disagrees with memory.  (Reaching the
 *   memory through a field GEP hides this: the GEP is checked with the
 *   struct's size first.  A bare `*p`, e.g. atomic_t at offset 0 with the GEP
 *   folded away, does not.)  Integer asm such as `lock; incl` is now lifted
 *   to IR instead, so the asm here is __raw_save_flags (`pushf ; pop` into an
 *   "=rm" operand), which runs as is; EFLAGS bit 1 always reads as 1 (201).
 * - through a variable index into a global the size is the whole global,
 *   checked at the element's offset, which is a false out-of-bounds for every
 *   element past the first.
 */
int counters[4];

int cal(unsigned long *p, int i)
{
	__asm__ __volatile__("# __raw_save_flags\n\tpushf ; pop %0"
			     : "=rm"(*p) : : "memory");
	if (!(*p & 2))
		exit(201);

	if (i < 0 || i >= 4)
		return 0;
	__asm__ __volatile__("lock; incl %0" : "+m"(counters[i]) :: "memory");
	if (i == 3)
		exit(200);
	return 0;
}
