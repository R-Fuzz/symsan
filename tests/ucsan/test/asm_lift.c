// METADATA: asm_cal.yaml
// SOLVER-ERROR-ABSENT
// FLAG: 200 201 202 203 204 205 206
// ABSENT: 210 211 212 213 214 215 216 217

#include <stdlib.h>

/*
 * Inline asm made of plain integer instructions is lifted to IR, so its
 * results carry labels and its memory effects are exact.  The shapes are the
 * kernel's (arch/x86/include/asm/{atomic,bitops,cmpxchg,percpu}.h):
 *
 * - atomic_add_return: `lock; xaddl`, the old value comes back (200);
 * - atomic_dec_and_test: `lock; decl` into "=@cce" (201);
 * - test_and_set_bit / clear_bit: `lock; btsq` into "=@ccc" / `lock; btrq`
 *   (202), with the bit really set and cleared (211, 212);
 * - try_cmpxchg: `lock; cmpxchgl` into "=@ccz" (203), storing on success
 *   (213);
 * - this_cpu_inc / this_cpu_read: `incl %gs:` / `movl %gs:` on a percpu
 *   variable, taken as plain memory while the %gs base is 0 (204);
 * - __ffs: `rep; bsf`, whose value must match (214).  (Its result has no
 *   label: TaintPass has no operation for cttz.)
 * - array_index_mask_nospec: `cmp; sbb`, a mask from the carry flag, whose
 *   branch is solvable (205) and whose value matches the C (215);
 * - csum_add: `addl; adcl $0`, the carry folded back in (216);
 * - unsafe_get_user / unsafe_put_user: an asm goto whose label is the
 *   exception-table fixup; the access falls through to the default path,
 *   and the value read is solvable (206) and the one written lands (217).
 *
 * 210 checks that the xadd result and the memory agree.
 */
#define LOCK_PREFIX							\
	".pushsection .smp_locks,\"a\"\n"				\
	".balign 4\n"							\
	".long 671f - .\n"						\
	".popsection\n"							\
	"671:\n\tlock; "

struct obj {
	int counter;
	unsigned long flags;
};

static int pcpu_count; /* stands in for a percpu variable */

static inline __attribute__((always_inline)) int
atomic_add_return(int i, int *v)
{
	int old = i;

	__asm__ __volatile__(LOCK_PREFIX "xaddl %0, %1"
			     : "+r"(old), "+m"(*v)
			     : : "memory", "cc");
	return old + i;
}

static inline __attribute__((always_inline)) _Bool
atomic_dec_and_test(int *v)
{
	_Bool z;

	__asm__ __volatile__(LOCK_PREFIX "decl %0"
			     : "+m"(*v), "=@cce"(z)
			     : : "memory");
	return z;
}

static inline __attribute__((always_inline)) _Bool
test_and_set_bit(long nr, unsigned long *addr)
{
	_Bool c;

	__asm__ __volatile__(LOCK_PREFIX "btsq %2, %0"
			     : "+m"(*addr), "=@ccc"(c)
			     : "Ir"(nr) : "memory");
	return c;
}

static inline __attribute__((always_inline)) void
clear_bit(long nr, unsigned long *addr)
{
	__asm__ __volatile__(LOCK_PREFIX "btrq %1, %0"
			     : "+m"(*addr)
			     : "Ir"(nr) : "memory");
}

static inline __attribute__((always_inline)) _Bool
try_cmpxchg(int *p, int *old, int new)
{
	_Bool ok;
	int o = *old;

	__asm__ __volatile__(LOCK_PREFIX "cmpxchgl %3, %1"
			     : "=@ccz"(ok), "+m"(*p), "+a"(o)
			     : "r"(new) : "memory");
	if (!ok)
		*old = o;
	return ok;
}

static inline __attribute__((always_inline)) void this_cpu_inc(void)
{
	__asm__ __volatile__("incl %%gs:%0" : "+m"(pcpu_count));
}

static inline __attribute__((always_inline)) int this_cpu_read(void)
{
	int v;

	__asm__("movl %%gs:%1, %0" : "=r"(v) : "m"(pcpu_count));
	return v;
}

static inline __attribute__((always_inline)) unsigned long
__ffs(unsigned long word)
{
	__asm__("rep; bsf %1,%0" : "=r"(word) : "rm"(word));
	return word;
}

static inline __attribute__((always_inline)) unsigned long
array_index_mask_nospec(unsigned long index, unsigned long size)
{
	unsigned long mask;

	__asm__ __volatile__("cmp %1,%2; sbb %0,%0;"
			     : "=r"(mask)
			     : "g"(size), "r"(index));
	return mask;
}

static inline __attribute__((always_inline)) unsigned int
csum_add(unsigned int a, unsigned int b)
{
	__asm__("addl %1, %0\n\tadcl $0, %0" : "+r"(a) : "rm"(b));
	return a;
}

#define EX_TABLE(label)							\
	" .pushsection \"__ex_table\",\"a\"\n"				\
	" .balign 4\n"							\
	" .long (1b) - .\n"						\
	" .long (" label ") - .\n"					\
	" .long 3\n"							\
	" .popsection\n"

static inline __attribute__((always_inline)) int
unsafe_get_user(unsigned int *val, unsigned int *uptr)
{
	unsigned int v;

	__asm__ goto("\n1:\tmovl %1,%0\n" EX_TABLE("%l2")
		     : "=r"(v) : "m"(*uptr) : : efault);
	*val = v;
	return 0;
efault:
	return -14;
}

static inline __attribute__((always_inline)) int
unsafe_put_user(unsigned int v, unsigned int *uptr)
{
	__asm__ goto("\n1:\tmovl %0,%1\n" EX_TABLE("%l2")
		     : : "ir"(v), "m"(*uptr) : : efault);
	return 0;
efault:
	return -14;
}

int cal(struct obj *o, int x, unsigned long w, unsigned long idx,
	unsigned int *uptr)
{
	unsigned int v;
	unsigned long m;
	unsigned int c;
	int r, old;

	r = atomic_add_return(5, &o->counter);
	if (o->counter != r)
		exit(210);
	if (r == 42)
		exit(200);

	if (atomic_dec_and_test(&o->counter))
		exit(201);

	if (test_and_set_bit(3, &o->flags))
		exit(202);
	if (!(o->flags & 8))
		exit(211);
	clear_bit(3, &o->flags);
	if (o->flags & 8)
		exit(212);

	old = x;
	if (try_cmpxchg(&o->counter, &old, 7)) {
		if (o->counter != 7)
			exit(213);
		exit(203);
	}

	this_cpu_inc();
	if (this_cpu_read() == 99)
		exit(204);

	if (w && __ffs(w) != (unsigned long)__builtin_ctzl(w))
		exit(214);

	m = array_index_mask_nospec(idx, 16);
	if (m != (idx < 16 ? ~0UL : 0UL))
		exit(215);
	if (m && idx)
		exit(205);

	c = csum_add((unsigned int)x, 0x80000000u);
	if (c != (unsigned int)((unsigned long)(unsigned int)x + 0x80000000u +
				(((unsigned long)(unsigned int)x + 0x80000000u) >> 32)))
		exit(216);

	if (unsafe_get_user(&v, uptr) == 0 && v == 0x4242)
		exit(206);
	unsafe_put_user(0x77, uptr);
	if (*uptr != 0x77)
		exit(217);
	return 0;
}
