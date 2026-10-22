// METADATA: asm_cal.yaml
// ABSENT: 1 201
// FLAG: 200

#include <stdlib.h>

/*
 * A function the module's own top-level asm defines, which asm calls by
 * address with a convention of its own, as KVM's fastop() calls its em_*
 * blocks: one 16-byte stub per operand size, entered at
 * block + index * 16, taking %rdx and returning in %rax.  Out of scope, its
 * C declaration gets an __external$ wrapper; its address must still name the
 * asm's code.  Pointed at the wrapper, the call lands in the middle of
 * compiled C (exit status 1, SIGSEGV).  201 if the stub's result is wrong.
 */
#define FOP_SIZE 16

__asm__(".pushsection .text\n"
	".global fop_block\n"
	".type fop_block, @function\n"
	".balign 16\n"
	"fop_block:\n"
	"	mov %rdx, %rax\n"
	"	ret\n"
	".balign 16\n"
	"	lea 1(%rdx), %rax\n"
	"	ret\n"
	".balign 16\n"
	".size fop_block, . - fop_block\n"
	".popsection\n");

extern void fop_block(void);

static inline __attribute__((always_inline)) unsigned long
fastop(unsigned long v, int idx)
{
	void (*fop)(void) = (void (*)(void))((char *)fop_block + idx * FOP_SIZE);
	unsigned long ret = 0, flags = 0;

	/* fastop()'s shape: the flags go in and out round the call */
	__asm__ __volatile__("push %[flags]; popf; call *%[f]; pushf; pop %[flags]"
			     : "+a"(ret), "+d"(v), [flags] "+D"(flags),
			       [f] "+S"(fop)
			     :
			     : "memory");
	return ret;
}

int cal(int x)
{
	if (fastop(41, 1) != 42)
		exit(201);
	if (fastop(7, 0) != 7)
		exit(201);
	if (x == 9)
		exit(200);
	return 0;
}
