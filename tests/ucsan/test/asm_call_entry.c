// METADATA: asm_cal.yaml
// CFLAGS: -O2
// ABSENT: 1 205
// FLAG: 122 200

#include <stdlib.h>

/*
 * KVM's fastop(): `call *fop` with fop = em_bsr + __ffs(dst.bytes) * 16, a
 * block whose entries the module asm defines as functions of their own.
 * The kernel keeps dst.bytes at 1, 2, 4 or 8; under UC it is the seed's, and
 * past the entries the call ran whatever code lay there (em_bsr_c: exit
 * status 1).  Landing on an entry is an invariant of the code: a seed that
 * breaks it ends the run (122, REASON_INVALID_INPUT), and is not the
 * program's (205).
 */
#define FOP_SIZE 16

__asm__(".pushsection .text\n"
	".global fop_blk\n"
	".balign 16\n"
	"fop_blk:\n"
	".balign 16\n"
	".type fop_blk_id, @function\n"
	"fop_blk_id:\n"
	"	mov %rdx, %rax\n"
	"	ret\n"
	".size fop_blk_id, .-fop_blk_id\n"
	".balign 16\n"
	".type fop_blk_inc, @function\n"
	"fop_blk_inc:\n"
	"	lea 1(%rdx), %rax\n"
	"	ret\n"
	".size fop_blk_inc, .-fop_blk_inc\n"
	".popsection\n"
	/* what lies past the block */
	".pushsection .text\n"
	".balign 16\n"
	"after_blk:\n"
	"	ud2\n"
	".popsection\n");

extern void fop_blk(void);

static inline __attribute__((always_inline)) unsigned long
fastop(unsigned long v, unsigned int idx)
{
	void (*fop)(void) = (void (*)(void))((char *)fop_blk + idx * FOP_SIZE);
	unsigned long ret = 0, flags = 0;

	__asm__ __volatile__("push %[flags]; popf; call *%[f]; pushf; pop %[flags]"
			     : "+a"(ret), "+d"(v), [flags] "+D"(flags),
			       [f] "+S"(fop)
			     :
			     : "memory");
	return ret;
}

int cal(int x, unsigned int idx)
{
	/* past the block, where no entry is (and idx << 4 does not wrap) */
	if (x == 3 && idx > 5 && idx < 100) {
		fastop(41, idx);
		exit(205);
	}
	if (x == 9 && idx < 2) {
		fastop(41, idx);
		exit(200);
	}
	return 0;
}
