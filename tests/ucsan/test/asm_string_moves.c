// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * String moves through (%rsi) to (%rdi) from a UC pointer: arch/x86/lib/
 * iomem.c's movs() and rep_movs().  Run natively they copied through the
 * pseudo-pointer and faulted; lowered to memcpy, the bytes and their labels
 * arrive, so 200 is solvable through them.  always_inline: the asm has to be
 * in cal, the only function in scope.
 */
#include <stdlib.h>

#define movs(type, to, from) \
	asm volatile("movs" type \
		     : "=&D" (to), "=&S" (from) \
		     : "0" (to), "1" (from) \
		     : "memory")

static inline __attribute__((always_inline))
void rep_movs(void *to, const void *from, unsigned long n)
{
	unsigned long d0, d1, d2;
	asm volatile("rep ; movsl\n\t"
		     "testb $2,%b4\n\t"
		     "je 1f\n\t"
		     "movsw\n"
		     "1:\ttestb $1,%b4\n\t"
		     "je 2f\n\t"
		     "movsb\n"
		     "2:"
		     : "=&c" (d0), "=&D" (d1), "=&S" (d2)
		     : "0" (n / 4), "q" (n), "1" ((long)to), "2" ((long)from)
		     : "memory");
}

int cal(const char *src, unsigned long n)
{
	char buf[16];
	char one;
	char *to = &one;
	const char *from = src;

	if (n > 16)
		return 0;
	movs("b", to, from);
	rep_movs(buf, src, n);
	if (one == 'Q' && n == 7 && buf[6] == 'Z')
		exit(200);
	return 0;
}
