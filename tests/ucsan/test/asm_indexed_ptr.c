// METADATA: asm_cal.yaml
// ABSENT: 1
// FLAG: 200

#include <stdlib.h>

/*
 * A pointer handed to asm in a register and dereferenced as the base of a
 * base+index address, as vmx_l1d_flush walks vmx_l1d_flush_pages:
 * `movzbl (%[pages], %%rax), %%ecx`.  The pointer is a global's value from
 * the seed, a pseudo pointer; read unchecked, its value is no address (exit
 * status 1, SIGSEGV).  Checked, it is the object the seed gives it.  The
 * loop is what keeps the asm from being lifted, as in the kernel's.
 */
unsigned char *pages;

int cal(int x)
{
	unsigned int v;

	__asm__ __volatile__("xorl %%eax, %%eax\n"
			     "1:\tmovzbl (%1,%%rax), %0\n\t"
			     "addl $64, %%eax\n\t"
			     "cmpl %%eax, %2\n\t"
			     "jne 1b\n"
			     : "=&c"(v)
			     : "r"(pages), "r"(128)
			     : "eax", "memory");
	(void)v;
	if (x == 3)
		exit(200);
	return 0;
}
