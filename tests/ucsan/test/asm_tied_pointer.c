// METADATA: asm_cal.yaml
// FLAG: 200
// ABSENT: 1

/*
 * ip_fast_csum passes the header pointer as an input tied to an output,
 * "1" (iph), and its template dereferences the output's number, (%1).
 * The check for a pointer the template dereferences looked for the
 * input's own number only, so the asm (a loop with adc, which runs as
 * is) read through the unmaterialized pointer: a SIGSEGV, exit 1.
 */
#include <stdlib.h>

int cal(unsigned char *hdr, int x)
{
	const void *iph = hdr;
	unsigned int ihl = 5, sum;

	/* ip_fast_csum, in cal itself: a helper would be out of scope */
	asm("  movl (%1), %0\n"
	    "  subl $4, %2\n"
	    "  jbe 2f\n"
	    "  addl 4(%1), %0\n"
	    "  adcl 8(%1), %0\n"
	    "  adcl 12(%1), %0\n"
	    "1: adcl 16(%1), %0\n"
	    "  lea 4(%1), %1\n"
	    "  decl %2\n"
	    "  jne	1b\n"
	    "  adcl $0, %0\n"
	    "  movl %0, %2\n"
	    "  shrl $16, %0\n"
	    "  addw %w2, %w0\n"
	    "  adcl $0, %0\n"
	    "  notl %0\n"
	    "2:"
	    : "=r" (sum), "=r" (iph), "=r" (ihl)
	    : "1" (iph), "2" (ihl)
	    : "memory");
	if (x == 9 && (unsigned short)sum != 1)
		exit(200);
	return 0;
}
