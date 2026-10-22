// METADATA: asm_cal.yaml
// ABSENT: 1 201
// FLAG: 200 202

#include <stdlib.h>

/*
 * String port I/O (`rep; insb`, `rep; outsw`), as the kernel's insb/outsw
 * write it (ioread8_rep, iowrite16_rep).  Run as is it is privileged and
 * faults (SIGSEGV with SI_KERNEL, then Die() -> exit status 1).  It is
 * lowered to a loop instead: each element in is a fresh symbolic value
 * stored to the buffer, so a branch on one is solvable (200), and each
 * element out a read of the buffer (202 is past it).  The outputs are the
 * pointer advanced past the buffer and a zero count (201 if not).
 */
int cal(int x)
{
	unsigned char buf[4] = { 0 };
	void *p = buf;
	unsigned long n = sizeof(buf);

	__asm__ __volatile__("rep; insb"
			     : "+D"(p), "+c"(n)
			     : "d"((unsigned short)0x60)
			     : "memory");
	if (p != buf + sizeof(buf) || n != 0)
		exit(201);
	if (buf[2] == 0x42)
		exit(200);

	unsigned short w[2] = { 1, 2 };
	const void *q = w;
	unsigned long m = 2;

	__asm__ __volatile__("rep; outsw"
			     : "+S"(q), "+c"(m)
			     : "d"((unsigned short)0x60)
			     : "memory");
	if (q != (const char *)w + sizeof(w) || m != 0)
		exit(201);
	if (x == 7)
		exit(202);
	return 0;
}
