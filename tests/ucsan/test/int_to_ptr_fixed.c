// METADATA: asm_cal.yaml
// ABSENT: 2 202
// FLAG: 1 201

#include <stdlib.h>

/*
 * A pointer the program computes as an integer, from no input: a kernel
 * address (page_offset_base + x, a fixmap slot) that no user process has.
 * With no label it was taken for a real pointer, and the access faulted
 * (exit status 1).  It is a pseudo pointer: its object comes from the seed
 * (201), and the same address is the same object (not 202).  A
 * non-canonical address is a sentinel (LIST_POISON), and must still fault
 * (1), not become an object (2).
 */
volatile unsigned long base;

int cal(int i)
{
	unsigned long a = base = 0xffff888000001000UL;
	int *p = (int *)a, *q = (int *)base;

	if (i == 7) {
		*(int *)(base + 0x5ead000000000000UL) = 1;
		exit(2);
	}
	*p = 5;
	if (*q != 5)
		exit(202);
	if (p[1] == 0x1234)
		exit(201);
	return 0;
}
