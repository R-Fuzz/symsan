// METADATA: asm_cal.yaml
// CFLAGS: -O2
// ABSENT: 1
// EVENT-ABSENT: 159
// FLAG: 201

#include <stdlib.h>

/*
 * Pointers the program keeps as integers -- a tagged pointer (sg_page's
 * `page_link & ~3`) and an array base (vmemmap_base) -- whose difference it
 * divides by the element size (page_to_pfn): `sdiv exact`, as the pointers
 * are into one array.  Their values are seed bytes that only have to satisfy
 * the path, so a seed that breaks the exactness is their placement, not the
 * program's UB: solved back to hold, not reported (159, INEXACT_DIV).  That
 * needs the bytes recorded as a pointer's, which they are once the program
 * turns them into one (inttoptr), as a pointer load records its bytes.
 */
struct rec {
	int a, b, c;
};

int cal(unsigned long link, unsigned long base)
{
	struct rec *p = (struct rec *)(link & ~3UL);
	struct rec *b = (struct rec *)base;
	volatile long d;

	/* solved knowing nothing of the division: may break it */
	if (p == b)
		return 0;
	if (p->a != 1 || b->a != 2)
		return 0;
	d = p - b;
	if (d == 3)
		exit(201);
	return 0;
}
