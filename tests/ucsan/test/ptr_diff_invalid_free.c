// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 158
// SOLVER-ERROR-ABSENT

/*
 * free() of a pointer that `e - table` bound to element i of table's object:
 * for i != 0 the address is inside the object -- element 0, accessed, is
 * below it -- and that is an invalid free (158), not a free of the object
 * (which would then report the use of table[0] as a use after free).  i is
 * the fresh index; any i but 0 is one.
 */
#include <stdlib.h>

struct elem {
	int a;
	int b[13];
};

struct elem *table;

int cal(struct elem *e)
{
	long i = e - table;

	if (table[0].a != 1)
		return 0;
	if (i != 0)
		free(e);	/* 158 */
	return 0;
}
