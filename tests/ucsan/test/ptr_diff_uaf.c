// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 151
// SOLVER-ERROR-ABSENT

/*
 * A pointer bound into another's object by `e - table` is a second pointer
 * label of that object, and free(table) marked only table's label: e still
 * reached the object as live, and the write through it after the free was
 * no use after free.  The free now marks the object (ucsan_obj_freed).
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

	table[0].a = 1;
	free(table);
	e->a = 7;		/* 151 */
	return (int)i;
}
