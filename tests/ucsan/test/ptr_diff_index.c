// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// ABSENT: 201
// SOLVER-ERROR-ABSENT

/*
 * `e - table` of two UC pointers that nothing relates: e is an argument and
 * table a global, two independent roots, though e is &table[i] in every
 * call the program expects (counter_show's `attr - counter_attrs`).  Their
 * pseudo-pointers' difference was any number, and sdiv exact by 56 of a
 * non-multiple is poison: the target multiplied by 7's inverse, the solver
 * divided, and the branch on the index was a value mismatch.  The index is
 * now a fresh symbolic value -- 3 is solvable (200) -- and e is bound to
 * element i of table's object, so a write through e is seen through
 * table[i] (201 never).
 */
#include <stdlib.h>

struct elem {
	int a;
	int b[13];	/* 56 bytes: not a power of two, sdiv exact */
};

struct elem *table;

int cal(struct elem *e)
{
	long i = e - table;

	e->a = 7;
	if (table[i].a != 7)
		exit(201);
	if (i == 3)
		exit(200);
	return 0;
}
