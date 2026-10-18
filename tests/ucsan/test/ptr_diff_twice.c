// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// ABSENT: 201
// SOLVER-ERROR-ABSENT

/*
 * `e - table` twice.  The first binds e to element i of table's object
 * (ptr_diff_index.c), and after that e and table are two pointer labels of
 * one object whose pseudo-pointers still have unrelated bases: their
 * difference was the same meaningless number the first one replaced, so j
 * was never i (201), and a branch on it a value mismatch.  The second
 * difference is now the difference of their offsets in the object, i again,
 * with i's SymSan label: 3 is solvable through j (200).
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
	long j = e - table;
	if (j != i)
		exit(201);
	if (j == 3)
		exit(200);
	return 0;
}
