// METADATA: asm_cal.yaml
// ENV: trace_bounds
// CFLAGS: -O2 -fno-vectorize -fno-unroll-loops
// FLAG: 200
// ABSENT: 1

/*
 * TaintPass's loop-hoisted bounds check must not be given a UCSan
 * pseudo-pointer.  SCEV cannot see through ucsan_check_pointer, so hoisting
 * reads the recurrence off the pointer before the check; for sb, an argument,
 * that is a pseudo-pointer, 0 in the seed while every access through it is
 * materialized.  The summary check then saw a NULL dereference and SymSan
 * Die()d: exit status 1, nothing reported (calc_sb_1_csum, which this
 * mirrors).  Only a stack object or a global, which ucsan_check_pointer
 * returns unchanged, may be hoisted that way; sb's accesses keep their
 * per-iteration checks, and what was read is solvable (200).
 */
#include <stdlib.h>

struct sb {
	unsigned int max_dev;
	unsigned int words[63];
};

unsigned int cal(struct sb *sb)
{
	unsigned int *p = (unsigned int *)sb;
	unsigned int csum = 0;
	int i;

	for (i = 0; i < 8; i++)
		csum ^= p[i];
	if (csum == 0x1234)
		exit(200);
	return csum;
}
