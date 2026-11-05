// METADATA: lib_small_arg.yaml
// ENV: checker_nullderef
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_small_arg.abilist
// LIB: lib_small_arg_lib.c
// ABSENT: 153
// FLAG: 200

#include <stdlib.h>

/*
 * A library callee's pointer argument is a value the callee decides what to
 * do with.  cppgc's conservative stack scan hands TryFindNode every word of
 * the stack, small integers too, and TryFindNode only compares it with the
 * traced nodes' ranges.  An unlabeled value in the null range was checked as
 * a null dereference (153, v8's GlobalHandlesTest.MoveWeakGlobal); only an
 * exact null was let through.  (lib_small_arg_deref: one the callee does
 * dereference is still reported.)
 */
int lib_in_range(const void *p, const void *lo, const void *hi);

int cal(int n)
{
	static char nodes[64];
	volatile long word = 0x30;  /* a stack word that is no pointer */
	if (!lib_in_range((const void *)word, nodes, nodes + sizeof(nodes)))
		exit(200);
	return n;
}
