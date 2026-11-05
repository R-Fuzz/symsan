// METADATA: lib_free.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_free.abilist
// LIB: lib_free_lib.c
// FLAG: 151

#include <stdlib.h>

/*
 * A library object in-scope code frees: UCSan's free gets no UCSan label for
 * it, so the use is a UAF by SymSan's, which TaintPass marks after UCSan's
 * wrapper.
 */
char *lib_alloc8(void);

int cal(int n)
{
	char *q = lib_alloc8();
	free(q);
	q[0] = (char)n;
	exit(200);
}
