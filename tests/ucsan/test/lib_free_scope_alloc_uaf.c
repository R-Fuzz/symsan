// METADATA: lib_free.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_free.abilist
// LIB: lib_free_lib.c
// FLAG: 151

#include <stdlib.h>

/*
 * An in-scope object library code frees (a unique_ptr it destroys): the
 * adapter gets no UCSan label, so UCSan's stays live, and the use is a UAF by
 * SymSan's, which the library's free marks.
 */
void lib_free(void *p);

int cal(int n)
{
	char *q = malloc(8);
	lib_free(q);
	q[0] = (char)n;
	exit(200);
}
