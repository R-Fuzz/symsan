// METADATA: lib_free.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_free.abilist
// LIB: lib_free_lib.c
// FLAG: 151

#include <stdlib.h>

/*
 * A use after free of an object library code allocated and freed.  UCSan
 * gives library allocations no label, so only SymSan's bounds label names it,
 * and in the combined runtime free is UCSan's wrapper: the library's free
 * (its __dfsl_ adapter) has to mark SymSan's label freed, or the use is no
 * UAF to either (a vector's buffer, freed as it grows, under an in-scope
 * pointer).
 */
char *lib_alloc8(void);
void lib_free(void *p);

int cal(int n)
{
	char *q = lib_alloc8();
	lib_free(q);
	q[0] = (char)n;
	exit(200);
}
