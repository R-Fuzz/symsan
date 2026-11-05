// METADATA: lib_free.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_free.abilist
// LIB: lib_free_lib.c
// ABSENT: 151
// FLAG: 200

#include <stdlib.h>

/*
 * The other side of lib_free_uaf: a library object freed later is not one
 * yet, and its use is no UAF.
 */
char *lib_alloc8(void);
void lib_free(void *p);

int cal(int n)
{
	char *q = lib_alloc8();
	q[0] = (char)n;
	lib_free(q);
	exit(200);
}
