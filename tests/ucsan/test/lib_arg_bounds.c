// METADATA: lib_arg_bounds.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_arg_bounds.abilist
// LIB: lib_arg_bounds_lib.c
// FLAG: 152

#include <stdlib.h>

/*
 * An in-scope object library code overruns: the pointer reaches it with its
 * SymSan bounds label.  UCSanPass checks a library callee's pointer argument
 * on a path of its own (checkPointerUnlessNull), joined by a phi that was
 * nosanitize, so TaintPass gave it no label: library code's access was
 * unchecked, and so was its free (lib_free_scope_alloc_uaf).
 */
void lib_write(char *p, int i, char v);

int cal(int n)
{
	char *p = malloc(4);
	lib_write(p, 8, (char)n);
	exit(200);
}
