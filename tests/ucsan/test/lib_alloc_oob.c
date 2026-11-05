// METADATA: lib_alloc.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_alloc.abilist
// LIB: lib_alloc_lib.c
// FLAG: 152

/*
 * The other side of lib_alloc_no_label: a library object an in-scope access
 * overruns is still an OOB -- its bounds are SymSan's label's, which the
 * library allocation keeps (only the UCSan label is gone).
 */
char *lib_alloc4(void);

int cal(int n)
{
	char *q = lib_alloc4();
	q[8] = (char)n;
	return 0;
}
