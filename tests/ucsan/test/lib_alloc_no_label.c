// METADATA: lib_alloc.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_alloc.abilist
// LIB: lib_alloc_lib.c
// ABSENT: 1
// FLAG: 152

#include <stdlib.h>

/*
 * An allocation library code makes is out of scope: library code keeps no
 * UCSan labels, and the label its __dfsl_ adapter got from UCSan's wrapper
 * was dropped on the spot -- only using up the 16-bit labels (61% of them in
 * v8's PreParserScopeAnalysis, which ran out).  It gets none now; 70000 of
 * them leave the labels to in-scope objects, whose bounds UCSan still checks.
 */
void lib_churn(int n);

int cal(int n)
{
	lib_churn(70000);
	char *p = malloc(4);
	p[8] = (char)n;
	exit(200);
}
