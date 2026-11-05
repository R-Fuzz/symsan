// METADATA: label_reuse.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/label_reuse.abilist
// LIB: label_reuse_lib.c
// ABSENT: 1
// FLAG: 152

#include <stdlib.h>

/*
 * A freed object's label is taken back once the labels run low, oldest
 * first: 70000 objects allocated and freed in turn need more labels than the
 * 16 bits have, and the run goes on to check the bounds of the next one
 * (v8's PreParserScopeAnalysis frees 57k of 63k objects, and ran out).
 */
void lib_repeat(void (*f)(void), int n);

void churn(void)
{
	free(malloc(16));
}

int cal(int n)
{
	lib_repeat(churn, 70000);
	char *p = malloc(4);
	p[8] = (char)n;
	exit(200);
}
