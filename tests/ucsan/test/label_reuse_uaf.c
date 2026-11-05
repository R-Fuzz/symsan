// METADATA: label_reuse.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/label_reuse.abilist
// LIB: label_reuse_lib.c
// FLAG: 151

#include <stdlib.h>

/*
 * The other side of label_reuse: a freed label is taken back only when the
 * labels run low, so short of that a use after free is still one.
 */
void lib_repeat(void (*f)(void), int n);

void churn(void)
{
	free(malloc(16));
}

int cal(int n)
{
	char *q = malloc(4);
	free(q);
	lib_repeat(churn, 1000);
	q[0] = (char)n;
	exit(200);
}
