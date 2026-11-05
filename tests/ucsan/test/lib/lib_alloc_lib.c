/* library code's allocations: out of scope */
#include <stdlib.h>

void lib_churn(int n)
{
	for (int i = 0; i < n; i++)
		free(malloc(16));
}

char *lib_alloc4(void)
{
	return malloc(4);
}
