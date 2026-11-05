/* library code's allocation and free */
#include <stdlib.h>

char *lib_alloc8(void)
{
	return malloc(8);
}

void lib_free(void *p)
{
	free(p);
}
