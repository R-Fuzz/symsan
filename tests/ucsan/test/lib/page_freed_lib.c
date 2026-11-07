/* library code's page mappings: map, then free (unmap or decommit) */
#include <sys/mman.h>

#define PAGES (1 << 16)

char *page_map(void)
{
	return mmap(0, PAGES, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void page_free(char *p, int how)
{
	if (how == 1)
		munmap(p, PAGES);
	else if (how == 2)
		mprotect(p, PAGES, PROT_NONE);
	else
		mmap(p, PAGES, PROT_NONE,
		     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
