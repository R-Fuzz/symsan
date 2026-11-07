// METADATA: lib_free.yaml
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/page_freed.abilist
// LIB: page_freed_lib.c
// FLAG: 151

/*
 * Pages library code unmapped, or decommitted (mprotect, or a MAP_FIXED
 * remap, to PROT_NONE after use), are freed (ucsan.cpp map_state): an access
 * to one faults natively, through a pointer UCSan does not check, and the
 * fault is a use after free (151), not a null dereference.  Before, a
 * PROT_NONE range was no mapping of the program's, so ucsan_int_to_pointer
 * gave its address a pseudo object and the access read that instead of
 * faulting.  (In scope, mmap is out of scope: a stub, which maps nothing.)
 */
char *page_map(void);
void page_free(char *p, int how);

int cal(int how)
{
	char *p = page_map();

	p[100] = 7;
	if (how >= 1 && how <= 3)
		page_free(p, how);
	return p[100];		/* 151 for how 1-3 */
}
