// METADATA: asm_cal.yaml
// ENV: trace_bounds checker_nullderef
// FLAG: 153 150,1

/*
 * A kmalloc with __GFP_ZERO (kzalloc, kcalloc, ...) returns initialized
 * memory.  The UCSan kmalloc wrappers ignored the flags and painted every
 * allocation uninitialized, so the NULL that kzalloc'ed memory holds was a
 * UBI when dereferenced (ext4_ext_rm_leaf's path[depth].p_bh, kcalloc'ed by
 * ext4_ext_remove_space) instead of the NULL dereference it is (153).  A
 * kmalloc without __GFP_ZERO is still uninitialized: that path's read is
 * the one UBI (150).
 */
#include <stdlib.h>

#define GFP_KERNEL 0xcc0u
#define __GFP_ZERO 0x100u

struct node {
	struct node *next;
	int v;
};

void *__kmalloc(unsigned long size, unsigned int flags);

int cal(int n)
{
	unsigned int flags = n == 1 ? GFP_KERNEL : GFP_KERNEL | __GFP_ZERO;
	struct node *p = __kmalloc(sizeof(*p), flags);

	if (!p)
		return 0;
	return p->next->v;
}
