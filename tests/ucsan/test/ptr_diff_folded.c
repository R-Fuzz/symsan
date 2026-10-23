// METADATA: asm_cal.yaml
// CFLAGS: -O2
// ABSENT: 1 202
// EVENT-ABSENT: 159
// FLAG: 201

#include <stdlib.h>

/*
 * A pointer difference the optimizer has folded to integers: sg_page() then
 * page_to_pfn() (i915's bit_17_swizzle), `(page_link & ~3) - vmemmap_base`,
 * the inttoptr and ptrtoint of the source cancelled out.  Both integers come
 * from where the module keeps pointers -- page_link and vbase are made
 * pointers of elsewhere (the dereferences below) -- so it is still the
 * element index of two pointers, as `pg - vmemmap` with ptrtoints is: a
 * fresh index i, and pg bound to vmemmap[i], so a write through one is read
 * through the other (201, not 202).  The exactness is the pointers'
 * placement, not reported (159).
 */
struct page {
	long flags, a, b, c, d, e, f, g;
};

struct sg {
	unsigned long page_link;
	unsigned int offset, length;
};

unsigned long vbase;
#define vmemmap ((struct page *)vbase)

int cal(struct sg *s)
{
	struct page *pg = (struct page *)(s->page_link & ~3UL);
	/* volatile: compared directly, pfn == 3 folds to a byte difference */
	volatile long pfn;

	if (s->length != 4096)
		return 0;
	pfn = pg - vmemmap;
	if (pfn != 3)
		return 0;
	pg->flags = 0x55;
	if (vmemmap[3].flags == 0x55)
		exit(201);
	exit(202);
}
