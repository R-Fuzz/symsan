// METADATA: compressed_ptr.yaml
// ENV: concrete_globals
// ABSENT: 153
// FLAG: 200

#include <stdlib.h>

/*
 * A compressed pointer, as v8 keeps its tagged fields: the low half of a
 * pointer is stored as a 32-bit field and decompressed as `base | raw` with a
 * concrete cage base.  The field's 4-byte load must keep the pointer's UCSan
 * label (its identity, whatever the concrete bits), or the decompressed
 * pointer is unlabeled and its dereference a null deref (153).
 */
struct holder {
	unsigned raw;
};

unsigned long cage_base;

int cal(int **pp, struct holder *h)
{
	h->raw = (unsigned)(unsigned long)*pp;
	int *q = (int *)(cage_base | (unsigned long)h->raw);
	if (*q == 0x1234)
		exit(200);
	return 0;
}
