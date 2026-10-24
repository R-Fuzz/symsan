// METADATA: asm_cal.yaml
// FLAG: 200
// CFLAGS: -O2

/*
 * A GEP's base check (a check of the base pointer with the size of the type
 * it indexes) is what creates a lazily created object at its base.  It was
 * emitted once per pointer per function, at the first GEP in program order,
 * so a GEP in another switch arm had none: the object was created at the
 * first field that arm touched, and a field the code assumes 16-byte aligned
 * was not (decode_operand: a movaps of ctxt->memop faulted).  A base check now
 * only stands for the GEPs it dominates.
 */
#include <stdlib.h>

struct op {
	__int128 a, b;
};

struct ctxt {
	long first;
	char pad[3];
	char tag;
	struct op memop;
};

int cal(struct ctxt *c, struct op *out, int x)
{
	switch (x) {
	case 0:
		/* the first GEP on c in program order */
		return c->pad[1] == 3;
	case 1:
		/* the arm's first access: a byte at offset 11 */
		if (c->tag != 9)
			return 0;
		*out = c->memop;
		exit(200);
	}
	return 0;
}
