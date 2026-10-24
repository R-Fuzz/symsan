// METADATA: asm_cal.yaml
// FLAG: 200
// ABSENT: 1 126
// CFLAGS: -O2

/*
 * A lazily created object is placed at its first check, so a first access
 * that is not at the object's start misplaces every field after it.  Here it
 * is a byte reached through integer arithmetic (no GEP, so no base check),
 * which put c->memop off the 16-byte alignment its copy assumes: the movaps
 * faulted (exit status 1, no trace).  ucsan_check_pointer now moves the
 * object to where c->memop has it.
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

int cal(struct ctxt *c, struct op *out)
{
	/* the first access to c: a byte at offset 11 */
	if (*(volatile char *)((long)c + 11) != 9)
		return 0;
	*out = c->memop;
	exit(200);
}
