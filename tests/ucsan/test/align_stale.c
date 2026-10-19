// METADATA: asm_cal.yaml
// FLAG: 200
// ABSENT: 1 126 210
// CFLAGS: -O2

/*
 * ucsan_check_pointer moves a lazily created object to place it at the
 * alignment an access needs, so a check's result (a real address) must not be
 * reused across another check: the pass reused it in the whole block (and
 * wherever it dominated), and a store through it after the move went to the
 * old window, unseen through any other pointer (210).
 */
#include <stdlib.h>

struct ctxt {
	long first;
	char pad[3];
	char tag;
	__int128 wide;
};

/* 1, in a way the compiler cannot fold: c's byte 11 through another pointer */
static volatile long one = 1;

int cal(struct ctxt *c, __int128 *out)
{
	/* the first access to c, a byte at offset 11: its offset 0 */
	volatile char *t = (volatile char *)((long)c + 11);
	char v = *t;	/* the store below reused this check */
	*out = *(volatile __int128 *)&c->wide;	/* 16-byte aligned: moves c */
	*t = v + 1;
	if (((volatile char *)c)[10 + one] != (char)(v + 1))
		exit(210);
	exit(200);
}
