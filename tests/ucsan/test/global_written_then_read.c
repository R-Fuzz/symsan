// METADATA: asm_cal.yaml
// FLAG: 200
// ABSENT: 201

/*
 * A global byte is symbolized from the seed at its first dereference, which
 * the runtime took to be one whose shadow is 0.  But 0 is also the shadow of
 * a byte the program wrote with a concrete value: g.p, cleared and then
 * stored, was symbolized again where it was read back, under a fresh
 * external label, and identity is the label, so g.p[0] read a lazily
 * created object instead of buf.  An ICMP fixture's skb head (queued_output
 * .head = queued_frame) failed its quote check that way.
 */
#include <stdlib.h>
#include <string.h>

struct holder {
	char *p;
	int n;
};

struct holder g;
char buf[16];

int cal(int x)
{
	memset(&g, 0, sizeof(g));
	g.p = buf;
	buf[0] = 'A';
	if (g.p[0] != buf[0])
		exit(201);
	exit(200);
}
