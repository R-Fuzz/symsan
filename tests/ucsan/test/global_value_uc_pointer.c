// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// ABSENT: 201
// SOLVER-ERROR-ABSENT

/*
 * A pointer read from a global's bytes is a UC pointer -- its value comes
 * from the seed -- and is mapped to a real one whatever that value is.  The
 * check for a pointer into the image ran first, so a value that happened to
 * land there was taken as a real address: here the global's own initial
 * value, &buf[1], odd and inside another global; in the kernel, a list
 * head's `next` the solver moved to 33 bytes before nmi_desc
 * (unregister_nmi_handler).  Mapped, it is a pointer to an object of its
 * own, and the store through it reaches it; taken as &buf[1], the store
 * changed buf[1] (201).
 */
#include <stdlib.h>

char buf[32];
char *pg = &buf[1];

int cal(int x)
{
	/* through a pointer the pass cannot trace to pg -- the kernel's was a
	 * loop phi -- so that pg's bytes are symbolized, as a UC global's */
	char **volatile pp = &pg;
	char *p = *pp;
	char before = buf[1];	/* buf's bytes are the seed's too */

	*p = before + 1;
	if (buf[1] != before)
		exit(201);
	if (x == 5)
		exit(200);
	return 0;
}
