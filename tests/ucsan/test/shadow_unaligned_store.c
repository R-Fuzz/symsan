// METADATA: asm_cal.yaml
// ENV: trace_bounds
// CFLAGS: -O2
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * A pointer read from a global's bytes whose value lies in the image is a
 * real pointer into it, and nothing makes that address keep the alignment
 * the IR claims for the access through it: here an odd one, by
 * construction; in the kernel, a list head's `next` the solver moved
 * (unregister_nmi_handler).  x86 does the store itself unaligned, but
 * UCSanPass clears its shadow -- 16 bytes for 8 -- with the IR's alignment
 * scaled by the shadow width, 16: a movaps, a general-protection fault, and
 * the run died with exit 1 before 200 was reachable.  -O2: unoptimized
 * codegen splits the 16-byte store into two 8-byte ones.
 */
#include <stdlib.h>

char buf[32];
char *pg = &buf[1];

int cal(int x)
{
	*(long *)pg = 0;
	if (x == 5)
		exit(200);
	return 0;
}
