// METADATA: asm_cal.yaml
// ENV: trace_bounds
// CFLAGS: -O2
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * Nothing makes the address of an access keep the alignment the IR claims
 * for it: here an odd address into a global, by construction (C makes the
 * store UB; x86 does it unaligned).  UCSanPass cleared its shadow -- 16
 * bytes for 8 -- with the IR's alignment scaled by the shadow width, 16: a
 * movaps, a general-protection fault, and the run died with exit 1 before
 * 200 was reachable (unregister_nmi_handler, where the odd address was a
 * seed value taken as a global's).  -O2: unoptimized codegen splits the
 * 16-byte store into two 8-byte ones.
 */
#include <stdlib.h>

char buf[32];

int cal(int x)
{
	volatile int one = 1;

	*(long *)(buf + one) = 0;
	if (x == 5)
		exit(200);
	return 0;
}
