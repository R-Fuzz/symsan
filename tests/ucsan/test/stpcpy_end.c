// METADATA: asm_cal.yaml
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * sprintf(buf, "%s", s) compiles to stpcpy(buf, s) - buf (uncore_event_show).
 * stpcpy's result was the real end of the copy, labeled as dest itself, and
 * buf the pseudo pointer: a value mismatch.  The result is now translated
 * back into buf's pseudo space (retptr0) and labeled dest + its offset.
 */
#include <stdlib.h>
#include <string.h>

int cal(char *buf, char *s, int x)
{
	long n = stpcpy(buf, s) - buf;

	/* the length itself is concrete to the solver; the branch on it must
	 * parse */
	if (n == 3)
		return 1;
	if (x == 7)
		exit(200);
	return 0;
}
