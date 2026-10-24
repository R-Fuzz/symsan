// METADATA: asm_cal.yaml
// ENV: KO_RESIGN_PTRARGS
// FLAG: 200
// ABSENT: 1 150

/*
 * An out-of-scope callee resigns its pointer arguments, as if it may have
 * written what they point to, but its stub sees only the fixed ones: a
 * pointer passed as a variadic argument kept its object uninitialized, and
 * the read of v after scan() returned 1 was a UBI report (150, with the UBI
 * checker on as the kernel eval runs; without it, as here, the run ended
 * with exit status 1).  The kernel's
 * sld_state_setup reads ratelimit after sscanf(arg, "ratelimit:%d",
 * &ratelimit) == 1 in this shape.
 */
#include <stdlib.h>

int scan(const char *s, const char *fmt, ...);

int cal(const char *s)
{
	int v;

	if (scan(s, "%d", &v) == 1 && v == 42)
		exit(200);
	return 0;
}
