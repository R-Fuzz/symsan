// METADATA: realloc_null.yaml
// ENV: checker_nullderef
// ABSENT: 153
// FLAG: 200

#include <stdlib.h>

/*
 * A buffer grown from nullptr, as v8's ValueSerializer grows its own: the
 * first realloc is realloc(NULL, n), a malloc.  A custom wrapper's pointer
 * argument was checked as a dereference, null too, and the call exited 153.
 * Without a byte count (the abilist's sizeN), null is a value the wrapper
 * takes, as a library callee's is.  (A local, not a global: under
 * concrete_globals a global's bytes carry labels, and a labeled pointer is
 * checked whatever its value.)
 */
int cal(unsigned n)
{
	char *buf = NULL;
	buf = realloc(buf, n + 1);
	if (!buf)
		return 0;
	buf[0] = 1;
	if (n == 0x40)
		exit(200);
	free(buf);
	buf = NULL;
	free(buf);
	return 0;
}
