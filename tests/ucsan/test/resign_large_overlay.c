// METADATA: asm_cal.yaml
// ENV: KO_RESIGN_PTRARGS
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * Resign overlays an object an out-of-scope callee may write -- here a
 * stack object, without trace_bounds -- with bytes from the seed, and gave each byte its own UCSan label.
 * serial8250_resume_port hands over a buffer big enough to exhaust the 16-bit
 * labels.  A large overlay's bytes now get their labels on demand, as a
 * lazily created object's do; reaching 200 checks they are the same bytes.
 */
#include <stdlib.h>

#define BIG 36000

void fill(char *p)
{
	p[0] = 0;
}

int cal(int n)
{
	char a[BIG];
	char b[BIG];

	fill(a);
	fill(b);
	if (a[100] == 'x' && b[30000] == 'y')
		exit(200);
	return n;
}
