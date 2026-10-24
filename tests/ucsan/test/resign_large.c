// METADATA: asm_cal.yaml
// ENV: trace_bounds KO_RESIGN_PTRARGS
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * Resign gave every uninitialized byte of an object it resigned its own
 * UCSan label.  unlzo hands two 40 KB buffers to out-of-scope callees, and
 * labels are 16-bit: "FATAL: UCSan: exhausted labels".  A long run of such
 * bytes now gets one on-demand marker, as a large lazily created object
 * does, and a byte its label (the same super object offset) when first read.
 * The solver reaching 200 checks those offsets: a byte deep in each buffer.
 */
#include <stdlib.h>

#define BIG 32768

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
