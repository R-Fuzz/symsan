// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 152 200

/*
 * A memory intrinsic whose destination is in a global skips
 * ucsan_check_pointer (a written destination needs no symbolizing), so its
 * length was never bounded.  __early_make_pgtable memsets
 * early_dynamic_pgts[i] for ptrs_per_p4d * 8 bytes, a symbolized global's
 * value, and wrote gigabytes of shadow past the 256 KB array.  The length
 * is now checked against the global: a count past it is an OOB (152).
 * SymSan's __taint_check_bounds, right after ucsan_set_label, reports this
 * small overrun too, so the test does not tell the two apart: what the
 * UCSan check adds is that it runs before the shadow write, which a test
 * could only see by writing gigabytes.
 */
#include <stdlib.h>
#include <string.h>

long table[8][64];
unsigned short count;
unsigned short row;

int cal(int x)
{
	memset(table[row & 7], 0, count * sizeof(long));
	if (x == 7)
		exit(200);
	return 0;
}
