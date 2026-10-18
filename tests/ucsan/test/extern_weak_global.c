// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * A global declared extern and __weak, and defined nowhere in the build --
 * the kernel's kallsyms_num_syms, defined only by its final link -- is an
 * undefined weak symbol, at address 0: kallsyms_lookup_names read through
 * it and faulted.  It gets the weak definition an extern declaration gets,
 * and its value is the seed's.
 */
#include <stdlib.h>

extern const unsigned int weak_count __attribute__((weak));

int cal(int x)
{
	if (weak_count + x == 5)
		exit(200);
	return 0;
}
