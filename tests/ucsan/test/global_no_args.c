// METADATA: asm_cal.yaml
// FLAG: 200

/*
 * An entry function without arguments that reads an initialized global.  On
 * the first, empty seed nothing has created the super object (object 0):
 * arguments are what create it.  The global is past the end of the seed, so
 * its symbolization keeps the initializer, 5, reports it to the manager, and
 * records it in this run's copy of the seed -- which indexed object 0 that
 * did not exist, a SIGSEGV in ucsan_check_pointer (s2idle_loop and
 * mmio_select_mitigation in the kernel eval).
 */
#include <stdlib.h>

int g = 5;

int cal(void)
{
	if (g == 7)
		exit(200);
	return g;
}
