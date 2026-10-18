// METADATA: asm_cal.yaml
// FLAG: 200
// ABSENT: 1

/*
 * machine_real_restart leaves the kernel with "ljmpl *%0" into the
 * real-mode trampoline.  Run natively that far jump is a GP fault (a
 * SIGSEGV, exit 1); it is no bug, so the run now ends there normally.
 */
#include <stdlib.h>

struct header { unsigned int restart_asm; };

int cal(int x)
{
	struct header h = { 0x1000 };

	if (x == 7) {
		asm volatile("ljmpl *%0" :: "m" (h.restart_asm), "D" (x));
		__builtin_unreachable();
	}
	if (x == 9)
		exit(200);
	return 0;
}
