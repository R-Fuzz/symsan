// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * machine_kexec's load_segments(): kernel selectors into the segment
 * registers.  They are no valid descriptors in a userspace run, and the
 * first `mov %eax, %ds` was a general-protection fault, before 200 was
 * reachable.  The model is flat: a segment register load does nothing.
 */
#include <stdlib.h>

#define __KERNEL_DS 0x18

int cal(int x)
{
	/* load_segments(), in cal itself: only cal is in scope */
	__asm__ __volatile__ (
		"\tmovl %0,%%ds\n"
		"\tmovl %0,%%es\n"
		"\tmovl %0,%%ss\n"
		"\tmovl %0,%%fs\n"
		"\tmovl %0,%%gs\n"
		: : "a" (__KERNEL_DS) : "memory"
		);
	if (x == 5)
		exit(200);
	return 0;
}
