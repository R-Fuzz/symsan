// METADATA: asm_cal.yaml
// FLAG: 200

/*
 * sync_core()'s iret to self only serializes the CPU; its `pushq $1f` was an
 * R_X86_64_32S the PIE link refused (arch/x86/kernel/alternative.o).  It is
 * now a no-op -- and its %rsp operand (ASM_CALL_CONSTRAINT) keeps its value:
 * zeroed, the stack pointer was 0 after it.
 */
#include <stdlib.h>

register unsigned long current_stack_pointer asm("rsp");

int cal(int x)
{
	unsigned long tmp;

	asm volatile("mov %%ss, %0\n\t"
		     "pushq %q0\n\t"
		     "pushq %%rsp\n\t"
		     "addq $8, (%%rsp)\n\t"
		     "pushfq\n\t"
		     "mov %%cs, %0\n\t"
		     "pushq %q0\n\t"
		     "pushq $1f\n\t"
		     "iretq\n\t"
		     "1:"
		     : "=&r" (tmp), "+r" (current_stack_pointer) : : "cc", "memory");
	if (x == 7)
		exit(200);
	return 0;
}
