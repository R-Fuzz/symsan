// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * rethook.c's arch_rethook_trampoline is written straight into .text --
 * no .pushsection -- from `.type X, @function` to `.size X`, and pushes its
 * own address ("pushq $arch_rethook_trampoline"), an R_X86_64_32S the PIE
 * link refuses.  Its C users are out of scope and become stubs, so that
 * self-reference (and its .global) is all that names it: it is dropped,
 * and every function of arch/x86/kernel/rethook.o linked again.
 */
#include <stdlib.h>

asm(".text\n"
    ".global self_tramp\n"
    ".type self_tramp, @function\n"
    "self_tramp:\n"
    "pushq $self_tramp\n"
    "addq $8, %rsp\n"
    "ret\n"
    ".size self_tramp, .-self_tramp\n");

extern void self_tramp(void);

unsigned long tramp_addr;

void install(void)
{
	tramp_addr = (unsigned long)self_tramp;
}

int cal(int x)
{
	if (x * 3 == 27)
		exit(200);
	return 0;
}
