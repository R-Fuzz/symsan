// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * A function defined by a top-level asm() block -- kvm.c's
 * __raw_callee_save___kvm_vcpu_is_preempted -- indexes a global with an
 * absolute 32-bit address ("movq __per_cpu_offset(,%rdi,8)"), which the
 * PIE link refuses (R_X86_64_32S).  Its only caller is out of scope and
 * becomes a stub, so nothing the scope keeps calls it: it is dropped,
 * and every function of arch/x86/kernel/kvm.o linked again.
 */
#include <stdlib.h>

long abs_table[4] = {1, 2, 3, 4};

asm(".pushsection .text, \"ax\"\n"
    ".global abs_lookup\n"
    ".type abs_lookup, @function\n"
    "abs_lookup:\n"
    "movq abs_table(,%rdi,8), %rax\n"
    "ret\n"
    ".size abs_lookup, . - abs_lookup\n"
    ".popsection\n");

extern long abs_lookup(long);

long (*lookup_fn)(long);

void install(void)
{
	lookup_fn = abs_lookup;
}

int cal(int x)
{
	if (abs_table[1] + x == 9)
		exit(200);
	return 0;
}
