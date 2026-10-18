// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * An out-of-scope function called both from C and, by name, from inline asm
 * -- call_on_irqstack_cond's irq_enter_rcu, called directly in one branch
 * and from the stack-switching asm in the other (sysvec_irq_work).  The C
 * call turns it into its __external$ wrapper and erases it, after which the
 * asm's call found no callee, was left alone, and linked against the bare
 * symbol: undefined, and nothing was built.
 */
#include <stdlib.h>

void helper(void);

int cal(int x)
{
	if (x == 7)
		helper();
	asm volatile("call helper"
		     : : : "memory", "rax", "rcx", "rdx", "rsi", "rdi",
		       "r8", "r9", "r10", "r11");
	if (x == 5)
		exit(200);
	return 0;
}
