// METADATA: asm_call.yaml
// FLAG: 200

#include <stdlib.h>

/*
 * call_on_irqstack's shape: a `call` to a void function from an asm with
 * several register outputs, so the asm returns a struct.  The rewrite used to
 * cast the void call into the struct's first element, which is invalid IR
 * (`bitcast void ... to ptr`) and crashes the backend.
 */
void irq_enter_rcu(void)
{
}

void *volatile sink_sp;
volatile long sink_r11;

int cal(int x)
{
	void *sp;
	long r11;

	__asm__ __volatile__("call irq_enter_rcu"
			     : "=r"(sp), "=r"(r11)
			     :
			     : "memory", "rax", "rcx", "rdx", "rsi", "rdi",
			       "r8", "r9", "r10");
	/* the outputs are used, but carry nothing defined: a void call */
	sink_sp = sp;
	sink_r11 = r11;
	if (x == 3)
		exit(200);
	return 0;
}
