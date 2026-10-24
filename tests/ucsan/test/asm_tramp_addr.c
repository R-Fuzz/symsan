// METADATA: asm_cal.yaml
// FLAG: 200

#include <stdlib.h>

/*
 * A static call trampoline, as DEFINE_STATIC_CALL emits it: top-level asm in
 * .static_call.text jumping to the current target, whose address in-scope C
 * hands on (static_call_update's STATIC_CALL_TRAMP_ADDR, init_hw_perf_events).
 * Only an address that reaches inline asm keeps naming the asm (fastop's
 * `call *fop`); this one takes the out-of-scope wrapper, so the block, which
 * jumps to a function the split erased, is dropped and the binary links.
 */
__asm__(".pushsection .static_call.text, \"ax\"\n"
	".globl tramp\n"
	".type tramp, @function\n"
	"tramp:\n"
	"	jmp target_fn\n"
	".size tramp, . - tramp\n"
	".popsection\n");

extern void tramp(void);

void target_fn(void)
{
}

void *update_key;

void update(void *tramp_addr)
{
	update_key = tramp_addr;
}

int cal(int x)
{
	update((void *)tramp);
	if (x == 5)
		exit(200);
	return 0;
}
