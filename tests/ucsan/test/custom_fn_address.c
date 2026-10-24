// METADATA: asm_cal.yaml
// FLAG: 200

/*
 * A function with a custom wrapper (panic) has its calls sent to the
 * wrapper, but its address as a value named the function itself, which
 * nothing defines, and TaintPass renamed it to panic.taint: an undefined
 * reference (ftrace_pop_return_trace's `ret = (unsigned long)panic`).  The
 * address now names an out-of-scope stub.
 */
#include <stdlib.h>

extern void panic(const char *fmt, ...);

unsigned long ret_addr;

int cal(int x)
{
	if (x == 3)
		ret_addr = (unsigned long)panic;
	if (x == 7)
		exit(200);
	return 0;
}
