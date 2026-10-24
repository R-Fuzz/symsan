// METADATA: asm_cal.yaml
// FLAG: 200 201
// ABSENT: 1

/*
 * A paravirt call is "call *%N" through a memory operand, the pv_ops slot:
 * slow_down_io's PVOP_VCALL0(cpu.io_delay), after every outb_p.  It was
 * left alone, so it ran natively through the out-of-scope pv_ops -- a
 * zero weak definition -- and jumped to 0 (a SIGSEGV, exit 1).  The
 * pointer is now loaded in IR and called like any indirect call: the
 * global is symbolized, and the call's result is symbolic.
 */
#include <stdlib.h>

struct ops {
	void (*io_delay)(void);
	unsigned long (*get)(unsigned long);
};
extern struct ops pv_ops;

int cal(int x)
{
	unsigned long di, r;

	asm volatile("call *%1"
		     : "=D" (di)
		     : "m" (pv_ops.io_delay)
		     : "memory", "cc", "rax", "rsi", "rdx", "rcx", "r8", "r9",
		       "r10", "r11");
	di = x;
	asm volatile("call *%2"
		     : "=a" (r), "+D" (di)
		     : "m" (pv_ops.get)
		     : "memory", "cc", "rsi", "rdx", "rcx", "r8", "r9", "r10",
		       "r11");
	if (r == 0x55)
		exit(201);
	if (x == 9)
		exit(200);
	return 0;
}
