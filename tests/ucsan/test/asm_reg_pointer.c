// METADATA: asm_cal.yaml
// ABSENT: 1
// FLAG: 200

#include <stdlib.h>

/*
 * A pointer handed to inline asm in a register and dereferenced by the asm
 * itself never goes through ucsan_check_pointer, so the asm sees the raw
 * (unmaterialized) pointer and faults (Die() -> exit status 1).  The kernel
 * shape is call_on_stack's `movq %rsp, (%[ts])` and the movntdqa copies.
 */
int cal(int *p)
{
	int v;

	__asm__ __volatile__("movl (%1), %0" : "=r"(v) : "r"(p) : "memory");
	if (*p == 5)
		exit(200);
	return v;
}
