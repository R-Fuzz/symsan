// METADATA: asm_call.yaml
// ABSENT: 201
// FLAG: 200

#include <stdlib.h>

/*
 * An inline asm `call sym` whose callee is in the module is rewritten into a
 * direct call.  The arguments must follow the SysV registers the constraints
 * name ({rdi}, {rsi}, ...), not the order the constraints are written in, and
 * the rewritten call must keep its argument/return labels (it is currently
 * marked nosanitize, which TaintPass skips).
 */
int sub(int a, int b)
{
	return a - b;
}

int cal(int a, int b)
{
	int r;

	__asm__ __volatile__("call sub"
			     : "=a"(r)
			     : "S"(b), "D"(a)
			     : "memory", "rcx", "rdx", "r8", "r9", "r10", "r11");
	if (r != a - b)
		exit(201);
	if (r == 5)
		exit(200);
	return 0;
}
