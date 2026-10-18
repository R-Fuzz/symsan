// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * A function taking a va_list gets a pointer to the caller's __va_list_tag,
 * so under UC a pseudo-pointer, and va_copy read and wrote the 24-byte
 * va_list through its operands unchecked: a fault 0x10 off a pseudo-NULL
 * before 200 was reachable (kvasprintf).
 */
#include <stdarg.h>
#include <stdlib.h>

int cal(int x, va_list ap)
{
	va_list aq;

	va_copy(aq, ap);
	va_end(aq);
	if (x == 5)
		exit(200);
	return 0;
}
