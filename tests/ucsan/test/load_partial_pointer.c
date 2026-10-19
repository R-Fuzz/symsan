// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * A stored pointer's bytes carry its bounds label, which is no value.  An
 * integer load that took in part of one (concrete bytes, then the pointer's
 * low half) built Concat(C, Trunc(Alloca)), a bounds node in an expression
 * the parser cannot serialize: "invalid label", and the branch on it was
 * never solved (handle_eject_request's union acpi_object).
 */
#include <stdlib.h>
#include <string.h>

struct __attribute__((packed)) obj {
	unsigned int type;
	char *ptr;
};

int cal(unsigned int x)
{
	char buf[13] = "hello world!";
	struct obj o;
	unsigned long v;

	o.type = 1;
	o.ptr = buf;
	memcpy(&v, &o, sizeof(v));	/* type, then the low half of ptr */
	if ((unsigned int)v + x == 12345)
		exit(200);
	if ((unsigned int)(v >> 32) + x == 7)
		return 1;
	return 0;
}
