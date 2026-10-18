// METADATA: asm_cal.yaml
// FLAG: 200
// ABSENT: 1

/*
 * __write_relocate_add calls write(loc, &val, size) with write = memcpy.
 * An indirect call does not check its pointer arguments -- the callee
 * does, at the access -- but memcpy's wrapper does not either: the wrapped
 * call path checks them for it.  So the call through the pointer handed
 * __dfsw_memcpy the unmaterialized loc (a SIGSEGV, exit 1).  A wrapped
 * function whose address is taken now gets a direct call of its own.
 */
#include <stdlib.h>
#include <string.h>

struct sect { char *addr; };

void *(*volatile writer)(void *, const void *, size_t) = memcpy;

int cal(struct sect *s, int x)
{
	long val = 0x1122;

	writer(s->addr, &val, sizeof(val));
	if (x == 9 && s->addr[0] == 0x22)
		exit(200);
	return 0;
}
