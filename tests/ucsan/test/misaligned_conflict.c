// METADATA: asm_cal.yaml
// FLAG: 126
// CFLAGS: -O2

/*
 * Two accesses to one object that no placement satisfies -- 16-byte aligned
 * 16-byte accesses 8 bytes apart -- are the code's own misalignment, and the
 * second would fault (movaps): an error, rather than a move back and forth.
 */
#include <stdlib.h>

typedef int v4si __attribute__((vector_size(16)));

int cal(char *c, v4si *out)
{
	out[0] = *(volatile v4si *)c;
	out[1] = *(volatile v4si *)(c + 8);
	exit(200);
}
