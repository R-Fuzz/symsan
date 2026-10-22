// METADATA: asm_cal.yaml
// ABSENT: 1 201
// FLAG: 200

#include <stdlib.h>

/*
 * `mov $1f, %0` with `1:` in another section's data, as the kernel's
 * TRACE_RESUME writes it (device_resume): the address of a packed
 * {u16 line; char *file} record in .tracedata.  Run as is, that address is an
 * absolute 32-bit relocation, and a PIE does not link.  It is lowered to the
 * address of a private global holding the same record (201 if it does not).
 */
struct rec {
	unsigned short line;
	const char *file;
} __attribute__((packed));

#define LINE 4242

int cal(int x)
{
	const void *td;

	__asm__ __volatile__("movq $1f,%0\n"
			     ".section .tracedata,\"a\"\n"
			     "1:\t.word %c1\n\t"
			     ".quad %c2\n"
			     ".previous"
			     : "=r"(td)
			     : "i"(LINE), "i"("rec.c"));
	const struct rec *r = td;
	if (r->line != LINE || r->file[0] != 'r' || r->file[3] != '.')
		exit(201);
	if (x == 3)
		exit(200);
	return 0;
}
