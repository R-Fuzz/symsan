// METADATA: asm_cal.yaml
// FLAG: 200
// ABSENT: 153 1

/*
 * An indirect call gets a direct call to each wrapped function of its type
 * whose address is taken (indirect_call_wrapped.c), taken when the pointer
 * is that function.  For a symbolic pointer -- a slot of an object UCSan
 * made up, a vtable's in a C++ test -- the comparison was a branch the
 * solver flipped: o->len == strlen, then strlen(NULL), a null
 * dereference.  Linking the instrumented libc++ made every libc++ function such a
 * target, and v8's unit tests ran libc++'s ~basic_ostream on a fake
 * v8::Platform (a segfault, exit 1).  A symbolic function pointer is an
 * unknown callee; only a concrete one is compared.
 */
#include <stdlib.h>
#include <string.h>

struct ops { size_t (*len)(const char *); };

size_t (*volatile measure)(const char *) = strlen;

int cal(struct ops *o, int x)
{
	size_t n = o->len(NULL);

	if (x == 9 && n == 5)
		exit(200);
	return 0;
}
