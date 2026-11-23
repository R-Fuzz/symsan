// METADATA: memcmp_null_empty.yaml
// ENV: checker_nullderef
// ABSENT: 153
// FLAG: 200

#include <stdlib.h>
#include <string.h>

/*
 * An empty array's data is null (v8's UniqueArray<int>::CopiedFrom(p, 0)),
 * and comparing or copying it with a count of 0 touches no byte: libc++'s
 * equal of two empty ranges is __builtin_memcmp(nullptr, p, 0).  A pointer
 * a mem function takes with a byte count was checked as a dereference of
 * that count, 0 too, and an unlabeled null then exited 153.  The memcpy and
 * memset here are llvm.memcpy/llvm.memset of a non-constant length 0, a
 * no-op.  (A local null, not a global: under concrete_globals a global's
 * bytes carry labels, and a labeled pointer is checked whatever its value.)
 */
int cal(unsigned n)
{
	char a[4] = {1, 2, 3, 4};
	char *empty = NULL;
	size_t len = n & 0xff;
	if (len == 0) {
		if (memcmp(empty, a, len) != 0)
			return 1;
		memcpy(empty, a, len);
		memset(empty, 0, len);
	}
	if (len == 0x41)
		exit(200);
	return 0;
}
