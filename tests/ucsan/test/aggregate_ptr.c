// METADATA: aggregate_ptr.yaml
// CFLAGS: -O2
// ABSENT: 1
// FLAG: 200

#include <stdlib.h>

/*
 * A pointer that travels in an aggregate: pick returns { ptr, i64 } in
 * registers, built with insertvalue and taken apart with extractvalue (as
 * get_user's lowered asm result is).  Its UCSan label must go with it, or the
 * pseudo pointer the seed gave *pp is dereferenced unchecked (exit status 1,
 * SIGSEGV) instead of being materialized.
 */
struct pr {
	int *p;
	long n;
};

__attribute__((noinline)) struct pr pick(int **pp, long n)
{
	struct pr r = { *pp, n };
	return r;
}

int cal(int **pp, long n)
{
	struct pr r = pick(pp, n);
	if (*r.p == 0x1234)
		exit(200);
	return (int)r.n;
}
