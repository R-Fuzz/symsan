// METADATA: asm_cal.yaml
// ENV: trace_bounds KO_RESIGN_PTRARGS
// CFLAGS: -O2
// FLAG: 201
// ABSENT: 150

/*
 * The condition of a select is not a use of an uninitialized value; the
 * select's result is what depends on it.  This is register_kretprobe's
 * kprobe_on_func_entry: ok is set only by adjust(), and read in the source
 * only once IS_ERR() has said that adjust() ran.  At -O2 the load of ok is
 * speculated to where the paths merge and feeds a select,
 *
 *   %ok  = load i32, ptr %ok.addr      ; also on the paths that skip adjust()
 *   %sel = select i1 (%ok == 0), i32 -22, i32 0
 *   %ret = select i1 IS_ERR(p), i32 (int)p, i32 %sel
 *
 * and tracing %sel's condition as a branch reported a UBI (150) on the
 * ERR_PTR paths, where %ret never takes %sel.  (Only -O2 has the speculation;
 * the ERR_PTRs are pointers, as in the kernel, because the jump threading
 * that would otherwise remove the merge does not fold an inttoptr compare.)
 */
#include <stdlib.h>

void *lookup_name(long key);
void *adjust(void *addr, int *ok);

static void *ERR_PTR(long error)
{
	return (void *)error;
}

static int IS_ERR(const void *ptr)
{
	return (unsigned long)ptr >= (unsigned long)-4095;
}

static void *find(void *addr, long key, int *ok)
{
	if (!addr && !key)
		goto invalid;
	if (key) {
		addr = lookup_name(key);
		if (!addr)
			return ERR_PTR(-2);
	}
	addr = adjust(addr, ok);
	if (addr)
		return addr;
invalid:
	return ERR_PTR(-22);
}

static int check(void *addr, long key)
{
	int ok;
	void *p = find(addr, key, &ok);

	if (IS_ERR(p))
		return (int)(long)p;
	if (!ok)
		return -22;
	return 0;
}

int cal(void *addr, long key)
{
	if (check(addr, key) == 0)
		exit(201);
	return 0;
}
