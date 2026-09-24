// METADATA: asm_cal.yaml
// ABSENT: 123 202 203 205
// FLAG: 200 201 204

#include <stdlib.h>

/*
 * Inline asm calls into helpers the module has no Function for: in the kernel
 * those are ALTERNATIVE fallbacks and the uaccess helpers, which live in
 * another object or in assembly.  Each is written here the way the kernel
 * writes it, with the helper defined in module asm so the native build links.
 * Such an asm used to be deleted, its result replaced by a same-typed input
 * or zero.  The helpers are __always_inline, as in the kernel, so the asm sits
 * in the in-scope caller.
 *
 * - arch_hweight32: `call __sw_hweight32` becomes a call to a declared
 *   __sw_hweight32; out of scope, its result is unconstrained, not the input
 *   passed through (201 reachable, as natively);
 * - copy_user_generic: `rep movsb` (fallback `call rep_movs_alternative`)
 *   becomes a memcpy, labels included (202 absent, 200 solvable);
 * - this_cpu_try_cmpxchg128: `call this_cpu_cmpxchg16b_emu` becomes a
 *   compare-and-exchange; deleted, it always "failed" and SLUB's fastpath
 *   retried forever (bounded here by 203; the loop threshold ends it at 123);
 * - get_user / put_user: `call __get_user_%P4` / `__put_user_%P4` become a
 *   load / store through the user pointer (204 solvable, 205 absent).
 *
 * A native build of this file needs -mno-red-zone, as the kernel has: the
 * asm `call`s push onto the stack below a leaf function's locals.  The
 * instrumented build lowers every one of these asms, so no `call` is left.
 */
#define ALTERNATIVE(oldinstr, newinstr)				\
	"661:\n\t" oldinstr "\n662:\n"					\
	".pushsection .altinstr_replacement,\"ax\"\n"		\
	"6641:\n\t" newinstr "\n6651:\n"				\
	".popsection\n"

__asm__(".text\n"
	".globl __sw_hweight32\n"
	"__sw_hweight32:\n"
	"\tpopcntl %edi, %eax\n"
	"\tret\n"
	".globl rep_movs_alternative\n"
	"rep_movs_alternative:\n"
	"\trep movsb\n"
	"\tret\n"
	".globl this_cpu_cmpxchg16b_emu\n"
	"this_cpu_cmpxchg16b_emu:\n"
	"\tlock cmpxchg16b (%rsi)\n"
	"\tret\n"
	".globl __get_user_4\n"
	"__get_user_4:\n"
	"\tmovl (%rax), %edx\n"
	"\txorl %eax, %eax\n"
	"\tret\n"
	".globl __put_user_4\n"
	"__put_user_4:\n"
	"\tmovl %eax, (%rcx)\n"
	"\txorl %ecx, %ecx\n"
	"\tret\n");

/* ASM_CALL_CONSTRAINT: a global register variable, as in the kernel */
register unsigned long current_stack_pointer __asm__("rsp");

static inline __attribute__((always_inline)) unsigned int
hweight32(unsigned int w)
{
	unsigned int res;

	__asm__(ALTERNATIVE("call __sw_hweight32", "popcntl %%edi, %%eax")
		: "=a"(res)
		: "D"(w));
	return res;
}

static inline __attribute__((always_inline)) unsigned long
copy_user(void *to, const void *from, unsigned long len)
{
	__asm__ __volatile__("1:\n\t"
			     ALTERNATIVE("rep movsb", "call rep_movs_alternative")
			     : "+c"(len), "+D"(to), "+S"(from), "+r"(current_stack_pointer)
			     : : "memory", "rax");
	return len;
}

static inline __attribute__((always_inline)) _Bool
try_cmpxchg128(unsigned __int128 *var, unsigned __int128 *oldp,
			    unsigned __int128 new)
{
	unsigned long lo = (unsigned long)*oldp;
	unsigned long hi = (unsigned long)(*oldp >> 64);
	_Bool ok;

	__asm__ __volatile__(ALTERNATIVE("call this_cpu_cmpxchg16b_emu",
					 "cmpxchg16b %%gs:(%%rsi)")
			     : "=@ccz"(ok), "+m"(*var), "+a"(lo), "+d"(hi)
			     : "b"((unsigned long)new),
			       "c"((unsigned long)(new >> 64)), "S"(var)
			     : "memory");
	if (!ok)
		*oldp = ((unsigned __int128)hi << 64) | lo;
	return ok;
}

static inline __attribute__((always_inline)) int
get_user4(unsigned int *val, unsigned int *uptr)
{
	register unsigned int v __asm__("rdx");
	int ret;

	__asm__ __volatile__("call __get_user_%P4"
			     : "=a"(ret), "=r"(v), "+r"(current_stack_pointer)
			     : "0"(uptr), "i"(sizeof(*uptr)));
	*val = v;
	return ret;
}

static inline __attribute__((always_inline)) int
put_user4(unsigned int val, unsigned int *uptr)
{
	register unsigned int v __asm__("rax") = val;
	int ret;

	__asm__ __volatile__("call __put_user_%P4"
			     : "=c"(ret), "+r"(current_stack_pointer)
			     : "0"(uptr), "r"(v), "i"(sizeof(*uptr))
			     : "ebx");
	return ret;
}

static unsigned __int128 slot __attribute__((aligned(16)));

int cal(unsigned int w, char *src, unsigned int *uptr)
{
	char dst[4] = {0};
	unsigned __int128 old;
	unsigned int v;
	int tries;

	if (hweight32(w) != w)
		exit(201);

	if (copy_user(dst, src, sizeof(dst)) != 0 || dst[0] != src[0])
		exit(202);
	if (dst[0] == 'A')
		exit(200);

	for (tries = 0; tries < 100; tries++) {
		old = slot;
		if (try_cmpxchg128(&slot, &old, old + 1))
			break;
	}
	if (tries == 100)
		exit(203);

	if (get_user4(&v, uptr) == 0 && v == 0x1234)
		exit(204);
	put_user4(0x55, uptr);
	if (*uptr != 0x55)
		exit(205);
	return 0;
}
