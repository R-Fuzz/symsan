// METADATA: label_space_meet.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/label_space_meet.abilist
// LIB: label_space_meet_lib.c
// ABSENT: 152
// FLAG: 1

#include <stdlib.h>

/*
 * Heap labels are allocated upward and a frame's stack labels downward, in
 * one 16-bit space.  allocate_label checked the heap's against the stack's
 * top, but a frame was never checked against the heap: a call deeper than
 * the stack was when the heap's last label was taken re-made that label a
 * stack object's, and a use of the heap object after the frame was gone was
 * an OOB against the callee's local (v8's PreParserScopeAnalysis, after 65k
 * labels: the PreParser that operator new returned).  The spaces meeting is
 * the labels running out, as it is for the heap.
 * (72 frames of 1024 locals: nine functions, each 8 deep -- the backend ends
 * a function's recursion at test.py's threshold -- called through library
 * code, whose frames take no labels, a trampoline per function.)
 */
#define DECL(k) void lib_call##k(void (*f)(int), int n);
DECL(0) DECL(1) DECL(2) DECL(3) DECL(4) DECL(5) DECL(6) DECL(7) DECL(8)

#define L4(x) volatile char x##0[8], x##1[8], x##2[8], x##3[8];
#define L16(x) L4(x##a) L4(x##b) L4(x##c) L4(x##d)
#define L64(x) L16(x##a) L16(x##b) L16(x##c) L16(x##d)
#define L256(x) L64(x##a) L64(x##b) L64(x##c) L64(x##d)
#define T4(x) x##0[0] = x##1[0] = x##2[0] = x##3[0] = (char)n;
#define T16(x) T4(x##a) T4(x##b) T4(x##c) T4(x##d)
#define T64(x) T16(x##a) T16(x##b) T16(x##c) T16(x##d)
#define T256(x) T64(x##a) T64(x##b) T64(x##c) T64(x##d)

#define DIVE(k, next)                         \
	void dive##k(int n)                       \
	{                                         \
		L256(a) L256(b) L256(c) L256(d)       \
		T256(a) T256(b) T256(c) T256(d)       \
		if (n > 0)                            \
			lib_call##k(dive##k, n - 1);      \
		else                                  \
			next;                             \
	}

DIVE(8, (void)0)
DIVE(7, lib_call8(dive8, 7))
DIVE(6, lib_call7(dive7, 7))
DIVE(5, lib_call6(dive6, 7))
DIVE(4, lib_call5(dive5, 7))
DIVE(3, lib_call4(dive4, 7))
DIVE(2, lib_call3(dive3, 7))
DIVE(1, lib_call2(dive2, 7))
DIVE(0, lib_call1(dive1, 7))

int cal(int n)
{
	char *p = malloc(1);
	lib_call0(dive0, 7);
	p[0] = (char)n;
	return p[0];
}
