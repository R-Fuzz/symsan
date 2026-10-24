// METADATA: asm_cal.yaml
// FLAG: 180 200
// EVENT: 106

#include <stdlib.h>

/*
 * The kernel's BUG() and WARN() are both `ud2` plus a __bug_table entry
 * passed as "i" operands (_BUG_FLAGS), so the asm is never clobber-only and
 * the trap is left in place; the target then dies of SIGILL, which the
 * runtime has no handler for (under apport this shows up as a hang, not a
 * failure).  BUG (flags without BUGFLAG_WARNING) must terminate like other
 * traps (exit 180); WARN (BUGFLAG_WARNING, bit 0) must continue, and is
 * reported as EVENT_WARN (106).
 */
#define BUGFLAG_WARNING (1 << 0)
#define BUGFLAG_TAINT(taint) ((taint) << 8)

#define _BUG_FLAGS(flags)						\
	__asm__ __volatile__("1:\t.byte 0x0f, 0x0b\n"			\
			     ".pushsection __bug_table,\"aw\"\n"	\
			     "2:\t.long 1b - .\n"			\
			     "\t.long %c0 - .\n"			\
			     "\t.word %c1\n"				\
			     "\t.word %c2\n"				\
			     "\t.org 2b+%c3\n"				\
			     ".popsection\n"				\
			     : : "i"(__FILE__), "i"(__LINE__),		\
			       "i"(flags), "i"(12))

int cal(int x)
{
	if (x == 42)
		_BUG_FLAGS(0);
	if (x == 43) {
		_BUG_FLAGS(BUGFLAG_WARNING | BUGFLAG_TAINT(9));
		exit(200);
	}
	return 0;
}
