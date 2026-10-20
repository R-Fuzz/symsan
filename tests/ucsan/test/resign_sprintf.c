// METADATA: asm_cal.yaml
// ENV: KO_RESIGN_PTRARGS KO_CHECKER_UBI
// FLAG: 200
// ABSENT: 1 150

/*
 * snprintf writes the buffer it is given, so its stub resigns it like any
 * out-of-scope callee's: it was in the abilist's "ignore" list of I/O writes
 * (write, fprintf, ...), whose stubs do not, and the buffer stayed
 * uninitialized -- the read of buf[0] after it was a UBI report.  The
 * kernel's kprobe_event_delete snprintf()s "-:%s" into a stack buffer and
 * reads its first byte (create_or_delete_trace_kprobe, inlined).
 */
#include <stdio.h>
#include <stdlib.h>

int cal(const char *name)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "-:%s", name);
	if (buf[0] == '-')
		exit(200);
	return 0;
}
