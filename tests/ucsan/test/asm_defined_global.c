// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 200
// SOLVER-ERROR-ABSENT

/*
 * A symbol defined by a top-level asm() block and declared extern in C --
 * kprobes' optprobe_template_entry -- is a declaration in the IR, and
 * UCSanPass gives undefined external globals a weak definition: it
 * collided with the asm's label at codegen ("symbol 'tmpl_entry' is
 * already defined"), and nothing was built.
 */
#include <stdlib.h>

asm(".pushsection .data\n"
    ".global tmpl_entry\n"
    "tmpl_entry:\n"
    ".byte 1, 2, 3, 4\n"
    ".popsection\n");

extern unsigned char tmpl_entry[];

int cal(int x)
{
	if (tmpl_entry[1] + x == 9)
		exit(200);
	return 0;
}
