// METADATA: asm_cal.yaml
// FLAG: 200

/*
 * A code template kept as data by a top-level asm() block (callthunks.c's
 * skl_call_thunk_template: `sarq $5, %gs:pcpu_hot + 16`) addressed a percpu
 * symbol absolutely, an R_X86_64_32S the PIE link refused.  Never run in
 * place, its percpu offset becomes 0, keeping the encoding and the length.
 */
#include <stdlib.h>

struct hot {
	long a, b, depth;
};
struct hot pcpu_hot;

asm(".pushsection .rodata\n"
    ".global tmpl_start\n"
    "tmpl_start:\n"
    "sarq $5, %gs:pcpu_hot + 16;\n"
    ".global tmpl_end\n"
    "tmpl_end:\n"
    ".popsection\n");

extern const char tmpl_start[], tmpl_end[];

int cal(int x)
{
	/* sarq $5, %gs:disp32: 65 48 c1 3c 25 <disp32> 05 */
	if (tmpl_end - tmpl_start == 10 && x == 7)
		exit(200);
	return 0;
}
