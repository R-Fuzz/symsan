// METADATA: asm_cal.yaml
// ABSENT: 1
// FLAG: 200 201

#include <stdlib.h>

/*
 * `call *%[f]` through a function pointer the seed gave, as
 * x86_emulate_insn's fastop(ctxt, ctxt->fop).  The C call through such a
 * pointer goes to an out-of-scope stub; run as is, the asm jumped to the
 * seed's value (exit status 1, SIGSEGV).  It is skipped instead, and its
 * caller-saved outputs are fresh symbolic values (200 on the result, 201
 * past it).
 */
struct ctxt {
	void (*fop)(void);
	unsigned long val;
};

int cal(struct ctxt *c)
{
	unsigned long ret = c->val, flags = 0;
	void (*fop)(void) = c->fop;

	__asm__ __volatile__("push %[flags]; popf; call *%[f]; pushf; pop %[flags]"
			     : "+a"(ret), [flags] "+D"(flags), [f] "+S"(fop)
			     :
			     : "memory", "rdx", "rcx", "r8", "r9", "r10", "r11");
	if (ret == 0x1234)
		exit(200);
	exit(201);
}
