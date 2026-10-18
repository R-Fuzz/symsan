// METADATA: asm_cal.yaml
// FLAG: 200

/*
 * An FPU state restore loads hardware state from memory, like wrmsr from
 * registers, and is a no-op in the model.  fpu__restore_sig's fxrstor64 of
 * a signal frame from the seed ran as is: reserved MXCSR bits are a general
 * protection fault (the kernel's exception table turns it into an error),
 * and a valid frame would have loaded the seed into the process's own FPU.
 */
#include <stdlib.h>

struct fxregs {
	unsigned char b[512];
} __attribute__((aligned(16)));

int cal(struct fxregs *fx)
{
	int err;

	if (*(unsigned int *)&fx->b[24] != 0xffffffffu)
		return 0;
	asm volatile("xor %0, %0\n\t"
		     "fxrstor64 %1"
		     : "=r"(err) : "m"(*fx) : "memory");
	if (err == 0 && fx->b[0] == 'x')
		exit(200);
	return 0;
}
