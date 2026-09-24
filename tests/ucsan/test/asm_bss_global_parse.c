// METADATA: asm_bss_global_parse.yaml
// SOLVER-ERROR-ABSENT
// DISCARD: 201

#include <stdlib.h>

/*
 * The inline asm writes a BSS global without updating the taint shadow.
 * UCSan symbolizes the global at the following C read. The solver must not
 * reject the comparison because its modeled initial byte differs from the
 * concrete value produced by the asm write.
 */
static int preempt_count;

int cal(void)
{
	__asm__ __volatile__("addl $1, %0" : "+m"(preempt_count) :: "memory");
	if (preempt_count != 1)
		exit(201);
	return 0;
}
