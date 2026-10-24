// METADATA: asm_cal.yaml
// ABSENT: 1 210 211 212 213
// FLAG: 200 201

#include <stdlib.h>

/*
 * VMX instructions fault outside VMX operation.  vmread/vmwrite act on the
 * runtime's model of the VMCS (ucsan_vmcs_field) instead, in the kernel's
 * asm goto shapes (arch/x86/kvm/vmx/vmx_ops.h: __vmcs_readl, vmx_asm2):
 *
 * - a field read before any write is symbolic, so a branch on the VM-exit
 *   reason is solvable (200);
 * - a read after a write returns what was written (212 never), label
 *   included, so a branch on it is solvable through the argument (201);
 * - they succeed: the `jna` failure path (210, 213) and the exception fixup
 *   (211) are never taken.
 */
#define EXTABLE(from, to)						\
	" .pushsection \"__ex_table\",\"a\"\n"				\
	" .balign 4\n"							\
	" .long (" #from ") - .\n"					\
	" .long (" #to ") - .\n"					\
	" .long 0 \n"							\
	" .popsection\n"

#define VM_EXIT_REASON 0x00004402UL
#define GUEST_RIP 0x0000681eUL

static inline __attribute__((always_inline)) unsigned long
vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm goto("1: vmread %[field], %[output]\n\t"
		 "jna %l[do_fail]\n\t"
		 EXTABLE(1b, %l[do_exception])
		 : [output] "=r" (value)
		 : [field] "r" (field)
		 : "cc"
		 : do_fail, do_exception);
	return value;
do_fail:
	exit(210);
do_exception:
	exit(211);
}

static inline __attribute__((always_inline)) void
vmcs_writel(unsigned long field, unsigned long value)
{
	asm goto("1: vmwrite %1, %0\n\t"
		 ".byte 0x2e\n\t"
		 "jna %l[error]\n\t"
		 EXTABLE(1b, %l[fault])
		 : : "r" (field), "rm" (value) : "cc" : error, fault);
	return;
error:
	exit(213);
fault:
	exit(211);
}

int cal(unsigned long x)
{
	if (vmcs_readl(VM_EXIT_REASON) == 30)
		exit(200);

	vmcs_writel(GUEST_RIP, x);
	if (vmcs_readl(GUEST_RIP) != x)
		exit(212);
	if (vmcs_readl(GUEST_RIP) == 0xffffffff81000000UL)
		exit(201);
	return 0;
}
