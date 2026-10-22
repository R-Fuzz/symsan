// METADATA: asm_cal.yaml
// ABSENT: 1
// FLAG: 200 201 202 203

#include <stdlib.h>

/*
 * Privileged instructions fault in a userspace run (a general-protection
 * fault, SIGSEGV with SI_KERNEL, then Die() -> exit status 1).  They are
 * modeled instead: a read of hardware state is a fresh symbolic value, so a
 * branch on it is solvable (200: rdmsr, as native_read_msr writes it with its
 * exception-table entry; 201: mov from %cr3; 202: inb; 203: rdpmc), and a
 * write or a control instruction does nothing (cli/sti, wrmsr, outb, wbinvd,
 * mov to %cr3, lgdt).
 */
struct desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed));

static inline __attribute__((always_inline)) unsigned long long
native_read_msr(unsigned int msr)
{
	unsigned long low, high;

	__asm__ __volatile__("1: rdmsr\n"
			     "2:\n"
			     " .pushsection \"__ex_table\",\"a\"\n"
			     " .balign 4\n"
			     " .long (1b) - .\n"
			     " .long (2b) - .\n"
			     " .long 9 \n"
			     " .popsection\n"
			     : "=a"(low), "=d"(high) : "c"(msr));
	return low | (high << 32);
}

static inline __attribute__((always_inline)) void
native_write_msr(unsigned int msr, unsigned int low, unsigned int high)
{
	__asm__ __volatile__("1: wrmsr\n"
			     "2:\n"
			     " .pushsection \"__ex_table\",\"a\"\n"
			     " .balign 4\n"
			     " .long (1b) - .\n"
			     " .long (2b) - .\n"
			     " .long 8 \n"
			     " .popsection\n"
			     : : "c"(msr), "a"(low), "d"(high) : "memory");
}

static inline __attribute__((always_inline)) unsigned long read_cr3(void)
{
	unsigned long val;

	__asm__ __volatile__("mov %%cr3,%0\n\t" : "=r"(val) : : "memory");
	return val;
}

static inline __attribute__((always_inline)) void write_cr3(unsigned long val)
{
	__asm__ __volatile__("mov %0,%%cr3" : : "r"(val) : "memory");
}

static inline __attribute__((always_inline)) unsigned char inb(unsigned short port)
{
	unsigned char v;

	__asm__ __volatile__("inb %w1, %b0" : "=a"(v) : "Nd"(port));
	return v;
}

static inline __attribute__((always_inline)) void
outb(unsigned char v, unsigned short port)
{
	__asm__ __volatile__("outb %b0, %w1" : : "a"(v), "Nd"(port));
}

static inline __attribute__((always_inline)) unsigned long long rdpmc(int counter)
{
	unsigned long low, high;

	__asm__ __volatile__("rdpmc" : "=a"(low), "=d"(high) : "c"(counter));
	return low | (high << 32);
}

int cal(int x)
{
	struct desc_ptr gdt = { 0, 0 };

	/*
	 * wrfsbase is not privileged where FSGSBASE is on, as Linux turns it on
	 * for userspace, and run as is it moves the process's own TLS: the next
	 * TLS access kills it (do_arch_prctl_64).  Writing hardware state, it
	 * does nothing.
	 */
	__asm__ __volatile__("wrfsbase %0" : : "r"((unsigned long)x) : "memory");
	__asm__ __volatile__("cli" : : : "memory");
	native_write_msr(0x10, (unsigned int)x, 0);
	outb(0x42, 0x80);
	__asm__ __volatile__("wbinvd" : : : "memory");
	__asm__ __volatile__("lgdt %0" : : "m"(gdt));
	write_cr3(0x1000);
	__asm__ __volatile__("sti" : : : "memory");

	if (native_read_msr(0x10) == 0x1234567890ULL)
		exit(200);
	if (read_cr3() == 0xabcd000UL)
		exit(201);
	if (inb(0x60) == 0x42)
		exit(202);
	if (rdpmc(0) == 7)
		exit(203);
	return 0;
}
