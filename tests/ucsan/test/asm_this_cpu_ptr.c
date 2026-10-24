// METADATA: asm_cal.yaml
// ABSENT: 1
// FLAG: 200

#include <stdlib.h>

/*
 * this_cpu_ptr (arch/x86/include/asm/percpu.h) adds the percpu offset,
 * read from %gs:this_cpu_off, to a pointer in a register tied to the output.
 * When that asm ran as is, its result had no label, so a symbolic pointer
 * that came in NULL (the usual seed) reached the dereference unlabeled:
 * ucsan_check_pointer could not materialize it and the load faulted (Die()
 * -> exit status 1).  The kernel shape is perf_trace_*'s
 * `head = this_cpu_ptr(event_call->perf_events); hlist_empty(head)`.
 */
static unsigned long this_cpu_off; /* stands in for the percpu offset */

#define this_cpu_ptr(ptr)						\
({									\
	unsigned long tcp_ptr__;					\
	__asm__ ("add %%gs:%1, %0"					\
		 : "=r" (tcp_ptr__)					\
		 : "m" (this_cpu_off), "0" (ptr));			\
	(__typeof__(*(ptr)) *)tcp_ptr__;				\
})

struct head {
	int *first;
};

struct call {
	struct head *perf_events;
};

int cal(struct call *c)
{
	struct head *h = this_cpu_ptr(c->perf_events);

	if (h->first && *h->first == 7)
		exit(200);
	return 0;
}
