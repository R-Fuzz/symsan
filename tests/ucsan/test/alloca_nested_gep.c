// METADATA: alloca_nested_gep.yaml
// ABSENT: 200

#include <stdbool.h>
#include <stdlib.h>

void __ucsan_symbolize_input(void *ptr, unsigned long size, int id);

static unsigned char source[8];

struct inner {
	unsigned char bytes[8];
};

struct guarded_inner {
	unsigned char before;
	struct inner value;
	unsigned char after;
};

#define COPY_BYTE(output, index) (output)[index] = source[index]

int cal(void)
{
	struct guarded_inner nested = { .before = 0xa5, .after = 0xa5 };
	bool equal = true;

	__ucsan_symbolize_input(source, sizeof(source), 1);
	COPY_BYTE(nested.value.bytes, 0);
	COPY_BYTE(nested.value.bytes, 1);
	COPY_BYTE(nested.value.bytes, 2);
	COPY_BYTE(nested.value.bytes, 3);
	COPY_BYTE(nested.value.bytes, 4);
	COPY_BYTE(nested.value.bytes, 5);
	COPY_BYTE(nested.value.bytes, 6);
	COPY_BYTE(nested.value.bytes, 7);
	for (unsigned int index = 0; index < sizeof(source); index++)
		equal = equal && nested.value.bytes[index] == source[index];

	if (!equal)
		exit(200);
	return 0;
}

#undef COPY_BYTE
