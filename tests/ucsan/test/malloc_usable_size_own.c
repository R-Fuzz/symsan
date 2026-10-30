// METADATA: malloc_usable_size_own.yaml
// ABSENT: 201
// FLAG: 200

// A program with its own malloc_usable_size, as v8's PartitionAlloc malloc
// shim has: asked about an object UCSan's malloc allocated (__libc_malloc's),
// it does not know it (PA_NOTREACHED).  UCSan's wrapper answers instead, with
// the size the object was asked for, its bounds.
#include <stddef.h>
#include <stdlib.h>

size_t malloc_usable_size(void *p) { exit(201); }

int cal(int n) {
  char *p = malloc(24);
  if (malloc_usable_size(p) == 24) exit(200);
  return n;
}
