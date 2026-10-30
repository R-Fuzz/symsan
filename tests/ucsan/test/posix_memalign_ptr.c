// METADATA: posix_memalign_ptr.yaml
// FLAG: 200

// posix_memalign's object is the stored pointer's: UCSan's wrapper used to
// leave the object's SymSan bounds label in the retval TLS, so the int result
// took it and the pointer had none.  The result is a plain 0 now, and the
// object is usable through the pointer.
#include <stdlib.h>

int cal(int n) {
  void *p;
  if (posix_memalign(&p, 64, 128) != 0) return 0;
  char *c = p;
  c[0] = 1;
  if (((unsigned long)p & 63) == 0 && c[0] == 1) exit(200);
  return n;
}
