// METADATA: bitfield_rmw_init.yaml
// ABSENT: 150
// FLAG: 200

#include <stdlib.h>

struct small { unsigned char size : 7, is_long : 1; };

__attribute__((noinline)) void init(struct small *s) {
  s->size = 0;
  s->is_long = 0;
}

int cal(int n) {
  struct small s;
  init(&s);
  if (s.is_long || s.size > n) return 0;
  exit(200);
}
