// P1 through a loop: the table pointer is a phi that reaches itself through
// a select (t = c ? A.type : t), and tableOffsetFromGV's walk over selects
// and phis recursed around the cycle until opt ran out of stack (v8's absl
// numbers.cc, flags.cc).  It only has to finish; a pointer reached around a
// loop is not taken as a table.
//
// -O1 keeps the phi/select pointer instead of spilling it through an alloca.
//
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -o %t.fg %s
// RUN: %t.fg 3 | FileCheck %s
// CHECK: sum 5

#include <stdio.h>
#include <stdlib.h>

struct encoding {
  int min_bytes;
  unsigned char type[256];
};

static const struct encoding ascii_encoding = {
    1, {[0 ... 255] = 1, ['0' ... '9'] = 2}};
static const struct encoding latin1_encoding = {
    1, {[0 ... 255] = 2, ['a' ... 'z'] = 3}};

__attribute__((noinline)) int sum(const unsigned char *s, int n, int sel) {
  const unsigned char *t = latin1_encoding.type;
  int c = 0;
  for (int i = 0; i < n; i++) {
    c += t[s[i]];
    t = (s[i] & sel) ? ascii_encoding.type : t;
  }
  return c;
}

int main(int argc, char **argv) {
  unsigned char s[3] = {'b', 'c', 'd'};
  printf("sum %d\n", sum(s, 3, argc > 1 ? atoi(argv[1]) : 0));
  return 0;
}
