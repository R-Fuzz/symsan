// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -fno-builtin -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1 exit_on_memerror=0" %t.fg %t.bin 2>&1 | FileCheck %s

// Under trace_bounds a stack object's bytes start labeled kInitializingLabel
// (-1), and a select on one gives its result that label: here a pointer, the
// way libc++'s data() selects on is_long.  The custom functions looked a
// pointer's label up as if it were one, and dfsan_get_label_info(-1) Die()s
// with "out of labels" -- v8's Interpreter::Initialize, comparing a short
// std::string with bcmp.  __taint_check_bounds reports the use, and with
// exit_on_memerror off the run goes on.
// CHECK-NOT: out of labels
// CHECK: done
#include <stdio.h>
#include <string.h>

struct rep {
  unsigned char hdr;  // never written
  char data[7];
};

__attribute__((noinline)) const char *pick(struct rep *r, const char *a,
                                           const char *b) {
  return (r->hdr & 1) ? a : b;
}

int main(int argc, char **argv) {
  struct rep r;
  char a[4] = {'a', 'b', 'c', 'd'}, b[4] = {'a', 'b', 'c', 'e'};
  const char *p = pick(&r, a, b);
  volatile size_t n = 4;
  int x = memcmp(p, "abcd", n) != 0;
  x += bcmp(p, "abcd", n) != 0;
  printf("done %d\n", x);
  return 0;
}
