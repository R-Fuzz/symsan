// The python binding's fork server, and the only coverage the binding has.
//
// The fork server is meant to be a pure performance change -- it swaps execv,
// dynamic linking and the shadow and union table setup for a fork -- so the
// test is that one corpus traced with it produces the same events as the same
// corpus traced without.  That equality is worth asserting rather than
// assuming: the server's input path is fixed once it is running, so a wrapper
// that let a caller point it somewhere new would serve the *first* input over
// and over and report a perfectly ordinary-looking event stream every time.
// The driver also checks that config() refuses to change anything the running
// server cannot honour, which is what keeps that failure from being silent.
//
// The target below is deliberately small and deliberately varied: a byte
// compare, a range compare, a four-byte assembly and a memcmp, so that the
// stream carries a payload record as well as plain conditions.
//
// REQUIRES: pysymsan
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O0 -o %t.fg %s
// RUN: env PYTHONPATH=%pysymsan-path %python \
// RUN:     %S/../../bindings/python/test_forkserver.py %t.fg | FileCheck %s

// CHECK: ok frozen-config
// CHECK: PASS

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) return 1;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;
  unsigned char buf[64];
  size_t n = fread(buf, 1, sizeof(buf), f);
  fclose(f);
  if (n < 8) {
    printf("short %zu\n", n);
    return 0;
  }
  if (buf[0] == 'A') printf("a\n");
  if (buf[1] > 0x40) printf("b\n");
  unsigned v = buf[2] | (buf[3] << 8) | (buf[4] << 16) | (buf[5] << 24);
  if (v == 0xdeadbeef) printf("c\n");
  if (!memcmp(buf, "MAGICHDR", 8)) printf("d\n");
  return 0;
}
