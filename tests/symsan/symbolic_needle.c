// String-theory: the two symbolic-needle cases concrete_haystack.c does not
// reach.  There the needle is absent and every character that would find it is
// plain ASCII, so only one direction and one encoding get exercised.
//
// Test 1 is the OTHER direction: the seed's needle is already in the haystack,
// so the search succeeds and the solver has to move the character OUT of it.
// There is no "clear the haystack" option here the way there is when the
// haystack is the symbolic side -- "deadbeef" is program text -- so the only
// answer is a different character, and it has to avoid all five of the
// haystack's distinct bytes rather than just the one the seed picked.
//
// Test 2 is the other encoding.  Every character of its haystack is >= 0x80, so
// the answer cannot be a byte that survives a bare i2s_invert: the needle
// arrives as SExt(Read i8) and 0xe9 is not representable in that i8 child --
// only the sign-extended 0xffffffe9, which denotes the same character, is.  A
// solver that tried the zero-extended value alone would decline this branch
// and would decline it silently, since declining is how every unsupported
// shape exits.
//
// RUN: python3 -c "import sys; sys.stdout.buffer.write(b'ab')" > %t.bin
// RUN: clang -O0 -fno-builtin -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O0 -fno-builtin -o %t.fg %s
//
// The RGD path (afltest -> parsers/rgd-parser.cpp -> i2s) is the one under
// test; solvers/z3-ts.cpp reaches these through its own string theory and is
// covered by concrete_haystack.c's fgtest arm.
// RUN: rm -rf %t.rgd.out
// RUN: mkdir -p %t.rgd.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.rgd.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char input[16] = {0};
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    return -1;
  }
  size_t n = fread(input, 1, sizeof(input) - 1, fp);
  fclose(fp);
  input[n] = '\0';

  // Test 1: the seed's 'a' IS in the haystack, so the miss is the flip.
  const char *hay1 = "deadbeef";
  if (strchr(hay1, input[0]) == NULL) {
    // CHECK-GEN1: absent
    printf("test1: absent\n");
  } else {
    // CHECK-ORIG: present
    printf("test1: present\n");
  }

  // Test 2: a haystack of bytes that are all negative as `char`.
  const char *hay2 = "\xe9\xea\xeb";
  if (strchr(hay2, input[1]) != NULL) {
    // CHECK-GEN2: hit
    printf("test2: hit\n");
  } else {
    // CHECK-ORIG: no hit
    printf("test2: no hit\n");
  }

  return 0;
}
