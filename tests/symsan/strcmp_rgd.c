// Regression test: the str*cmp family has to be solvable on the RGD path, the
// one a fuzzer actually runs.
//
// Two separate bugs made this fail, and both are invisible to the %fgtest
// suite because solvers/z3-ts.cpp handles cases parsers/rgd-parser.cpp does
// not:
//
//   1. The wrappers tagged every comparison fstrcmp.  rgd-parser has no
//      fstrcmp case, so the label was rejected with "invalid op: 85", the task
//      was never built, and the whole ladder (i2s, jigsaw, z3) never saw the
//      constraint.  A str*cmp against a literal is a fixed-width byte
//      comparison and is now tagged fmemcmp, exactly as __dfsw_memcmp already
//      tagged the same thing.
//
//   2. The operand labels came from get_str_label(), which measures with
//      strlen() rather than with the compared length.  Guard A's buffer is
//      deliberately NOT terminated, so strlen() runs past all 64 tainted bytes
//      and the label was 64 bytes wide while the fmemcmp said 4 -- which
//      reaches jigsaw's JIT as "icmp eq i64 %x, i512 %y" and aborts the
//      process in the IR verifier.
//
// Guard B pins the width rule for the unbounded strcmp: the comparison is as
// wide as the *concrete* side plus its NUL (7), not as wide as the symbolic
// side (9).  Taking the symbolic side's length would read the constant content
// past the end of "secret" and constrain whatever follows it in .rodata.
//
// The seed has no zero byte anywhere, so nothing terminates by accident.
//
// The checks are independent (not nested behind an early bail), so one
// concolic run emits one input per check (see tests/symsan/switch.c).
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'import sys; sys.stdout.buffer.write(b"A"*64)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  // No initializer and no terminator: all 64 bytes are tainted and strlen()
  // walks off the end of them.
  char buf[64];
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  // Guard A: bounded comparison against a literal, on the unterminated buffer.
  if (strncmp(buf, "0123", 4) == 0) {
    // CHECK-GEN1: GoodA
    printf("GoodA\n");
  }

  // Guard B: unbounded comparison, symbolic side longer than the literal.
  char s[16];
  memcpy(s, buf + 16, 9);
  s[9] = '\0';
  if (strcmp(s, "secret") == 0) {
    // CHECK-GEN2: GoodB
    printf("GoodB\n");
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
