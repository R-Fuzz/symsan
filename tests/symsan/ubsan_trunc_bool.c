// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00')" > %t.bin
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: ls %t.out | count 0

// A trunc to i1 is no integer conversion, so it poses no truncation or sign-
// change UB task.  C converts to bool by `!= 0`; a trunc to i1 is codegen's
// own reading of a byte it knows holds 0 or 1 -- a bool bitfield here, `and 1`
// then trunc (InstCombine makes `(x & 1) != 0` one too).  Each bool read used
// to ask the solver for a "lossy" value (sext(trunc x) != x: x = 1, the bool's
// other value), and the sign-change check compared the i1 with `slt` against a
// constant the z3 parser built as a Bool: a null AST, cached as an expression,
// and "cannot find cached expression" for every v8 bool bitfield read.
// Nothing here branches, so a generated input could only come from such a task.

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"

struct flags { bool on : 1; bool off : 1; };

int main(int argc, char **argv) {
  if (argc < 2) return 1;
  FILE *fp = chk_fopen(argv[1], "rb");
  unsigned char c = 0;
  chk_fread(&c, 1, 1, fp);
  fclose(fp);

  struct flags s;
  memcpy(&s, &c, 1);
  bool on = s.on, off = s.off;
  printf("%d %d\n", on, off);
  return 0;
}
