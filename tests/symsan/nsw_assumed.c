// RUN: rm -rf %t.out %t.nf.out
// RUN: mkdir -p %t.out %t.nf.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\xf8\xff\xff\x7f')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 KO_DONT_OPTIMIZE=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: test ! -e %t.out/id-0-0-0
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.nf.out model_poison=0" %fgtest %t.fg %t.bin
// RUN: test -e %t.nf.out/id-0-0-0
//
// `a + 16` on an int is an add nsw: the compiled code may assume it does not
// overflow, so a run in which it does has poison the model cannot follow.
// With a = INT_MAX - 7 the seed overflows: the run reports it and ends there
// (exit_on_poison), and the branch after it -- whose recorded outcome no
// longer follows from its label -- is not solved.  model_poison=0 is the old
// behaviour, which traces past it and solves the branch.  (Held, the
// condition is assumed on the path instead; tests/ucsan/test/ptr_diff_exact.c
// covers that half, since fgtest's optimistic solving answers an infeasible
// nested query anyway.)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2)
    return 0;
  int32_t a = 0;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&a, sizeof(a), 1, fp);
  fclose(fp);

  if (a + 16 < a)
    printf("wrapped\n");
  else
    printf("ok\n");
  return 0;
}
