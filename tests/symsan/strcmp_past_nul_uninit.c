// RUN: python -c"import sys; sys.stdout.buffer.write(b'A\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O0 -fno-builtin -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1 exit_on_memerror=1" %t.fg %t.bin 2>&1 | FileCheck %s

// strcmp(concrete, symbolic) lowers to an fmemcmp over the concrete side's
// length + 1 (str_cmp_len), so here it reads buf's third byte: past buf's
// terminator, never written, a stack byte trace_bounds marks uninitialized
// (kInitializingLabel).  strcmp itself stops at the terminator and never
// reads it, but the operand's label took it in, the comparison came out
// kInitializingLabel, and __taint_trace_memcmp took the strcmp for a use of
// uninitialized memory: Die() under exit_on_memerror (UCSan: a UBI, exit
// 150 -- v8's BignumTest.Square, EXPECT_EQ(0, strcmp("64", buffer)) with a
// symbolic buffer "1").  Bytes past a side's own terminator now count as
// the concrete bytes they hold.
// CHECK-NOT: uninitialized
// CHECK: done
#include <stdio.h>
#include <string.h>
#include "lib.h"

int main(int argc, char **argv) {
  char buf[8];
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, 2, fp);  // "A\0": buf[2..7] never written
  fclose(fp);
  int x = strcmp("ab", buf) == 0;
  x += strcasecmp("AB", buf) == 0;
  printf("done %d\n", x);
  return 0;
}
