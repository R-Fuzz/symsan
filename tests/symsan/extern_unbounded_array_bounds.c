// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x01\x00\x00\x00')" > %t.bin
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1" %t.fg %t.bin 2>&1 | FileCheck %s

// An array of unknown bound (`extern T a[]`, [0 x T] in IR) has no bounds the
// program knows: its size is the linker's, as for the table a section's
// __start_ symbol begins (cppgc's GCInfo table, gc_info_section).  It used to
// be traced as the bounds [a, a), and its first read was an OOB overflow.
// CHECK-NOT: OOB
// CHECK: finalize 2
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct info { long id; long size; };

__attribute__((used, section("ko_info_section")))
static const struct info info0 = {1, 16};
__attribute__((used, section("ko_info_section")))
static const struct info info1 = {2, 32};

extern const struct info __start_ko_info_section[];

int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], "rb");
  uint32_t i = 0;
  if (!f || fread(&i, 1, sizeof(i), f) != sizeof(i)) return 1;
  // (the index is the input's: a concrete one would never be checked)
  const struct info *p = &__start_ko_info_section[i & 1];
  printf("finalize %ld\n", p->id);
  return 0;
}
