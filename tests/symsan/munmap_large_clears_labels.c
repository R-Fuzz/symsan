// RUN: python -c'print("ABCD")' > %t.bin
// RUN: env KO_USE_Z3=1 %ko-clang -O0 -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin" timeout 60 %t.z3 %t.bin | FileCheck %s

// munmap clears the labels of what it unmapped.  For a large range it used to
// read every label of it: v8's cppgc cage, reserved and trimmed 8 GB at a
// time, faulted in 32 GB of shadow, minutes before V8::Initialize returned.
// Now the shadow's whole pages go back to the OS instead (zero when read
// again), and only the edges are written.  Mapped again at the same place,
// the bytes have no label: at the start, inside and at the end, as before.
// CHECK: before: 1 1 1
// CHECK: after: 0 0 0
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

typedef uint32_t dfsan_label;
extern dfsan_label dfsan_read_label(const void *addr, uint64_t size);

#define SIZE (16UL << 30)

int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], "rb");
  char in[4];
  if (!f || fread(in, 1, 4, f) != 4) return 1;
  int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
  char *p = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (p == MAP_FAILED) return 1;
  char *at[3] = {p, p + SIZE / 2 + 123, p + SIZE - 1};
  for (int i = 0; i < 3; i++) *at[i] = in[i];
  printf("before: %d %d %d\n", dfsan_read_label(at[0], 1) != 0,
         dfsan_read_label(at[1], 1) != 0, dfsan_read_label(at[2], 1) != 0);
  if (munmap(p, SIZE)) return 1;
  if (mmap(p, SIZE, PROT_READ | PROT_WRITE, flags | MAP_FIXED, -1, 0) != p)
    return 1;
  printf("after: %d %d %d\n", dfsan_read_label(at[0], 1) != 0,
         dfsan_read_label(at[1], 1) != 0, dfsan_read_label(at[2], 1) != 0);
  return 0;
}
