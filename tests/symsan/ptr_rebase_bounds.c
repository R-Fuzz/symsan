// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -o %t.fg %s
// RUN: env TAINT_OPTIONS="debug=1 trace_bounds=1" %t.fg 2>&1 | FileCheck %s

// A pointer moved to a new buffer by the difference of the buffers' starts,
// p += new - old, is in the new buffer: v8's Assembler::GrowBuffer moves its
// pc_ that way (pc_delta).  A bounds label does not survive ptrtoint, so the
// difference had none and the result kept p's, the old buffer's: each write
// after a grow was reported against the old (freed) buffer.  The same through
// a typed pointer (an exact division of the difference).
// -O1 keeps the difference an SSA value, as v8's optimized build does.
// CHECK-NOT: OOB
// CHECK-NOT: UAF
// CHECK: sum 4356
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct buf {
  char *start, *pc;
  int *words, *wp;
  int size;
};

__attribute__((noinline)) static void grow(struct buf *b) {
  char *n = malloc(b->size * 2);
  int *w = malloc(b->size * 2 * sizeof(int));
  ptrdiff_t delta = n - b->start;
  ptrdiff_t wdelta = w - b->words;
  memmove(n, b->start, b->pc - b->start);
  memmove(w, b->words, (b->wp - b->words) * sizeof(int));
  free(b->start);
  free(b->words);
  b->start = n;
  b->words = w;
  b->pc += delta;
  b->wp += wdelta;
  b->size *= 2;
}

__attribute__((noinline)) static void emit(struct buf *b, char c) {
  if (b->pc - b->start == b->size) grow(b);
  *b->pc++ = c;
  *b->wp++ = c;
}

int main(void) {
  struct buf b = {malloc(4), 0, malloc(4 * sizeof(int)), 0, 4};
  b.pc = b.start;
  b.wp = b.words;
  for (int i = 0; i < 33; i++) emit(&b, (char)(50 + i));
  int sum = 0;
  for (char *p = b.start; p < b.pc; p++) sum += *p;
  for (int *p = b.words; p < b.wp; p++) sum += *p;
  printf("sum %d\n", sum);
  return 0;
}
