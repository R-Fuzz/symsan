// A pointer compared against NULL *after* its buffer was freed.
//
// __taint_union filters comparisons over a bounds label -- `ptr1 op ptr2` has
// nothing to solve, and the label carries an allocation extent in op1/op2 rather
// than an expression, so building an ICmp over it would produce a node no parser
// can serialize.  free() does not make a new label for the freed region: it
// rewrites the existing one's op from Alloca to Free in place, so that the
// address is not reused and a later access is still reportable as a
// use-after-free.  The filter used to test for Alloca only, so it stopped firing
// the moment a buffer was freed and the unserializable node got built after all.
//
// Found on the 811-seed libpng corpus, where it was exactly one parse failure
// per seed, all of them png_free_jmpbuf's `if (jb != NULL && ...)` -- a compare
// that is *in* the free path and so always sees the rewritten op.
//
// The pointer has to be stored and reloaded, as libpng reads it back out of
// png_ptr->jmp_buf_ptr: a pointer kept in an SSA value never has a shadow for
// the compare to pick a label up from, and the bug does not show.
//
// What is checked is that the whole trace parses -- parse-only mode reports
// failed=0 -- while the one genuinely symbolic branch still solves.  Counting
// output files would not catch it: the freed compare was never solvable, so its
// rejection costs no input, only a real branch's worth of nested constraints and
// a misleading entry in the failure histogram.
//
// RUN: python -c'print("A"*8)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O0 -o %t.fg %s
//
// the trace parses clean: no bounds label reaches the parser
// RUN: env SYMSAN_PARSE_ONLY=1 %fgtest %t.fg %t.bin | FileCheck --check-prefix=CHECK-PARSE %s
//
// and the real branch is still solved
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

struct holder { char *p; };
static struct holder h;

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[8];
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  h.p = (char *)malloc(64);
  memcpy(h.p, buf, sizeof(buf));

  // still Alloca here: filtered, and no condition is even traced
  if (h.p != NULL)
    printf("live nonnull\n");

  free(h.p);

  // now Free, same label, same bounds -- this is the png_free_jmpbuf shape
  if (h.p != NULL)
    printf("freed nonnull\n");

  if (buf[0] == 'Z')
    printf("solvable\n");

  // CHECK-ORIG: live nonnull
  // CHECK-ORIG: freed nonnull
  printf("Done\n");
  return 0;
}

// the two pointer compares contribute no condition at all, so the trace holds
// exactly one, and nothing in it is rejected
// CHECK-PARSE: PARSE-SUMMARY conds=1 ok=1 empty=0 failed=0
// CHECK-SOL: solvable
