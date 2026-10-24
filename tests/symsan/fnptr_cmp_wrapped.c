// A pointer to a function with a wrapper compares equal to that function.
//
// TaintPass replaces a wrapped function's address with its dfsw$ wrapper's,
// except in comparisons, so that an extern_weak function's null check is not
// folded away.  But against anything other than null the other side is a
// pointer the program stored, i.e. the wrapper, and `fp == memcpy` was false
// for fp = memcpy (the kernel's __write_relocate_add picks memcpy or
// text_poke by pointer).  Only a comparison with null keeps the original.
//
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented | FileCheck %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: %t.fg | FileCheck %s
// CHECK: same

#include <stdio.h>
#include <string.h>

void *(*volatile writer)(void *, const void *, size_t) = memcpy;

int main(void) {
  if (writer == memcpy)
    printf("same\n");
  else
    printf("different\n");
  return 0;
}
