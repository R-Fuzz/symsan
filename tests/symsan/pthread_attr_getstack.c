// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00')" > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -o %t.fg %s -lpthread
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1" %t.fg %t.bin | FileCheck %s

// pthread_getattr_np and pthread_attr_getstack write through their pointers
// in libc.  As discard (getstack) or unlisted (getattr_np) they left the
// shadow of what they wrote as it was: under trace_bounds a stack variable's
// is kInitializingLabel, and the branch on base -- v8's
// Stack::ObtainCurrentThreadStackStart -- Die()d (exit_on_memerror).
// CHECK: stack
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>

int main(int argc, char **argv) {
  pthread_attr_t attr;
  if (pthread_getattr_np(pthread_self(), &attr))
    return 1;
  void *base;
  size_t size;
  size_t guard;
  if (pthread_attr_getstack(&attr, &base, &size) ||
      pthread_attr_getguardsize(&attr, &guard))
    return 1;
  pthread_attr_destroy(&attr);
  char *top = (char *)base + size;
  if ((char *)&attr > (char *)base && (char *)&attr < top && guard < size)
    printf("stack\n");
  return 0;
}
