// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s -lpthread
// RUN: not env TAINT_OPTIONS="" %t.fg 2>&1 | FileCheck %s --check-prefix=NO
// RUN: env TAINT_OPTIONS="allow_threads=1" %t.fg 2>&1 | FileCheck %s --check-prefix=YES

// Threads are not supported: the event ring has one producer, and a second
// thread's records tore it (v8's DefaultPlatform workers: garbage message
// types).  A trace ends where the thread would start, exit 127
// (REASON_THREAD), unless allow_threads.
// NO: threads are not supported
// NO-NOT: joined
// YES: joined 42
#include <pthread.h>
#include <stdio.h>

static void *work(void *arg) { return (void *)((long)arg + 1); }

int main(void) {
  pthread_t t;
  void *r;
  printf("start\n");
  fflush(stdout);
  if (pthread_create(&t, NULL, work, (void *)41L) != 0) return 1;
  pthread_join(t, &r);
  printf("joined %ld\n", (long)r);
  return 0;
}
