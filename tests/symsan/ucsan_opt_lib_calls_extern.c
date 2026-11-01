// RUN: rm -rf %t.d && mkdir -p %t.d
// RUN: clang-18 -O0 -c -emit-llvm -o %t.d/a.bc %s
// RUN: echo "{entry: cal, scope: [cal]}" > %t.d/m.yaml
// RUN: echo "fun:lib=uninstrumented" > %t.d/lib.abilist
// RUN: %ucsan-opt -c -t -m %t.d/m.yaml --ucsan-abilist=%t.d/lib.abilist -o %t.d/a.ucsan %t.d/a.bc
// RUN: FileCheck %s < %t.d/a.bc-m.ucsan.s

// Library code ("ucsan-lib": lib, listed uninstrumented) calls an external
// function UCSan does not model (pthread_create, sysconf: in SymSan's abilist
// only) as SymSan alone would, the function itself or its wrapper; in-scope
// code (cal) calls UCSan's out-of-scope stub.  Every use went to the stub,
// which writes none of the callee's effects: v8's Thread::Start, library code
// under a UT, found pthread_create's thread unset, and its CHECK aborted.
#include <pthread.h>
#include <unistd.h>

// CHECK-LABEL: define {{.*}} @lib.taint(
// CHECK: call {{.*}} @__dfsw_pthread_create(
// CHECK: call {{.*}} @sysconf(
// CHECK-LABEL: define {{.*}} @cal.taint(
// CHECK: call {{.*}} @"__external$sysconf"(
static void *run(void *p) { return p; }

__attribute__((noinline)) long lib(void) {
  pthread_t t;
  if (pthread_create(&t, 0, run, 0))
    return -1;
  pthread_join(t, 0);
  return sysconf(_SC_PAGESIZE);
}

long cal(void) {
  return sysconf(_SC_NPROCESSORS_ONLN) + lib();
}

int main(void) { return cal() < 0; }
