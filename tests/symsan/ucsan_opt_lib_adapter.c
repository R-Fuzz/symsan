// RUN: rm -rf %t.d && mkdir -p %t.d
// RUN: clang-18 -O0 -c -emit-llvm -o %t.d/a.bc %s
// RUN: echo "{entry: cal, scope: [cal]}" > %t.d/m.yaml
// RUN: echo "fun:lib=uninstrumented" > %t.d/lib.abilist
// RUN: %ucsan-opt -c -t -m %t.d/m.yaml --ucsan-abilist=%t.d/lib.abilist -o %t.d/a.ucsan %t.d/a.bc
// RUN: FileCheck %s < %t.d/a.bc-m.ucsan.s

// A body ucsan_opt's UCSanPass leaves to TaintPass ("ucsan-lib": lib, which
// the UCSan abilist lists uninstrumented) calls UCSan's custom functions
// through their __dfsl_ adapters, as ko-clang's does.  ucsan_opt did not pass
// TaintPass UCSan's abilist, so lib called the __dfsw_ wrapper, whose 16-bit
// result label left the high half of the 32-bit slot as it was: in v8's
// AllocateAtLeast, a garbage label that crashed __taint_union.
#include <malloc.h>
#include <stdlib.h>

// CHECK-LABEL: define {{.*}} @lib.taint(
// CHECK-NOT: @__dfsw_malloc_usable_size(
// CHECK: call {{.*}} @__dfsl_malloc_usable_size(
// CHECK-LABEL: define
__attribute__((noinline)) size_t lib(void *p) { return malloc_usable_size(p); }

int cal(int n) {
  void *p = malloc(n);
  return lib(p) > 24;
}

int main(void) { return cal(24); }
