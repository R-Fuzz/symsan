// RUN: rm -rf %t.d && mkdir -p %t.d
// RUN: clang-18 -O0 -c -emit-llvm -o %t.d/a.bc %s
// RUN: echo "{entry: cal, scope: [cal], custom: {fatal: {ref_name: abort, arg_maps: []}}}" > %t.d/m.yaml
// RUN: echo "fun:lib=uninstrumented" > %t.d/lib.abilist
// RUN: %ucsan-opt -c -t -m %t.d/m.yaml --ucsan-abilist=%t.d/lib.abilist -o %t.d/a.ucsan %t.d/a.bc
// RUN: FileCheck %s < %t.d/a.bc-m.ucsan.s

// A body left to TaintPass ("ucsan-lib": lib, listed uninstrumented) that
// calls a function the YAML maps to a custom with no arguments (a fatal
// reporter mapped to abort: v8's V8_Dcheck under the UT harness) calls the
// custom's wrapper, as in-scope code does.  TaintPass saw only fatal's
// declaration and called fatal.taint, which nothing defines: the link failed
// as soon as an out-of-scope v8 function with a DCHECK ran as library code.
#include <stdlib.h>

__attribute__((noinline)) void fatal(const char *msg) { abort(); }

// CHECK-LABEL: define {{.*}} @lib.taint(
// CHECK-NOT: @fatal.taint(
// CHECK: call {{.*}} @__auto_dfsw_fatal(
// CHECK-LABEL: define
__attribute__((noinline)) int lib(int n) {
  if (n < 0)
    fatal("negative");
  return n + 1;
}

int cal(int n) {
  if (n > 10)
    fatal("too big");
  return lib(n);
}

int main(void) { return cal(1); }
