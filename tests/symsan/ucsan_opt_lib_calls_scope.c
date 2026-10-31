// RUN: rm -rf %t.d && mkdir -p %t.d
// RUN: clang-18 -O0 -c -emit-llvm -o %t.d/a.bc %s
// RUN: echo "{entry: cal, scope: [cal, use]}" > %t.d/m.yaml
// RUN: echo "fun:lib=uninstrumented" > %t.d/lib.abilist
// RUN: %ucsan-opt -c -t -m %t.d/m.yaml --ucsan-abilist=%t.d/lib.abilist -o %t.d/a.ucsan %t.d/a.bc
// RUN: FileCheck %s < %t.d/a.bc-m.ucsan.s

// Library code ("ucsan-lib": lib, listed uninstrumented) that calls in-scope
// code (use) passes it concrete values: it zeroes their labels in UCSan's
// argument TLS first.  It wrote nothing there, so use() read s's label as
// cal's call had left it, the object behind "ax", and lib's buf, at another
// address, was out of its bounds: v8 UTs whose out-of-scope callees run as
// library code got an OOB in std::string's in-scope methods on the first
// seed (gtest's death tests, CallOnce's std::function).
#include <string.h>

__attribute__((noinline)) int use(const char *s, int n) {
  return s[n - 1] == 'x';
}

// CHECK-LABEL: define {{.*}} @lib.taint(
// CHECK: store i16 0, ptr @__ucsan_arg_tls, {{.*}}!nosanitize
// CHECK-NEXT: store i16 0, ptr inttoptr (i64 add (i64 ptrtoint (ptr @__ucsan_arg_tls to i64), i64 2) to ptr), {{.*}}!nosanitize
// CHECK: call {{.*}} @use.taint(
// CHECK-LABEL: define
__attribute__((noinline)) int lib(int n) {
  char buf[8];
  memset(buf, 'x', sizeof(buf));
  return use(buf, n & 7 ? n & 7 : 8);
}

int cal(const char *s, int n) {
  if (use(s, n))
    return lib(n);
  return 0;
}

int main(void) { return cal("ax", 2); }
