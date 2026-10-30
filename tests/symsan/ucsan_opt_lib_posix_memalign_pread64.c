// RUN: rm -rf %t.d && mkdir -p %t.d
// RUN: clang-18 -O0 -c -emit-llvm -o %t.d/a.bc %s
// RUN: echo "{entry: cal, scope: [cal]}" > %t.d/m.yaml
// RUN: echo "fun:lib=uninstrumented" > %t.d/lib.abilist
// RUN: %ucsan-opt -c -t -m %t.d/m.yaml --ucsan-abilist=%t.d/lib.abilist -o %t.d/a.ucsan %t.d/a.bc
// RUN: FileCheck %s < %t.d/a.bc-m.ucsan.s

// Library code calls UCSan's posix_memalign and pread64 through their __dfsl_
// adapters, which the combined runtime did not have: v8 built through
// ucsan_opt (v8::base::AlignedAlloc from Isolate::New, absl's ELF reader)
// failed to link on undefined __dfsl_posix_memalign and __dfsl_pread64, as
// this test's a.ucsan did.
#define _LARGEFILE64_SOURCE
#include <stdlib.h>
#include <unistd.h>

// CHECK-LABEL: define {{.*}} @lib.taint(
// CHECK: call {{.*}} @__dfsl_posix_memalign(
// CHECK: call {{.*}} @__dfsl_pread64(
// CHECK-LABEL: define
__attribute__((noinline)) long lib(void **p, int fd, char *buf) {
  long r = posix_memalign(p, 64, 128);
  return r + pread64(fd, buf, 16, 0);
}

int cal(int n) {
  void *p;
  char buf[16];
  return lib(&p, n, buf) > 0;
}

int main(void) { return cal(0); }
