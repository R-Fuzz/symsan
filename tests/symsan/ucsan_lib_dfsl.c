// RUN: env KO_USE_FASTGEN=1 KO_UCSAN_LIB=1 %ko-clang -S -emit-llvm -o - %s | FileCheck %s --check-prefix=LIB
// RUN: env KO_USE_FASTGEN=1 %ko-clang -S -emit-llvm -o - %s | FileCheck %s --check-prefix=PLAIN

// Library code built to be linked under UCSan (KO_UCSAN_LIB, TaintPass
// -taint-ucsan-lib: libc++-ucsan.a) calls a function UCSan's abilist lists
// `custom` through its __dfsl_ adapter, not its __dfsw_ wrapper: under UCSan
// the runtime's __dfsw_malloc is ucsan_custom.cpp's, which takes UCSan's
// 16-bit labels, and libc++'s operator new got a 16-bit label in the low half
// of its 32-bit one (0xffff000b, v8's Ostream.AsHexBytes), a segfault in
// __taint_union.  A function UCSan does not list (strlen) keeps __dfsw_, and
// without KO_UCSAN_LIB malloc does too.
#include <stdlib.h>
#include <string.h>

// LIB-NOT: @__dfsw_malloc(
// LIB: call {{.*}} @__dfsw_strlen(
// LIB: call {{.*}} @__dfsl_malloc(
// LIB: call void @__dfsl_free(
// PLAIN: call {{.*}} @__dfsw_malloc(
// PLAIN: call void @__dfsw_free(
char *f(const char *s, char *old) {
  char *p = malloc(strlen(s) + 1);
  free(old);
  return p;
}
