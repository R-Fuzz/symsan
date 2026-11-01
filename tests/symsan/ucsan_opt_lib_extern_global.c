// RUN: rm -rf %t.d && mkdir -p %t.d
// RUN: clang-18 -O0 -c -emit-llvm -o %t.d/a.bc %s
// RUN: echo "{entry: cal, scope: [cal]}" > %t.d/m.yaml
// RUN: echo "fun:lib=uninstrumented" > %t.d/lib.abilist
// RUN: %ucsan-opt -c -t -m %t.d/m.yaml --ucsan-abilist=%t.d/lib.abilist -o %t.d/a.ucsan %t.d/a.bc
// RUN: FileCheck %s < %t.d/a.bc-m.ucsan.s

// A global the module only declares gets a weak zero definition, for
// in-scope code to read (environ here); one library code ("ucsan-lib": lib,
// listed uninstrumented) reads stays a declaration, the shared library's.
// The executable's weak definition took the place of libc's stdout: v8's
// PrintF, library code under a UT, passed vfprintf a null FILE.
#include <stdio.h>

extern char **environ;

// CHECK-DAG: @stdout = external global ptr
// CHECK-DAG: @environ = weak global ptr null
__attribute__((noinline)) int lib(const char *s) {
  return fputs(s, stdout);
}

int cal(const char *s) {
  return (environ != 0) + lib(s);
}

int main(void) { return cal("x\n") < 0; }
