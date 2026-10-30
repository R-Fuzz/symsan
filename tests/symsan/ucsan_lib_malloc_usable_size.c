// RUN: env KO_USE_FASTGEN=1 KO_UCSAN_LIB=1 %ko-clang -S -emit-llvm -o - %s | FileCheck %s

// malloc_usable_size is UCSan-custom: library code asks UCSan's wrapper,
// through its adapter, about the objects UCSan's malloc gave it.  Called as
// uninstrumented it reached the program's own (v8's PartitionAlloc shim),
// which did not know them.
#include <malloc.h>

// CHECK: call {{.*}} @__dfsl_malloc_usable_size(
size_t f(void *p) { return malloc_usable_size(p); }
