// RUN: env KO_USE_FASTGEN=1 KO_UCSAN_LIB=1 %ko-clang -S -emit-llvm -o - %s | FileCheck %s

// The *64 twins of UCSan's simulated opens.  Under UCSan the combined runtime
// had no __dfsw_open64 or __dfsw_openat64 at all (dfsan_custom.cpp's are
// !USE_UCSAN_CUSTOM) and no __dfsl_ adapter for any of the three, so library
// code calling them failed to link (v8's absl and partition_alloc: open64).
// They take the same adapters as open, openat and fopen.
#define _LARGEFILE64_SOURCE
#include <fcntl.h>
#include <stdio.h>

// CHECK-NOT: @__dfsw_open64(
// CHECK: call {{.*}} @__dfsl_open64(
// CHECK: call {{.*}} @__dfsl_openat64(
// CHECK: call {{.*}} @__dfsl_fopen64(
int f(const char *path, FILE **fp) {
  int fd = open64(path, O_RDONLY);
  int fd2 = openat64(fd, path, O_RDONLY);
  *fp = fopen64(path, "r");
  return fd + fd2;
}
