// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 KO_UCSAN_LIB=1 %ko-clang -O0 -S -emit-llvm -o - %s | FileCheck %s

// A bitfield assignment in library code built for UCSan (KO_UCSAN_LIB) is
// still a read-modify-write store (Bitfield.h): the __ucsan_lib_store call
// before each store only updates UCSan's shadow, and taken as a write between
// the load and the store it made the store a plain one, the uninitialized
// label of the stack byte copied onto the bits just written.  libc++'s short
// string sets its size and is_long bits this way, so every std::string built
// in library code (gtest's test registration) failed its first size() test
// with a UBI.  (KO_DONT_OPTIMIZE: at -O3 the two stores fold into one.)
struct small { unsigned char size : 7, is_long : 1; };

// CHECK-LABEL: define {{.*}}@init
// CHECK: call void @__ucsan_lib_store(
// CHECK: call void @__taint_store_rmw(
// CHECK: call void @__ucsan_lib_store(
// CHECK: call void @__taint_store_rmw(
// CHECK: ret void
void init(struct small *s) {
  s->size = 0;
  s->is_long = 0;
}
