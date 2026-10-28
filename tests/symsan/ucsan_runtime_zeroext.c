// RUN: printf 'entry: f\nscope:\n  - f\n' > %t.yaml
// RUN: env KO_USE_UCSAN_ONLY=1 METADATA=%t.yaml %ko-clang -S -emit-llvm -o - %s | FileCheck %s

// UCSan's runtime takes its labels as uint16_t and its flags as bool/uint8_t,
// and clang compiles it assuming the caller zero-extended them
// (ucsan_combine_label compares its first label with `cmp $0xffff, %edi`).
// Without zeroext on UCSanPass's declarations, a label could arrive with junk
// high bits (0xaeffff in a v8 replay) and an uninitialized one be missed.

// CHECK-DAG: declare ptr @ucsan_check_pointer(ptr, i16 zeroext, i64, i1 zeroext, i32, i32)
// CHECK-DAG: declare zeroext i16 @ucsan_combine_label(i16 zeroext, i16 zeroext)
// CHECK-DAG: declare zeroext i16 @ucsan_load_pointer_shadow(ptr, i64, i1 zeroext, ptr, i64)
// CHECK-DAG: declare void @ucsan_store_pointer_shadow(i16 zeroext, ptr, i64)
// CHECK-DAG: declare ptr @ucsan_set_label_for_args(i32, i32, i8 zeroext, i64)
int f(int *p, int b) {
  *p += b;
  return *p;
}
