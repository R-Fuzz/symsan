// RUN: env KO_USE_FASTGEN=1 KO_DONT_OPTIMIZE=1 %ko-clang -O0 -S -emit-llvm -o - %s | FileCheck --check-prefix=TAINT %s
// RUN: rm -rf %t.d && mkdir -p %t.d
// RUN: clang-18 -O0 -c -emit-llvm -o %t.d/a.bc %s
// RUN: echo "{entry: cal, scope: [cal, widen]}" > %t.d/m.yaml
// RUN: echo "fun:widen_lib=uninstrumented" > %t.d/lib.abilist
// RUN: %ucsan-opt -c -t -m %t.d/m.yaml --ucsan-abilist=%t.d/lib.abilist -o %t.d/a.ucsan %t.d/a.bc
// RUN: FileCheck --check-prefix=UCSAN %s < %t.d/a.bc-m.ucsan.s

// A local's shadow is kept in a shadow alloca of its own (promoted) only when
// every load and store of it is of its type's shadow.  clang returns an
// __int128 at -O0 by storing it to an i128 alloca and loading it back as
// { i64, i64 }: the promoted shadow was one label, an i32 (UCSan's an i16),
// and the { i32, i32 } loaded from it read a stack word past it that nothing
// wrote as the second word's label.  v8's DiyFp::Times, calling absl's
// uint128 operator* as library code, stored that word (0xffe10010) as a label
// and faulted in __taint_union_store.

// TAINT-LABEL: define {{.*}} @widen.taint(
// TAINT-NOT: load { i32, i32 }, ptr %
// TAINT: ret { i64, i64 }
// UCSAN-LABEL: define {{.*}} @widen.taint(
// UCSAN-NOT: load { i{{16|32}}, i{{16|32}} }, ptr %
// UCSAN: ret { i64, i64 }
// UCSAN-LABEL: define {{.*}} @widen_lib.taint(
// UCSAN-NOT: load { i{{16|32}}, i{{16|32}} }, ptr %
// UCSAN: ret { i64, i64 }

__attribute__((noinline)) unsigned __int128 widen(const unsigned char *b) {
  return ((unsigned __int128)b[1] << 64) + b[0];
}

__attribute__((noinline)) unsigned __int128 widen_lib(const unsigned char *b) {
  return ((unsigned __int128)b[0] << 64) + b[1];
}

int cal(const unsigned char *b) {
  return (unsigned long)(widen(b) >> 64) == 'z' &&
         (unsigned long)(widen_lib(b) >> 64) == 'y';
}

int main(void) {
  const unsigned char b[2] = {'y', 'z'};
  return !cal(b);
}
