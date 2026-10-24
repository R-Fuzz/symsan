// RUN: env KO_USE_FASTGEN=1 %ko-clang -O2 -S -emit-llvm -o - %s | FileCheck %s

// A bool load's value is made the bool it stands for before TaintPass
// instruments it.  Codegen trusts a load marked !range [0, 2) (clang's _Bool),
// and an i1 load (a bool global GlobalOpt shrank), to hold 0 or 1 and uses the
// byte itself.  An input byte can hold anything -- UCSan fills globals,
// resigned locals and lazily initialized objects from seed bytes -- and the
// target then branched on the whole byte while SymSan evaluated the frontend's
// trunc of it: the kernel eval recorded such conditions as 0xff (and 0xaf,
// 0x5c, ...) against a recomputed 1 or 0, value mismatches.  The load becomes
// zext(byte != 0) without its range, an i1 load an i8 load and `!= 0`.
// (Only codegen of an unoptimized module shows the byte; at -O2 the value
// arrives normalized, so this checks the transformation, not a solve.)

#include <stdbool.h>

struct rec {
  int x;
  bool flag;
};

// CHECK-LABEL: define {{.*}} @flag_of.taint(
// CHECK: [[B:%[0-9]+]] = load i8, ptr {{%[0-9]+}}, align 4
// CHECK-NOT: !range
// CHECK-SAME: {{$}}
// CHECK: icmp ne i8 [[B]], 0
__attribute__((noinline)) int flag_of(const struct rec *r) {
  return r->flag ? 7 : 3;
}

static bool seen;

__attribute__((noinline)) void mark(void) { seen = true; }

// CHECK-LABEL: define {{.*}} @was_seen.taint(
// CHECK-NOT: load i1
// CHECK: [[S:%[0-9]+]] = load i8, ptr @seen
// CHECK: icmp ne i8 [[S]], 0
__attribute__((noinline)) int was_seen(void) { return seen ? 11 : 5; }
