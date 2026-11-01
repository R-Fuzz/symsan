// RUN: rm -rf %t.d && mkdir -p %t.d
// RUN: clang++-18 -O0 -fexceptions -c -emit-llvm -o %t.d/a.bc %s
// RUN: echo "{entry: cal, scope: [cal]}" > %t.d/m.yaml
// RUN: %ucsan-opt -c -i -t --libcxx -m %t.d/m.yaml -o %t.d/a.ucsan %t.d/a.bc
// RUN: FileCheck %s < %t.d/a.bc-m.ucsan.s

// An indirect call UCSan checks before making (the pointer may be null or
// made up) is made on one side of a branch and stubbed on the other.  An
// invoke ends its block: it was replaced by a call, the merge block lost its
// terminator, and the module was broken -- TaintPass crashed on libc++'s
// -fexceptions __put_character_sequence (v8's torque), which calls a facet's
// virtual widen in a try block.  The call made is an invoke now, unwinding
// where the original did, and the merge block goes on to its normal path.

// CHECK-LABEL: define {{.*}} @cal.taint(
// CHECK: invoke {{.*}} %{{[0-9]+}}(
// CHECK-NEXT: to label %[[MERGE:[0-9]+]] unwind label %[[LPAD:[0-9]+]]
// CHECK: [[MERGE]]:
// CHECK-NEXT: phi i32
// CHECK: [[LPAD]]:
// CHECK-NEXT: landingpad
struct B {
  virtual int f(int) = 0;
};

extern "C" int cal(B *b) {
  try {
    return b->f(1);
  } catch (...) {
    return -1;
  }
}

struct D : B {
  int f(int x) override { return x; }
};

int main() {
  D d;
  return cal(&d) != 1;
}
