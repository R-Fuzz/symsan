// RUN: %ko-clang++ -DTU_INSTRUMENTED -c %s -o %t.inst.o
// RUN: clang++ -c %s -DTU_UNINSTRUMENTED -o %t.unin.o
// RUN: %ko-clang++ -DTU_MAIN -c %s -o %t.main.o
// RUN: %ko-clang++ %t.unin.o %t.inst.o %t.main.o -o %t.exe
// RUN: llvm-nm --defined-only %t.exe | FileCheck --check-prefix=CHECK-SYMS %s
// RUN: %t.exe | FileCheck %s

// A link test, not a solving test: an instrumented C++ object has to link
// against an uninstrumented one that includes the same headers.
//
// TaintPass gives every instrumented definition a '.taint' suffix, but the
// COMDAT group the definition sits in is signed with the *original* mangled
// name.  An uninstrumented translation unit that includes the same header
// emits a group with that very same signature, and a linker keeps only the
// first group it sees for a signature -- silently dropping the other one and
// the '.taint' definition inside it.  References to it then resolve as
// undefined weaks, i.e. address 0, and since taint.ld links at a fixed
// 0x700000200000 base with these symbols hidden (so no PLT can absorb them)
// the link dies with
//   relocation truncated to fit: R_X86_64_PLT32 against undefined symbol
//     `sym_inl(int) [clone .taint]'
// (or "relocation ... out of range" under lld).  --whole-archive is no help:
// it forces the archive member in, but the group inside is still discarded.
//
// This is not a corner case -- it is every C++ target whose link line carries
// an uninstrumented object built against libc++, which is how the two-stage
// AFL++/SymSan pipeline and the libc++ archives themselves are put together.
// The failure showed up on libtiff's tiff_read_rgba_fuzzer as an unresolved
// std::__1::basic_string<...>::__throw_length_error[abi:ne180100]().
//
// Uninstrumented order matters: %t.unin.o goes first on the link line so its
// groups are the ones the linker sees first, which is the failing direction.
// Note also that TU_UNINSTRUMENTED must stay free of anything needing an
// out-of-line libc++/libc++abi symbol (no new/delete, no throw, no function
// -local statics), because only '.taint' copies of those are linked in.

#include <stdio.h>

#pragma GCC visibility push(hidden)

// A plain inline function: clang emits it in a group signed with its own name,
// which is the shape libc++'s _LIBCPP_HIDE_FROM_ABI internals take.
__attribute__((noinline)) inline int sym_inl(int x) { return x * 3 + 1; }

// A virtual base forces clang to emit both the complete (C1) and the base (C2)
// constructor, and it puts the pair in one group signed 'C5' -- a name that
// matches neither member.  So re-signing only groups named after their own
// member is not enough; the whole group has to move once every member of it
// was suffixed.
struct VBase {
  int a;
  __attribute__((noinline)) VBase() : a(1) {}
};
struct Derived : virtual VBase {
  int b;
  __attribute__((noinline)) Derived() : b(2) {}
  __attribute__((noinline)) ~Derived() {}
};
__attribute__((noinline)) inline int use_derived() {
  Derived d;
  return d.a + d.b;
}

#pragma GCC visibility pop

#if defined(TU_INSTRUMENTED)
int from_instrumented(int x) { return sym_inl(x) + use_derived(); }

#elif defined(TU_UNINSTRUMENTED)
// Never called -- it is here only so this object contributes the colliding
// COMDAT groups, the same way a real uninstrumented harness object does.
int from_uninstrumented(int x) { return sym_inl(x) + use_derived() + 100; }

#elif defined(TU_MAIN)
int from_instrumented(int);
int main() {
  // sym_inl(2) == 7, use_derived() == 3
  // CHECK: from_instrumented=10
  printf("from_instrumented=%d\n", from_instrumented(2));
  return 0;
}
#else
#error "one of TU_INSTRUMENTED / TU_UNINSTRUMENTED / TU_MAIN must be defined"
#endif

// The instrumented definitions are still *defined* in the image rather than
// having gone away with their discarded group.  (Their uninstrumented twins
// are not checked for: nothing calls from_uninstrumented, so --gc-sections
// reclaims them once the link itself has succeeded.)
// CHECK-SYMS-DAG: _Z7sym_inli.taint
// CHECK-SYMS-DAG: _Z11use_derivedv.taint
// CHECK-SYMS-DAG: _ZN7DerivedC1Ev.taint
