// A 128-bit comparison against a 128-bit CONSTANT: the __dfsan::WideConst leaf.
//
// op1 and op2 in dfsan_label_info are 64 bits each, which together is exactly
// what a concrete 128-bit operand needs, so a wide constant is carried as a
// leaf label of its own -- (l1 = 0, l2 = 0, op = WideConst, size = 128,
// op1 = lo64, op2 = hi64) -- rather than through a side channel the way memcmp
// and the lookup tables are.  union_util's operator== compares both fields, so
// dedup is exact: one union-table entry per distinct constant for the life of
// the trace, no pipe message, no parser cache, no per-trace state.
//
// The constant is asymmetric ON PURPOSE.  Two halves swapped is the natural bug
// on both sides of the hop -- rgd-parser pushes two consecutive input_args
// slots and z3-solver.cpp reassembles them with z3::concat, and either could
// order them wrong -- and a swapped constant is not a decline, it is a wrong
// formula that z3 will confidently model.  With a palindromic constant the
// swap is invisible.  What is checked is therefore the REPLAY: only bytes that
// really equal k print GoodK.
//
// jigsaw declines, for the reason in uint128_t.c: the comparison itself is 128
// bits and get_distance is uint64, so truncating it would be a false SAT.
//
// i2s SOLVES it, and gets to for free rather than by learning anything about
// 128 bits.  solve_memcmp_ast is a byte-pattern matcher that never reads the
// traced op1/op2 value at all -- it assembles the wanted bytes out of
// consecutive input_args slots, which is precisely the multi-slot form a
// WideConst lands in.  So the wide-equality route is a routing change (send
// Equal to solve_memcmp_ast instead of declining) and not a width change.  What
// stays declined is a wide NON-equality, where get_i2s_value has to turn the
// relation into a wanted value and that function is uint64.
//
// Do NOT add -O to the instrumented RUN lines.  Promoting the constant happens
// in the runtime (__taint_get_wide), and the reason it has to is visible only
// at -O0: clang keeps a literal __int128 in an alloca, so this compare arrives
// as `icmp eq i128 %a, %b` with two loads and no ConstantInt anywhere.  A
// compile-time promotion keyed on isa<ConstantInt> would fire only once an
// optimizer had folded the load away, i.e. never in a debug or fuzzing build --
// exactly backwards.  Optimize this test and it silently stops covering that.
//
// RUN: python -c'print("A"*16)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_Z3=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s
//
// jigsaw on its own declines the 128-bit comparison
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_JIGSAW=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out | FileCheck --check-prefix=CHECK-NOSOL --allow-empty %s
//
// the default ladder is i2s -> jigsaw, and i2s takes it through the byte-pattern
// path; replay rather than the mere existence of an output is what is checked,
// since a lo/hi swap would also produce a file
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  __uint128_t a;
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(&a, 1, sizeof(a), fp);
  fclose(fp);

  // neither half is a repeat of the other, and neither is a palindrome
  __uint128_t k = ((__uint128_t)0x0123456789abcdefULL << 64) |
                  (__uint128_t)0xfedcba9876543210ULL;

  if (a == k) {
    // CHECK-SOL: GoodK
    printf("GoodK\n");
  }

  // unconditional, so the seed run has something to match and no extra
  // symbolic branch is introduced
  // CHECK-ORIG: Done
  printf("Done\n");
  return 0;
}

// CHECK-NOSOL-NOT: id-
