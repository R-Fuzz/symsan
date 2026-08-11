// Unit test for the algebraic simplifications built into __taint_union()
// (runtime/dfsan/dfsan.cpp).  It calls dfsan_union() -- the exported one-line
// wrapper around __taint_union -- on synthetic operand triples and asserts the
// label it hands back.
//
// It exists because the rest of tests/symsan cannot see these folds at all.
// Every other test observes a fold only through the inputs a solver eventually
// generates, and *disabling a correct fold is semantics-preserving*: the branch
// still gets a node, the solver still answers, the generated input is still the
// same.  Measured on the 149-test suite, deleting the Trunc(ZExt) fold,
// disabling the saturated compare, and restoring the historical `1 << 64`
// width_mask bug each changed zero test results.  That width_mask bug is the
// one that actually shipped, and this is the shape of test that catches it
// (see the ones&x @64 case below).
//
// Asserting on the label rather than on solver output is the whole point, so
// there is deliberately no solving here and no %fgtest / %t.out.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: env KO_USE_Z3=1 %ko-clang -O0 -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin | FileCheck %s
//
// ...and again with solve_ub on, where `0 << x` must stop folding: the result
// is 0 either way, but the exponent is symbolic and shifting by >= the width is
// UB, so folding it would swallow the shift-exponent check.  A second argv tells
// the test which mode it is in.
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %t.z3 %t.bin ub | FileCheck %s
//
// ...and once with debug on, which is the only way the folds' own AOUT format
// strings ever get executed.  They go to the sanitizer's internal Printf, whose
// grammar is a strict subset of C's and whose response to an unsupported
// directive is Die() -- so a bad specifier in a fold is a hard abort of the
// traced process, reachable only when someone turns debug on.  `%#lx` in the
// saturated-compare AOUT was exactly that.
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out debug=1" %t.z3 %t.bin | FileCheck %s
// CHECK: FOLD-RESULT PASS

#include <stdint.h>
#include <stdio.h>

typedef uint32_t dfsan_label;
extern dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2, uint16_t op,
                               uint16_t size, uint64_t op1, uint64_t op2);
extern dfsan_label dfsan_read_label(const void *addr, uint64_t size);
extern uint32_t dfsan_get_label_count(void);

// Opcode and predicate numbers are written out by hand here rather than
// included from runtime/dfsan/dfsan.h, on purpose.  An oracle that reads its
// expectations out of the code under test cannot see a bug in them -- the
// normalizer oracle's first version passed 3610 checks while blind for exactly
// that reason.  1-67 are LLVM 18's Instruction.def; Not is SymSan's own.
enum { Not=1, Add=13, Sub=15, Mul=17, Shl=25, LShr=26, AShr=27, And=28, Or=29,
       Xor=30, Trunc=38, ZExt=39, ICmp=53 };
enum { bveq=32, bvneq=33, bvugt=34, bvuge=35, bvult=36, bvule=37, bvsgt=38,
       bvsge=39, bvslt=40, bvsle=41 };

static int fails;

static void chk(const char *what, dfsan_label got, dfsan_label want) {
  if (got != want) {
    printf("FAIL %-22s got %u, want %u\n", what, got, want);
    fails++;
  }
}

// For the folds whose correct answer is "build a node": naming the label it
// must *not* be is all the check needs, and it keeps the test independent of
// how many labels earlier cases happened to allocate.
static void chk_ne(const char *what, dfsan_label got, dfsan_label bad) {
  if (got == bad) {
    printf("FAIL %-22s got %u, must differ\n", what, got);
    fails++;
  }
}

int main(int argc, char **argv) {
  unsigned char buf[20];
  if (argc < 2) return 2;
  int solve_ub = argc > 2;  // set by the second RUN line, which turns it on
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) return 2;
  size_t n = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  if (n != sizeof(buf)) return 2;

  dfsan_label x = dfsan_read_label(&buf[0], 1);  // an 8-bit leaf
  dfsan_label y = dfsan_read_label(&buf[1], 1);  // a *different* 8-bit leaf
  dfsan_label q = dfsan_read_label(&buf[0], 8);  // a 64-bit node
  if (!x || !y || !q) {
    printf("FAIL no input label (x=%u y=%u q=%u)\n", x, y, q);
    return 2;
  }

  uint32_t before = dfsan_get_label_count();

  // both operands concrete -> no shadow at all
  chk("concrete+concrete", dfsan_union(0, 0, Add, 8, 3, 4), 0);

  // the qsym identities, constant on the left
  chk("0|x",       dfsan_union(0, x, Or,   8, 0, 0), x);
  chk("0^x",       dfsan_union(0, x, Xor,  8, 0, 0), x);
  chk("0+x",       dfsan_union(0, x, Add,  8, 0, 0), x);
  chk("0&x",       dfsan_union(0, x, And,  8, 0, 0), 0);
  chk("0*x",       dfsan_union(0, x, Mul,  8, 0, 0), 0);
  // A shift of 0 folds to 0 only while there is no shift-exponent check to
  // lose.  All three shifts, and the two right ones for the same reason: the
  // exponent is symbolic and shifting by >= the width is UB whatever is being
  // shifted.
  if (solve_ub) {
    chk_ne("0<<x keeps UB",   dfsan_union(0, x, Shl,  8, 0, 0), 0);
    chk_ne("0 lshr x keeps",  dfsan_union(0, x, LShr, 8, 0, 0), 0);
    chk_ne("0 ashr x keeps",  dfsan_union(0, x, AShr, 8, 0, 0), 0);
  } else {
    chk("0<<x",      dfsan_union(0, x, Shl,  8, 0, 0), 0);
    chk("0 lshr x",  dfsan_union(0, x, LShr, 8, 0, 0), 0);
    chk("0 ashr x",  dfsan_union(0, x, AShr, 8, 0, 0), 0);
  }
  chk("ones&x",    dfsan_union(0, x, And,  8, 0xff, 0), x);
  chk("ones|x",    dfsan_union(0, x, Or,   8, 0xff, 0), 0);

  // ...and the same identity reached only through the commutative swap, which
  // is what puts a constant operand in l1 in the first place.  Nothing else in
  // this file would notice if the swap stopped swapping op1/op2 alongside the
  // labels.
  chk("x+0 (swapped)", dfsan_union(x, 0, Add, 8, 0, 0), x);
  chk("x&0 (swapped)", dfsan_union(x, 0, And, 8, 0, 0), 0);
  chk("x&ones (swap)", dfsan_union(x, 0, And, 8, 0, 0xff), x);
  chk("swap normalizes", dfsan_union(x, 0, Add, 8, 0, 5),
                         dfsan_union(0, x, Add, 8, 5, 0));

  // the non-commutative identities, constant on the right
  chk("x-0",       dfsan_union(x, 0, Sub,  8, 0, 0), x);
  chk("x<<0",      dfsan_union(x, 0, Shl,  8, 0, 0), x);
  chk("x lshr 0",  dfsan_union(x, 0, LShr, 8, 0, 0), x);
  chk("x ashr 0",  dfsan_union(x, 0, AShr, 8, 0, 0), x);

  // same label on both sides
  chk("x^x",       dfsan_union(x, x, Xor, 8, 0, 0), 0);
  chk("x-x",       dfsan_union(x, x, Sub, 8, 0, 0), 0);
  chk("x ==x",     dfsan_union(x, x, (bveq  << 8) | ICmp, 8, 0, 0), 0);
  chk("x <=u x",   dfsan_union(x, x, (bvule << 8) | ICmp, 8, 0, 0), 0);
  chk("x <u x",    dfsan_union(x, x, (bvult << 8) | ICmp, 8, 0, 0), 0);

  // The all-ones mask at 64 bits.  This is the regression test for the shipped
  // `(1 << size) - 1` bug: the shift is UB at size 64, x86 masks the count to
  // 0, 1 << 64 evaluates to 1, and every all-ones fold silently stops firing on
  // i64 -- with no visible effect on any other test in the suite.
  chk("ones&x @64", dfsan_union(0, q, And, 64, ~(uint64_t)0, 0), q);
  chk("ones|x @64", dfsan_union(0, q, Or,  64, ~(uint64_t)0, 0), 0);

  // comparisons against the extreme value of their own width
  chk("x >=u 0",    dfsan_union(x, 0, (bvuge << 8) | ICmp, 8, 0, 0),    0);
  chk("x <u 0",     dfsan_union(x, 0, (bvult << 8) | ICmp, 8, 0, 0),    0);
  chk("x <=u 0xff", dfsan_union(x, 0, (bvule << 8) | ICmp, 8, 0, 0xff), 0);
  chk("x >u 0xff",  dfsan_union(x, 0, (bvugt << 8) | ICmp, 8, 0, 0xff), 0);
  chk("x >=s -128", dfsan_union(x, 0, (bvsge << 8) | ICmp, 8, 0, 0x80), 0);
  chk("x <s -128",  dfsan_union(x, 0, (bvslt << 8) | ICmp, 8, 0, 0x80), 0);
  chk("x <=s 127",  dfsan_union(x, 0, (bvsle << 8) | ICmp, 8, 0, 0x7f), 0);
  chk("x >s 127",   dfsan_union(x, 0, (bvsgt << 8) | ICmp, 8, 0, 0x7f), 0);
  // ICmp is not commutative, so the swap above did not run and these reach the
  // fold with the constant still on the left -- the only cases that exercise
  // the predicate swap inside it.
  chk("0 <=u x",    dfsan_union(0, x, (bvule << 8) | ICmp, 8, 0, 0),    0);
  chk("0xff >=u x", dfsan_union(0, x, (bvuge << 8) | ICmp, 8, 0xff, 0), 0);
  chk("127 >=s x",  dfsan_union(0, x, (bvsge << 8) | ICmp, 8, 0x7f, 0), 0);
  chk("saturated @64", dfsan_union(q, 0, (bvule << 8) | ICmp, 64, 0,
                                   ~(uint64_t)0), 0);

  // Trunc(ZExt(x)) back to x's own width.  dfsan_custom.cpp:328 depends on this
  // one: it is what keeps `c = tolower(c)` collapsing to the 8-bit node a later
  // str*cmp has to find.
  dfsan_label z = dfsan_union(x, 0, ZExt, 32, 0, 0);
  chk_ne("zext built", z, 0);
  chk("trunc(zext(x))", dfsan_union(z, 0, Trunc, 8, 0, 0), x);
  chk_ne("trunc to other width", dfsan_union(z, 0, Trunc, 16, 0, 0), x);

  // 0b1 ^ x at one bit is rewritten to Not, so it must land on the same
  // hash-consed node a Not builds directly.
  chk("1^x -> Not", dfsan_union(0, x, Xor, 1, 1, 0),
                    dfsan_union(0, x, Not, 1, 1, 0));

  // Above 64 bits a zero label is a concrete operand whose high half was never
  // shipped, and dfsan_union has no __taint_get_wide call in front of it to
  // turn that into a WideConst -- so the shadow is dropped rather than guessed.
  chk("wide, zero label", dfsan_union(0, q, Add, 128, 5, 0), 0);

  // Negative controls.  Without these the whole file passes if __taint_union
  // starts returning 0 for everything, which would be the worst possible bug:
  // a fold that eats live branches is invisible to a solver-output test too.
  chk_ne("x <u 0x41",  dfsan_union(x, 0, (bvult << 8) | ICmp, 8, 0, 0x41), 0);
  chk_ne("0 <u x",     dfsan_union(0, x, (bvult << 8) | ICmp, 8, 0, 0),    0);
  chk_ne("x != x",     dfsan_union(x, 0, (bvneq << 8) | ICmp, 8, 0, 1),    0);
  chk_ne("x & 0x0f",   dfsan_union(0, x, And, 8, 0x0f, 0), 0);
  chk_ne("x - 1",      dfsan_union(x, 0, Sub, 8, 0, 1),    0);
  chk_ne("x + y",      dfsan_union(x, y, Add, 8, 0, 0),    0);
  chk_ne("x ^ y",      dfsan_union(x, y, Xor, 8, 0, 0),    0);
  chk_ne("x - y",      dfsan_union(x, y, Sub, 8, 0, 0),    0);
  chk_ne("x ==y",      dfsan_union(x, y, (bveq << 8) | ICmp, 8, 0, 0), 0);
  // ones&x at 64 bits must fold, but ones&x at 63 must not be *mistaken* for it
  chk_ne("0xff...&x @64 wrong mask",
         dfsan_union(0, q, And, 64, ~(uint64_t)1, 0), q);

  printf("labels created: %u\n", dfsan_get_label_count() - before);
  printf("%s (%d failures)\n", fails ? "FOLD-RESULT FAIL" : "FOLD-RESULT PASS",
         fails);
  return fails != 0;
}
