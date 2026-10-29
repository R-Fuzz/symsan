// A vector llvm.bswap -- here the loop vectorizer's <4 x i32>, in v8 its SIMD
// byte reversal -- must not crash TaintPass.  Its bswap decomposition asked
// the operand for getIntegerBitWidth(), a cast<IntegerType>, and opt
// segfaulted; a vector now falls through and drops the shadow, as the unary
// bit ops (bitreverse, ctpop, ...) already did.
//
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O2 -o %t.fg %s
// RUN: %t.fg | FileCheck %s
// CHECK: 04030201 08070605

#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) void swap_all(uint32_t *__restrict d,
                                        const uint32_t *__restrict s) {
  for (int i = 0; i < 8; ++i)
    d[i] = __builtin_bswap32(s[i]);
}

int main(void) {
  uint32_t s[8] = {0x01020304, 0x05060708}, d[8];
  swap_all(d, s);
  printf("%08x %08x\n", d[0], d[1]);
  return 0;
}
