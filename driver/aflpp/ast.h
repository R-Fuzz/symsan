#pragma once

#include "rgd.pb.h"

#include <stdint.h>
#include <string>

namespace rgd {
  enum AstKind {
    Bool, // 0
    Constant, // 1
    Read, // 2
    Concat, // 3
    Extract, // 4

    ZExt, // 5
    SExt, // 6

    // Arithmetic
    Add, // 7
    Sub, // 8
    Mul, // 9
    UDiv, // 10
    SDiv, // 11
    URem, // 12
    SRem, // 13
    Neg,  // 14

    // Bit
    Not, // 15
    And, // 16
    Or, // 17
    Xor, // 18
    Shl, // 19
    LShr, // 20
    AShr, // 21

    // Compare
    Equal, // 22
    Distinct, // 23
    Ult, // 24
    Ule, // 25
    Ugt, // 26
    Uge, // 27
    Slt, // 28
    Sle, // 29
    Sgt, // 30
    Sge, // 31

    // Logical
    LOr, // 32
    LAnd, // 33
    LNot, // 34

    // Special
    Ite, // 35
    Load, // 36    to be worked with TT-Fuzzer
    Memcmp, //37
    MemcmpN, // 38
  };

  static const char* AstKindName[] = {
    "Bool",
    "Constant",
    "Read",
    "Concat",
    "Extract",
    "ZExt",
    "SExt",
    "Add",
    "Sub",
    "Mul",
    "UDiv",
    "SDiv",
    "URem",
    "SRem",
    "Neg",
    "Not",
    "And",
    "Or",
    "Xor",
    "Shl",
    "LShr",
    "AShr",
    "Equal",
    "Distinct",
    "Ult",
    "Ule",
    "Ugt",
    "Uge",
    "Slt",
    "Sle",
    "Sgt",
    "Sge",
    "LOr",
    "LAnd",
    "LNot",
    "Ite",
    "Load",
    "Memcmp",
    "MemcmpN",
  };

  static inline bool isRelationalKind(uint32_t kind) {
    if (kind >= Equal && kind <= Sge)
      return true;
    else
      return false;
  }

  static inline uint32_t negate_cmp(uint32_t kind) {
    switch (kind) {
      case Equal: return Distinct;
      case Distinct: return Equal;
      case Ult: return Uge;
      case Ule: return Ugt;
      case Ugt: return Ule;
      case Uge: return Ult;
      case Slt: return Sge;
      case Sle: return Sgt;
      case Sgt: return Sle;
      case Sge: return Slt;
      default: return Bool;
    }
  }

  static bool isEqualAstRecursive(const AstNode& lhs, const AstNode& rhs) {
    
    // number of operands and size of the operands must match
    const int children_size = lhs.children_size();
    if (children_size != rhs.children_size()) return false;
    if (lhs.bits() != rhs.bits()) return false;
    
    if (lhs.kind() != rhs.kind()) {
      // to maximize the reuse of JIT'ed functions, jigsaw does not
      // care about which relational operator is used, as long as
      // they are both relational operators
      if (isRelationalKind(lhs.kind()) && isRelationalKind(rhs.kind())) {
        // do nothing, fall through to compare operands
      } else {
        return false;
      }
    } else if (lhs.hash() != rhs.hash()) {
      // if the kind is the same, then hash has to match
      return false;
    }
    // compare each operand
    for (int i = 0; i < children_size; i++) {
      if (!isEqualAstRecursive(lhs.children(i), rhs.children(i)))
        return false;
    }
    return true;
  }

  static inline bool isEqualAst(const AstNode& lhs, const AstNode& rhs) {
    return isEqualAstRecursive(lhs, rhs);
  }

  static inline uint32_t xxhash(uint32_t h1, uint32_t h2, uint32_t h3) {
    const uint32_t PRIME32_1 = 2654435761U;
    const uint32_t PRIME32_2 = 2246822519U;
    const uint32_t PRIME32_3 = 3266489917U;
    const uint32_t PRIME32_4 =  668265263U;
    const uint32_t PRIME32_5 =  374761393U;

#define XXH_rotl32(x,r) ((x << r) | (x >> (32 - r)))
    uint32_t h32 = PRIME32_5;
    h32 += h1 * PRIME32_3;
    h32  = XXH_rotl32(h32, 17) * PRIME32_4;
    h32 += h2 * PRIME32_3;
    h32  = XXH_rotl32(h32, 17) * PRIME32_4;
    h32 += h3 * PRIME32_3;
    h32  = XXH_rotl32(h32, 17) * PRIME32_4;
 #undef XXH_rotl32

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
  }

  static inline void buf_to_hex_string(const uint8_t *buf, unsigned length,
                                       std::string &str) {
    const char hex_table[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'a', 'b', 'c', 'd', 'e', 'f' };
    
    str.clear();
    for (unsigned i = 0; i < length; ++i) {
      uint8_t val = buf[i];
      str.push_back(hex_table[val >> 4]);
      str.push_back(hex_table[val & 0xf]);
    }
  }

}; // namespace rgd
