#pragma once

#include <stdint.h>
#include <assert.h>
#include <vector>
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

    // Last
    LastOp
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

  static inline bool isRelationalKind(uint16_t kind) {
    if (kind >= Equal && kind <= Sge)
      return true;
    else
      return false;
  }

  static inline bool isBinaryOperation(uint16_t kind) {
    if (kind >= Add && kind <= AShr && kind != Neg && kind != Not)
      return true;
    else
      return false;
  }

  static inline uint16_t negate_cmp(uint16_t kind) {
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

  static inline bool isSignedCmp(uint16_t kind) {
    if (kind >= Slt && kind <= Sge)
      return true;
    else
      return false;
  }

  class AstNode {
  public:
    AstNode(size_t size=32) : child0_(0), child1_(0), kind_(0), bits_(0), index_(0),
      boolvalue_(0), is_root_(1), label_(0), hash_(0) {
      root_ = new std::vector<AstNode>(); // only allocate if is root
      root_->reserve(size + 1); // default capacity, +1 for dummy root
      root_->emplace_back(AstNode(root_)); // add a dummy root
    }
    AstNode(std::vector<AstNode> *r) : root_(r), child0_(0), child1_(0),
      kind_(0), bits_(0), index_(0), boolvalue_(0), is_root_(0), label_(0),
      hash_(0) {} // don't allocate if not root
    ~AstNode() { if (is_root_) delete root_; }

    inline void CopyFrom(const AstNode& other) {
      if (this->root_ == other.root_) {
        // don't change is_root_ flag
        child0_ = other.child0_;
        child1_ = other.child1_;
        kind_ = other.kind_;
        bits_ = other.bits_;
        index_ = other.index_;
        boolvalue_ = other.boolvalue_;
        label_ = other.label_;
        hash_ = other.hash_;
      } else {
        RecursiveCopyFrom(other);
      }
    }

    inline uint32_t children_size() const {
      return (!!child0_) + (!!child1_);
    }

    inline const AstNode& children(uint32_t i) const {
      assert(i < 2);
      return i == 0 ? root_->at(child0_) : root_->at(child1_);
    }

    inline AstNode* mutable_children(uint32_t i) {
      assert(i < 2);
      return i == 0 ? &root_->at(child0_) : &root_->at(child1_);
    }

    AstNode* add_children() {
      size_t size = root_->size();
      assert(size < root_->capacity() && "cannot resize");
      if (child0_ == 0) child0_ = size;
      else if (child1_ == 0) child1_ = size;
      else assert(false && "too many children");
      root_->emplace_back(AstNode(root_));
      return &root_->back();
    }

    inline void clear_children() { child0_ = child1_ = 0; }
    inline void clear_children(uint32_t i) {
      assert(i < 2);
      if (i == 1) child1_ = 0;
      else child0_ = child1_; // pop child1 to child0
    }

    inline uint16_t kind() const { return kind_; }
    inline void set_kind(uint16_t kind) { kind_ = kind; }
    inline uint16_t bits() const { return bits_; }
    inline void set_bits(uint16_t bits) { bits_ = bits; }
    inline uint32_t index() const { return index_; }
    inline void set_index(uint32_t index) { index_ = index; }
    inline uint8_t boolvalue() const { return boolvalue_; }
    inline void set_boolvalue(uint8_t value) { boolvalue_ = value ? 0 : 1; }
    inline uint32_t label() const { return label_; }
    inline void set_label(uint32_t label) { label_ = label; }
    inline uint32_t hash() const { return hash_; }
    inline void set_hash(uint32_t hash) { hash_ = hash; }
  private:
    std::vector<AstNode> *root_; // root of the AST
    uint32_t child0_;
    uint32_t child1_;
    uint16_t kind_;
    uint16_t bits_;
    uint32_t index_ : 30;  //used by read expr for index and extract expr
    uint8_t boolvalue_ : 1;  //used by bool expr
    uint8_t is_root_ : 1; // true if this is the root of the AST
    uint32_t label_;  //for expression dedup
    uint32_t hash_;  //for node dedup

    void RecursiveCopyFrom(const AstNode &other) {
      // copy children
      if (other.child0_) {
        if (this->child0_ == 0) {
          child0_ = root_->size();
          root_->emplace_back(AstNode(root_));
        }
        root_->at(child0_).RecursiveCopyFrom(other.children(0));
      } else {
        child0_ = 0;
      }
      if (other.child1_) {
        if (this->child1_ == 0) {
          child1_ = root_->size();
          root_->emplace_back(AstNode(root_));
        }
        root_->at(child1_).RecursiveCopyFrom(other.children(1));
      } else {
        child1_ = 0;
      }
      // copy other fields
      kind_ = other.kind_;
      bits_ = other.bits_;
      index_ = other.index_;
      boolvalue_ = other.boolvalue_;
      label_ = other.label_;
      hash_ = other.hash_;
    }
  };

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
