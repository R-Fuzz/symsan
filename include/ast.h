#pragma once

#include <stdint.h>
#include <stdexcept>
#include <string>
#include <vector>

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

    // Floating-point arithmetic (operands & result are IEEE-754 bit-vectors).
    // The out-of-process RGD path lifts BV children to the fpa theory in the
    // z3 solver; jigsaw JIT and i2s stay integer-only and reject these.
    FAdd, // 39
    FSub, // 40
    FMul, // 41
    FDiv, // 42
    FRem, // 43
    FNeg, // 44

    // FP casts
    FpToUi, // 45
    FpToSi, // 46
    UiToFp, // 47
    SiToFp, // 48
    FpTrunc, // 49
    FpExt, // 50

    // FP intrinsics / libcalls
    FpFabs, // 51
    FpSqrt, // 52
    FpRound, // 53   rounding-mode selector carried in AstNode index()
    FpMin, // 54
    FpMax, // 55
    FpCopysign, // 56
    FpIsNan, // 57
    FpIsInf, // 58
    FpIsFinite, // 59
    FpSignbit, // 60
    FpLrint, // 61

    // FP transcendentals (exp/log/pow family).  z3's fpa theory has no way to
    // invert these and jigsaw is integer-only, so those solvers reject them
    // (see below); the i2s solver instead computes the numeric libm inverse
    // (e.g. log for exp) and VERIFIES it, so it can flip these guards.  Kept
    // inside the [FAdd, FUne] range so isFloatingPointKind() covers them.
    FpExp, // 62
    FpExp2, // 63
    FpLog, // 64
    FpLog2, // 65
    FpLog10, // 66
    FpLog1p, // 67
    FpPow, // 68   binary: base and exponent (one is a constant for i2s)

    // FP comparisons (LLVM FCmp predicates 1..14; FALSE/TRUE are constants).
    // Kept OUTSIDE the isRelationalKind() range on purpose so that the
    // integer-only jigsaw/i2s solvers cleanly reject FP tasks (fall back to z3).
    FOeq, // 69
    FOgt, // 70
    FOge, // 71
    FOlt, // 72
    FOle, // 73
    FOne, // 74
    FOrd, // 75
    FUno, // 76
    FUeq, // 77
    FUgt, // 78
    FUge, // 79
    FUlt, // 80
    FUle, // 81
    FUne, // 82

    // Load of a read-only global lookup table at a symbolic index; the single
    // child is the index expression.  Table contents travel out of band and are
    // held by the parser, keyed on the base address.  Appended here (rather than
    // reusing the reserved Load, 36) so existing kind numbering is untouched.
    // i2s-only: jigsaw's JIT and both z3 backends reject it, see
    // solvers/z3-solver.cpp and solvers/jigsaw/jit.cc.
    TLookup, // 83

    // llvm.bitreverse: reverse the operand's bit order.  One child, same width
    // in as out.  Deliberately NOT in the isBinaryOperation range -- it is
    // unary, and the integer solvers dispatch on that.
    BitReverse, // 84

    // String theory: the dfsan ops 77-88 (dfsan.h), plus PtrToInt applied to a
    // string op.  Appended here rather than grouped next to the FP ops so that
    // no existing kind is renumbered -- the same reason TLookup and BitReverse
    // sit where they do.  The cost is that this enum no longer mirrors
    // dfsan.h's ordering, where the string ops (74-88) come *before* the FP
    // ops (89+); the gain is that no persisted hash, cached AST or
    // AstKindName[] entry shifts.
    //
    // One kind per dfsan op, rather than one kind plus a sort field, because
    // z3's string theory indexes with Int and not BV.  The sort has to be
    // recoverable from the node alone, and with distinct kinds it is --
    // see stringKindSort() below.
    //
    // Concrete content -- haystacks, needles, character sets, GEP offsets --
    // is NOT stored in the node.  It is packed into Constraint::input_args as
    // an rgd::Constant child, exactly the way fmemcmp's target is, and hashed
    // value-free.  So strstr(s, "abc") and strstr(s, "xyz") share one AST and
    // one JIT'ed function; see THE HASHING INVARIANT below.
    //
    // None of these is boolean-valued -- every one sits under an ICmp -- so
    // isRelationalKind() and the parser's root / nested-comparison handling
    // are unaffected.  Mind the polarity: StrCmp is 0-on-match, while
    // PrefixOf and SuffixOf are 1-on-match.
    StrLen,      // 85 <- fstrlen   77: opaque symbolic length over the content
    StrChr,      // 86 <- fstrchr   78: index of the first occurrence, or -1
    StrRChr,     // 87 <- fstrrchr  79: index of the last occurrence, or -1
    StrStr,      // 88 <- fstrstr   80: index of the first substring match, -1
    StrPbrk,     // 89 <- fstrpbrk  81: index of the first char from a set, -1
    StrOff,      // 90 <- fstr_off  82: a string index plus a constant offset
    SubStr,      // 91 <- fsubstr   83: slice; nested for 3-operand slices
    StrCat,      // 92 <- fstrcat   84: concatenation
    StrCmp,      // 93 <- fstrcmp   85: 0 when equal, non-zero otherwise
    PrefixOf,    // 94 <- fprefixof 86: 1 when str starts with prefix, else 0
    SuffixOf,    // 95 <- fsuffixof 87: 1 when str ends with suffix, else 0
    StrLength,   // 96 <- flength   88: sequence length of a string expression
    // PtrToInt over a string op.  Not a passthrough: the index a search op
    // returns is relative to its haystack, while a pointer difference is
    // absolute, so the haystack's offset within the input has to be added
    // (compare solvers/z3-ts.cpp's PtrToInt case).  Unlike every other payload
    // here that offset is NOT a Constant child: z3-ts.cpp reads it from its
    // string_info_cache_, which the RGD parser does not keep, and it is anyway
    // recoverable from the node -- it is the index() of the leftmost Read under
    // the haystack subtree.  A solver that needs it walks there.
    StrPtrToInt, // 97

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
    "FAdd",
    "FSub",
    "FMul",
    "FDiv",
    "FRem",
    "FNeg",
    "FpToUi",
    "FpToSi",
    "UiToFp",
    "SiToFp",
    "FpTrunc",
    "FpExt",
    "FpFabs",
    "FpSqrt",
    "FpRound",
    "FpMin",
    "FpMax",
    "FpCopysign",
    "FpIsNan",
    "FpIsInf",
    "FpIsFinite",
    "FpSignbit",
    "FpLrint",
    "FpExp",
    "FpExp2",
    "FpLog",
    "FpLog2",
    "FpLog10",
    "FpLog1p",
    "FpPow",
    "FOeq",
    "FOgt",
    "FOge",
    "FOlt",
    "FOle",
    "FOne",
    "FOrd",
    "FUno",
    "FUeq",
    "FUgt",
    "FUge",
    "FUlt",
    "FUle",
    "FUne",
    "TLookup",
    "BitReverse",
    "StrLen",
    "StrChr",
    "StrRChr",
    "StrStr",
    "StrPbrk",
    "StrOff",
    "SubStr",
    "StrCat",
    "StrCmp",
    "PrefixOf",
    "SuffixOf",
    "StrLength",
    "StrPtrToInt",
  };

  static inline bool isRelationalKind(uint16_t kind) {
    if (kind >= Equal && kind <= Sge)
      return true;
    else
      return false;
  }

  // Signed integer relational kinds (bvslt/bvsle/bvsgt/bvsge).  These are
  // distinguished from the unsigned/equality relations because the jigsaw JIT
  // SIGN-extends a signed comparison's operands to 64-bit (so gd.cc's
  // (int64_t) distance is correct), while unsigned/equality comparisons
  // ZERO-extend.  A signed and an unsigned comparison over identical operands
  // therefore compile to DIFFERENT native functions and must NOT share a
  // JIT'ed function (see isEqualAstRecursive) -- otherwise a signed constraint
  // could reuse an unsigned (zero-extending) function and report an unsound SAT.
  static inline bool isSignedRelationalKind(uint16_t kind) {
    if (kind >= Slt && kind <= Sge)
      return true;
    else
      return false;
  }

  // Floating-point relational kinds are deliberately kept out of the
  // isRelationalKind() range: the integer-only jigsaw JIT and i2s solvers
  // dispatch on isRelationalKind(), so excluding FP makes them reject FP
  // tasks and fall back to the (FP-aware) z3 solver.
  static inline bool isFPRelationalKind(uint16_t kind) {
    if (kind >= FOeq && kind <= FUne)
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

  // Any floating-point op (FP arithmetic, casts, intrinsics/libcalls, and FP
  // comparisons) lives contiguously in [FAdd, FUne].  The integer-only solvers
  // (jigsaw JIT, i2s input-to-state) cannot reason about these: input bytes
  // reaching a comparison *through* an FP op (e.g. (long)x == 42, lrint(x) == 42)
  // no longer appear literally, so copying the constant into the input produces
  // a bogus solution.  Such solvers must reject a constraint whose ops bitset
  // intersects this range and fall back to the FP-aware z3 solver.
  static inline bool isFloatingPointKind(uint16_t kind) {
    if (kind >= FAdd && kind <= FUne)
      return true;
    else
      return false;
  }

  // Every string-theory kind lives contiguously in [StrLen, StrPtrToInt].  Like
  // isFloatingPointKind above, this is what a solver that cannot reason about
  // these tests its ops bitset against before declining: the i2s solver in
  // particular works off the *enclosing* comparison's traced operand values and
  // can emit a byte assignment without ever walking the string subtree, so an
  // unsound SAT is what silence buys.  jigsaw's JIT and both z3 backends reject
  // an unknown kind through their default: case already.
  static inline bool isStringKind(uint16_t kind) {
    if (kind >= StrLen && kind <= StrPtrToInt)
      return true;
    else
      return false;
  }

  // The three predicates below are the AST-kind twins of the dfsan-op ones in
  // runtime/dfsan/dfsan.h:391-405 (copied verbatim into solvers/z3-ts.cpp:144-157,
  // which cannot include the runtime header).  They translate only because the
  // string kinds were appended in dfsan.h's own relative order, so a range test
  // on ops carries over to a range test on kinds; that ordering is therefore an
  // invariant, not an accident.
  static_assert(StrChr == StrLen + 1 && StrRChr == StrChr + 1 &&
                    StrStr == StrRChr + 1 && StrPbrk == StrStr + 1 &&
                    StrOff == StrPbrk + 1 && SubStr == StrOff + 1 &&
                    StrCat == SubStr + 1 && StrCmp == StrCat + 1 &&
                    PrefixOf == StrCmp + 1 && SuffixOf == PrefixOf + 1 &&
                    StrLength == SuffixOf + 1 && StrPtrToInt == StrLength + 1,
                "string kinds must keep dfsan.h's relative order (fstrlen..flength, "
                "+8); the range predicates below depend on it");

  // A node that evaluates to a string, or to a position within one -- the twin of
  // __dfsan::is_string_op, whose [fstr_op_start, fstr_op_end) range is fstrchr
  // through fstrcat.
  //
  // NOT the same set as isStringKind above, and the difference is the whole point
  // of having both.  isStringKind is the decline gate: every kind a solver without
  // string support must refuse.  This one is the narrower "is my operand a string
  // expression?" question -- it excludes StrLen (an opaque bitvector length),
  // StrCmp/PrefixOf/SuffixOf (predicates *over* strings, not strings), StrLength
  // and StrPtrToInt (Ints derived from one).  dfsan_custom.cpp:628-687 asks
  // exactly this to decide whether a memcmp of two labels is really an fstrcmp.
  static inline bool isStringOpKind(uint16_t kind) {
    if (kind >= StrChr && kind <= StrCat)
      return true;
    else
      return false;
  }

  // An indexOf-type node: one that returns a position rather than content, and -1
  // for "no match".  The twin of __dfsan::is_indexof_op (fstrchr..fstr_off).
  // StrOff is in the range because an offset applied to a position is still a
  // position -- which is what lets z3-ts.cpp walk a chain of them back to the
  // underlying haystack (z3-ts.cpp:1324).
  //
  // A subset of the Int-sorted kinds, not all of them: StrLength and StrPtrToInt
  // are Ints too but are not positions into a haystack.
  static inline bool isIndexOfStringKind(uint16_t kind) {
    if (kind >= StrChr && kind <= StrOff)
      return true;
    else
      return false;
  }

  // A node that evaluates to string content, as opposed to a position or a
  // predicate.  The twin of __dfsan::is_content_string_op (fsubstr, fstrcat).
  // Coincides exactly with the StrSortString bucket below.
  static inline bool isContentStringKind(uint16_t kind) {
    return kind == SubStr || kind == StrCat;
  }

  // The z3 sort a string-theory node evaluates to.  There is no sort field on
  // AstNode; the kind IS the sort tag, which is the whole reason the thirteen
  // dfsan string ops get thirteen kinds instead of one parameterised kind.  A
  // search op returns an Int position into a string, not a bitvector, and
  // handing z3 the wrong one is a sort error raised at assert time -- far from
  // the parse that caused it.
  enum StringSort {
    StrSortBV,      // an ordinary bitvector; the width is in bits()
    StrSortInt,     // z3 Int: a position within a string, or -1 for "no match"
    StrSortString,  // z3 String (a sequence of characters)
  };

  // Only meaningful when isStringKind(kind); other kinds are bitvectors anyway.
  static inline StringSort stringKindSort(uint16_t kind) {
    // positions, arithmetic on positions, and the two other Int-sorted kinds:
    // StrPtrToInt is a pointer difference, and flength is Z3_mk_seq_length --
    // Int-sorted too, unlike the BV that fstrlen's opaque length produces
    if (isIndexOfStringKind(kind) || kind == StrPtrToInt || kind == StrLength)
      return StrSortInt;
    if (isContentStringKind(kind))
      return StrSortString;
    // StrLen, StrCmp, PrefixOf, SuffixOf
    return StrSortBV;
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
      // FP predicate negations (LLVM's ordered<->unordered complement pairs).
      case FOeq: return FUne;
      case FUne: return FOeq;
      case FOgt: return FUle;
      case FUle: return FOgt;
      case FOge: return FUlt;
      case FUlt: return FOge;
      case FOlt: return FUge;
      case FUge: return FOlt;
      case FOle: return FUgt;
      case FUgt: return FOle;
      case FOne: return FUeq;
      case FUeq: return FOne;
      case FOrd: return FUno;
      case FUno: return FOrd;
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
      if (i >= 2) throw std::out_of_range("children index out of range");
      return i == 0 ? root_->at(child0_) : root_->at(child1_);
    }

    inline AstNode* mutable_children(uint32_t i) {
      if (i >= 2) throw std::out_of_range("children index out of range");
      return i == 0 ? &root_->at(child0_) : &root_->at(child1_);
    }

    AstNode* add_children() {
      size_t size = root_->size();
      // assert(size < root_->capacity() && "cannot resize");
      if (size >= root_->capacity()) return nullptr;
      if (child0_ == 0) child0_ = size;
      else if (child1_ == 0) child1_ = size;
      else return nullptr; //assert(false && "too many children");
      root_->emplace_back(AstNode(root_));
      return &root_->back();
    }

    inline void clear_children() { child0_ = child1_ = 0; }
    inline void clear_children(uint32_t i) {
      if (i >= 2) throw std::out_of_range("children index out of range");
      if (i == 1) child1_ = 0;
      else { child0_ = child1_; child1_ = 0; } // pop child1 to child0
    }

    inline uint16_t kind() const { return kind_; }
    inline void set_kind(uint16_t kind) { kind_ = kind; }
    inline uint16_t bits() const { return bits_; }
    inline void set_bits(uint16_t bits) { bits_ = bits; }
    inline uint32_t index() const { return index_; }
    inline void set_index(uint32_t index) { index_ = index; }
    inline uint8_t boolvalue() const { return boolvalue_; }
    // Stores the value as given.  This used to store its complement, which
    // nothing was written against: every caller in find_roots() sets it from
    // the value it means (eval_icmp's answer, `!child->boolvalue()` for a Not)
    // and every reader -- find_roots' own constant folding, jit.cc,
    // z3-solver.cpp -- reads the raw bit back, so the two disagreed and each
    // fold that inspected a folded operand took the wrong arm.
    inline void set_boolvalue(uint8_t value) { boolvalue_ = value ? 1 : 0; }
    inline uint32_t label() const { return label_; }
    inline void set_label(uint32_t label) { label_ = label; }
    inline uint32_t hash() const { return hash_; }
    inline void set_hash(uint32_t hash) { hash_ = hash; }

    // --- serialization --------------------------------------------------
    // Flat POD image of one node: every field except root_, which is a
    // pointer patched on load, and is_root_, which is implied by position.
    // This layout is part of the on-disk format; see Constraint::save().
    struct NodeRec {
      uint32_t child0, child1;
      uint32_t index;
      uint32_t label, hash;
      uint16_t kind, bits;
      uint8_t  boolvalue;
      uint8_t  reserved[3];
    };

    // Append this AST's image to @p out: the standalone root first, then the
    // whole arena, so a child index c in any record refers to out[1 + c] --
    // the arena's element 0 is the unused dummy the root constructor adds.
    void serialize(std::vector<NodeRec> &out) const {
      out.push_back(to_rec());
      for (const auto &n : *root_) out.push_back(n.to_rec());
    }

    inline size_t serialized_nodes() const { return 1 + root_->size(); }

    // Rebuild from what serialize() wrote.  Every child index is range
    // checked first: a corrupt AST that loads without complaint is a wrong
    // answer later, which is much worse than a rejected file here.
    bool deserialize(const NodeRec *recs, size_t count) {
      if (!is_root_ || count == 0) return false;
      const size_t arena = count - 1;
      for (size_t i = 0; i < count; ++i) {
        if (recs[i].child0 >= arena || recs[i].child1 >= arena) return false;
        if (recs[i].index >= (1u << 30)) return false; // index_ is 30 bits
      }
      root_->clear();
      root_->reserve(arena);
      for (size_t i = 1; i < count; ++i) {
        root_->emplace_back(AstNode(root_));
        root_->back().from_rec(recs[i]);
      }
      from_rec(recs[0]);
      return true;
    }

  private:
    inline NodeRec to_rec() const {
      NodeRec r{};
      r.child0 = child0_; r.child1 = child1_;
      r.index = index_; r.label = label_; r.hash = hash_;
      r.kind = kind_; r.bits = bits_; r.boolvalue = boolvalue_;
      return r;
    }
    inline void from_rec(const NodeRec &r) {
      child0_ = r.child0; child1_ = r.child1;
      index_ = r.index; label_ = r.label; hash_ = r.hash;
      kind_ = r.kind; bits_ = r.bits; boolvalue_ = r.boolvalue & 1;
    }

    std::vector<AstNode> *root_; // root of the AST
    uint32_t child0_;
    uint32_t child1_;
    uint16_t kind_;
    uint16_t bits_;
    // index_ is multiplexed by kind_; there is no tag, the kind IS the tag.
    // NOTE isEqualAstRecursive() does NOT compare index_, so a payload that is
    // only reachable *through* index_ is invisible to the AST caches -- see
    // THE HASHING INVARIANT below.
    //
    //   Read       input byte offset; jit.cc maps it through local_map
    //   Extract    starting bit of the slice
    //   Constant   base slot in Constraint::input_args.  One slot per 8 bytes:
    //              a dfsan WideConst lowers to two, LOW half first, and a
    //              memcmp/string target packs ceil(size/8) of them (the target
    //              is a Constant *child* of the Memcmp node, so it is the
    //              child that carries the index, not the Memcmp itself)
    //   TLookup    base slot of the packed table: [0] = num_elems, then the
    //              contents, 8 bytes per slot, little-endian
    //   FpRound,
    //   FP arith   rounding-mode selector (see FpRound above)
    //   StrLen     1 when the terminating NUL is itself an input byte
    //              (dfsan's null_from_input), else 0
    //   SubStr     slice mode: 0 = prefix, 1 = suffix
    //   other
    //   string ops unused, 0.  Every *value* a string kind needs -- content,
    //              needle, character set, GEP offset, observed length -- rides
    //              in a Constant child and is indexed there instead, so that it
    //              stays out of the hash and two constraints differing only in
    //              it share one JIT'ed function.  The two selectors above are
    //              structural rather than values: nothing reads them from
    //              args[], so they must be folded into the hash by hand, the
    //              way FpRound's is (parsers/rgd-parser.cpp)
    //   all others unused, 0
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

  // THE HASHING INVARIANT.  (hash(), isEqualAst) is the key of jigsaw's
  // JIT'ed-function cache -- see fCache in solvers/jit-solver.cpp, whose
  // myHash uses hash() as the bucket and isEqualAst as the comparator.  JIT
  // compilation is jigsaw's dominant cost (jit-solver.cpp times process_time
  // and jit_time separately, and counts cache_hits/cache_misses), so the AST
  // is deliberately shaped to make one compiled function serve as many
  // constraints as possible:
  //
  //   Anything the JIT'ed function reads at run time through args[] must be
  //   EXCLUDED from the hash, so the function is reused across values.
  //   Anything consumed out of band -- i.e. baked into the generated code, or
  //   held on the side by the parser and read by a solver -- must be FOLDED
  //   INTO the hash, or two different payloads collide on one function.
  //
  // The reuse direction is why constants are not in the AST at all: a
  // Constant hashes as xxhash(size, Constant, arg_index) with the VALUE
  // ABSENT, and the value travels in Constraint::input_args, from which jit.cc
  // emits a load of args[index() + RET_OFFSET].  So `x == 5` and `x == 7` are
  // one key and share one compiled function -- the generated code genuinely
  // does not depend on which constant it is.
  //
  // The fold direction covers everything that does NOT have that property.
  // Because isEqualAstRecursive below never compares index(), two nodes that
  // differ only in a payload hung off index() are indistinguishable to this
  // cache unless the payload is in hash().  TLookup folds its table contents
  // for that reason (see the comment at its parser case), and FP arithmetic
  // folds its rounding-mode selector, which jit.cc bakes into the emitted
  // constrained intrinsic rather than reading from args[].
  //
  // A new node kind carrying a payload has to pick a side, and picking wrong
  // is silent either way: fold and lose reuse, or omit and risk conflating two
  // constraints.  The test is whether the compiled function's behaviour is
  // independent of the payload.  For concrete bytes -- a memcmp target, a
  // string needle -- it is, so they go in input_args and stay out of the hash.
  static bool isEqualAstRecursive(const AstNode& lhs, const AstNode& rhs) {

    // number of operands and size of the operands must match
    const int children_size = lhs.children_size();
    if (children_size != rhs.children_size()) return false;
    if (lhs.bits() != rhs.bits()) return false;
    
    if (lhs.kind() != rhs.kind()) {
      // to maximize the reuse of JIT'ed functions, jigsaw does not
      // care about which relational operator is used, as long as
      // they are both relational operators -- EXCEPT that signed and
      // unsigned comparisons extend their operands differently in the
      // JIT (sign- vs zero-extend), so they must stay in separate reuse
      // classes; sharing across the boundary yields an unsound SAT.
      if (isRelationalKind(lhs.kind()) && isRelationalKind(rhs.kind())
          && isSignedRelationalKind(lhs.kind()) == isSignedRelationalKind(rhs.kind())) {
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
