#include "solver.h"

#include "dfsan/dfsan.h"

#include <math.h>
#include <string.h>

using namespace rgd;

#define DEBUG 0

#if !DEBUG
#undef DEBUGF
#define DEBUGF(_str...) do { } while (0)
#elif !defined (DEBUGF)
#define DEBUGF(_str...) do { fprintf(stderr, _str); } while (0)
#endif

#ifndef WARNF
#define WARNF(_str...) do { fprintf(stderr, _str); } while (0)
#endif

#if defined(__GNUC__)
static inline bool (likely)(bool x) { return __builtin_expect((x), true); }
static inline bool (unlikely)(bool x) { return __builtin_expect((x), false); }
#else
static inline bool (likely)(bool x) { return x; }
static inline bool (unlikely)(bool x) { return x; }
#endif

#undef SWAP64
#define SWAP64(_x)                                                             \
  ({                                                                           \
                                                                               \
    uint64_t _ret = (_x);                                                           \
    _ret =                                                                     \
        (_ret & 0x00000000FFFFFFFF) << 32 | (_ret & 0xFFFFFFFF00000000) >> 32; \
    _ret =                                                                     \
        (_ret & 0x0000FFFF0000FFFF) << 16 | (_ret & 0xFFFF0000FFFF0000) >> 16; \
    _ret =                                                                     \
        (_ret & 0x00FF00FF00FF00FF) << 8 | (_ret & 0xFF00FF00FF00FF00) >> 8;   \
    _ret;                                                                      \
                                                                               \
  })

// It is impossible to define 128 bit constants, so ...
#ifdef WORD_SIZE_64
  #define SWAPN(_x, _l)                            \
    ({                                             \
                                                   \
      u128  _res = (_x), _ret;                     \
      char *d = (char *)&_ret, *s = (char *)&_res; \
      int   i;                                     \
      for (i = 0; i < 16; i++)                     \
        d[15 - i] = s[i];                          \
      u32 sr = 128U - ((_l) << 3U);                \
      (_ret >>= sr);                               \
      (u128) _ret;                                 \
                                                   \
    })
#endif

#define SWAPNN(_x, _y, _l)                     \
  ({                                           \
                                               \
    char *d = (char *)(_x), *s = (char *)(_y); \
    u32   i, l = (_l)-1;                       \
    for (i = 0; i <= l; i++)                   \
      d[l - i] = s[i];                         \
                                               \
  })

static uint64_t get_i2s_value(uint32_t comp, uint64_t v, bool rhs) {
  switch (comp) {
    case rgd::Equal:
    case rgd::Ule:
    case rgd::Uge:
    case rgd::Sle:
    case rgd::Sge:
      return v;
    case rgd::Distinct:
    case rgd::Ugt:
    case rgd::Sgt:
      if (rhs) return v - 1;
      else return v + 1;
    case rgd::Ult:
    case rgd::Slt:
      if (rhs) return v + 1;
      else return v - 1;
    default:
      WARNF("Non-relational i2s op %u!\n", comp);
  }
  return v;
}

//===----------------------------------------------------------------------===//
// Floating-point input-to-state helpers
//
// FP-typed labels carry the IEEE-754 encoding as a bit-vector, so a "direct"
// FCmp (an input value read straight into an FP compare against a constant)
// looks, at the byte level, exactly like the integer i2s case: the symbolic
// operand's bytes appear literally in the input and can be replaced wholesale.
// The only twist is that the replacement value must satisfy an FP relation, so
// we decode to a C double/float, pick a satisfying value (using nextafter for
// strict inequalities), and re-encode.  Every guess is verified against the
// actual FP semantics before we claim SAT (see solve_fcmp).
//===----------------------------------------------------------------------===//

// Decode an IEEE-754 bit pattern (4- or 8-byte) into a C double.
static inline double fp_decode(uint64_t bits, uint32_t bytes) {
  if (bytes == 8) {
    double d; memcpy(&d, &bits, sizeof(d)); return d;
  } else { // 4
    uint32_t u = (uint32_t)bits; float f; memcpy(&f, &u, sizeof(f)); return (double)f;
  }
}

// Encode a C double into an IEEE-754 bit pattern of the given width (narrowing
// to float for 4-byte).  Inverse of fp_decode.
static inline uint64_t fp_encode(double d, uint32_t bytes) {
  if (bytes == 8) {
    uint64_t b; memcpy(&b, &d, sizeof(b)); return b;
  } else { // 4
    float f = (float)d; uint32_t u; memcpy(&u, &f, sizeof(u)); return (uint64_t)u;
  }
}

// Next representable value from x toward dir (+/-inf), at the target precision.
static inline double fp_next(double x, double dir, uint32_t bytes) {
  if (bytes == 8) return nextafter(x, dir);
  else return (double)nextafterf((float)x, (float)dir);
}

// Map an rgd FP relational kind to the LLVM FCmp predicate (1..14).
static inline uint32_t fcmp_predicate(uint32_t comparison) {
  return comparison - rgd::FOeq + 1;
}

// Swap the operands of an FCmp predicate: returns the predicate P' such that
// (a P b) == (b P' a).  Only the ordering-sensitive predicates change.
static inline uint32_t swap_fcmp_predicate(uint32_t pred) {
  switch (pred) {
    case 2:  return 4;  // OGT <-> OLT
    case 3:  return 5;  // OGE <-> OLE
    case 4:  return 2;
    case 5:  return 3;
    case 10: return 12; // UGT <-> ULT
    case 11: return 13; // UGE <-> ULE
    case 12: return 10;
    case 13: return 11;
    default: return pred; // OEQ, ONE, ORD, UNO, UEQ, UNE are symmetric
  }
}

// Concrete evaluation of an FCmp (LLVM predicate 1..14) on two doubles.
static inline bool i2s_eval_fcmp(uint32_t pred, double a, double b) {
  bool ord = !(isnan(a) || isnan(b));
  switch (pred) {
    case 1:  return ord && a == b; // OEQ
    case 2:  return ord && a > b;  // OGT
    case 3:  return ord && a >= b; // OGE
    case 4:  return ord && a < b;  // OLT
    case 5:  return ord && a <= b; // OLE
    case 6:  return ord && a != b; // ONE
    case 7:  return ord;           // ORD
    case 8:  return !ord;          // UNO
    case 9:  return !ord || a == b; // UEQ
    case 10: return !ord || a > b;  // UGT
    case 11: return !ord || a >= b; // UGE
    case 12: return !ord || a < b;  // ULT
    case 13: return !ord || a <= b; // ULE
    case 14: return !ord || a != b; // UNE
    default: return false;
  }
}

// Pick a value for the symbolic operand that satisfies (sym <pred> k) when the
// symbolic operand is the lhs, or (k <pred> sym) when it is the rhs.  We fold
// the rhs case into the lhs case by swapping the predicate, then choose a
// witness relative to the constant k.  The result is still verified by the
// caller, so an unsatisfiable predicate (e.g. OGT against +inf) just fails
// verification and is skipped.
static inline double fp_i2s_target(uint32_t pred, double k, bool sym_is_lhs,
                                   uint32_t bytes) {
  uint32_t p = sym_is_lhs ? pred : swap_fcmp_predicate(pred);
  switch (p) {
    case 1:  // OEQ: sym == k
    case 3:  // OGE: sym >= k
    case 5:  // OLE: sym <= k
    case 7:  // ORD: sym is not NaN
    case 9:  // UEQ: sym == k (or NaN)
    case 11: // UGE
    case 13: // ULE
      return k;
    case 2:  // OGT: sym > k
    case 10: // UGT
      return fp_next(k, HUGE_VAL, bytes); // toward +inf
    case 4:  // OLT: sym < k
    case 12: // ULT
      return fp_next(k, -HUGE_VAL, bytes); // toward -inf
    case 6:  // ONE: sym != k, not NaN
    case 14: // UNE
      return k == 0.0 ? 1.0 : 0.0;
    case 8:  // UNO: sym is NaN (k is a concrete constant, assumed not NaN)
      return (double)NAN;
    default:
      return k;
  }
}

// True for the FP binops that solve_fcmp can invert against a constant.
// FpPow is included: it is binary (base, exponent) with one constant operand,
// so it reuses the same fp_binop_eval/invert/const machinery as FAdd..FDiv.
static inline bool isFPArithKind(uint16_t kind) {
  return (kind >= rgd::FAdd && kind <= rgd::FDiv) || kind == rgd::FpPow;
}

// True for the unary FP transcendentals solve_fcmp can invert numerically
// (exp/exp2/log/log2/log10/log1p).  z3 cannot invert these, but i2s computes
// the closed-form libm inverse (see fp_trans_invert) and verifies it.
static inline bool isFPTransKind(uint16_t kind) {
  return kind >= rgd::FpExp && kind <= rgd::FpLog1p;
}

// Forward-evaluate a unary FP transcendental at the target precision (float for
// 4-byte, double for 8-byte), mirroring fp_binop_eval so the structural check
// matches the runtime-recorded result bit-exactly.
static inline double fp_trans_eval(double v, uint16_t kind, uint32_t bytes) {
  if (bytes == 4) {
    float fv = (float)v, fr;
    switch (kind) {
      case rgd::FpExp:   fr = expf(fv); break;
      case rgd::FpExp2:  fr = exp2f(fv); break;
      case rgd::FpLog:   fr = logf(fv); break;
      case rgd::FpLog2:  fr = log2f(fv); break;
      case rgd::FpLog10: fr = log10f(fv); break;
      case rgd::FpLog1p: fr = log1pf(fv); break;
      default: fr = fv;
    }
    return (double)fr;
  } else {
    switch (kind) {
      case rgd::FpExp:   return exp(v);
      case rgd::FpExp2:  return exp2(v);
      case rgd::FpLog:   return log(v);
      case rgd::FpLog2:  return log2(v);
      case rgd::FpLog10: return log10(v);
      case rgd::FpLog1p: return log1p(v);
      default: return v;
    }
  }
}

// Invert a unary FP transcendental: return the input value x such that
// f(x) == s.  A heuristic guess (FP rounding is not exactly invertible), always
// re-verified by the caller.  exp<->log, exp2<->log2, log10->pow(10,.),
// log1p->expm1.
static inline double fp_trans_invert(double s, uint16_t kind) {
  switch (kind) {
    case rgd::FpExp:   return log(s);
    case rgd::FpExp2:  return log2(s);
    case rgd::FpLog:   return exp(s);
    case rgd::FpLog2:  return exp2(s);
    case rgd::FpLog10: return pow(10.0, s);
    case rgd::FpLog1p: return expm1(s);
    default: return s;
  }
}

// Forward-evaluate an FP binop in the target precision (float for 4-byte, double
// for 8-byte).  const_is_rhs selects operand order for the non-commutative ops:
// true  -> (v op cst), false -> (cst op v).  Computing in the target precision
// lets the structural check below match the runtime-recorded result bit-exactly.
static inline double fp_binop_eval(double v, double cst, uint16_t kind,
                                   bool const_is_rhs, uint32_t bytes) {
  if (bytes == 4) {
    float fv = (float)v, fc = (float)cst, fr;
    switch (kind) {
      case rgd::FAdd: fr = fv + fc; break;                       // commutative
      case rgd::FSub: fr = const_is_rhs ? fv - fc : fc - fv; break;
      case rgd::FMul: fr = fv * fc; break;                       // commutative
      case rgd::FDiv: fr = const_is_rhs ? fv / fc : fc / fv; break;
      // pow(base, exp): const_is_rhs -> exponent is constant (v^c), else base
      // is constant (c^v).
      case rgd::FpPow: fr = const_is_rhs ? powf(fv, fc) : powf(fc, fv); break;
      default: fr = fv;
    }
    return (double)fr;
  } else {
    switch (kind) {
      case rgd::FAdd: return v + cst;                            // commutative
      case rgd::FSub: return const_is_rhs ? v - cst : cst - v;
      case rgd::FMul: return v * cst;                            // commutative
      case rgd::FDiv: return const_is_rhs ? v / cst : cst / v;
      case rgd::FpPow: return const_is_rhs ? pow(v, cst) : pow(cst, v);
      default: return v;
    }
  }
}

// Invert an FP binop: return the operand value that makes the binop produce s.
// The result is a heuristic guess (FP rounding is not exactly invertible) and is
// always re-verified by the caller.
static inline double fp_binop_invert(double s, double cst, uint16_t kind,
                                     bool const_is_rhs) {
  switch (kind) {
    case rgd::FAdd: return s - cst;                             // v = s - cst
    case rgd::FSub: return const_is_rhs ? s + cst : cst - s;    // v op cst / cst op v
    case rgd::FMul: return s / cst;                             // v = s / cst
    case rgd::FDiv: return const_is_rhs ? s * cst : cst / s;    // v op cst / cst op v
    // pow: exponent const -> v = s^(1/cst); base const -> v = log(s)/log(cst)
    case rgd::FpPow: return const_is_rhs ? pow(s, 1.0 / cst) : log(s) / log(cst);
    default: return s;
  }
}

// Find the Constant child of an FP binop node and return its IEEE bits plus
// which side it is on.  Mirrors get_binop_value's constant lookup.
static inline bool fp_binop_const(std::shared_ptr<const Constraint> constraint,
    const AstNode &node, uint64_t &cst_bits, bool &const_is_rhs) {
  auto &left = node.children(0);
  auto &right = node.children(1);
  if (left.kind() == Constant) {
    cst_bits = constraint->input_args[left.index()].second;
    const_is_rhs = false;
    return true;
  } else if (right.kind() == Constant) {
    cst_bits = constraint->input_args[right.index()].second;
    const_is_rhs = true;
    return true;
  }
  return false;
}

static inline uint64_t _get_binop_value(uint64_t v1, uint64_t v2, uint16_t kind) {
  switch (kind) {
    case rgd::Add: return v1 + v2;
    case rgd::Sub: return v1 - v2;
    case rgd::Mul: return v1 * v2;
    case rgd::UDiv: return v2 ? v1 / v2 : 0;
    case rgd::SDiv: return v2 ? (int64_t)v1 / (int64_t)v2 : 0;
    case rgd::URem: return v2 ? v1 % v2 : 0;
    case rgd::SRem: return v2 ? (int64_t)v1 % (int64_t)v2 : 0;
    case rgd::And: return v1 & v2;
    case rgd::Or: return v1 | v2;
    case rgd::Xor: return v1 ^ v2;
    case rgd::Shl: return v1 << v2;
    case rgd::LShr: return v1 >> v2;
    case rgd::AShr: return (int64_t)v1 >> v2;
    default: WARNF("Non-binary i2s op %u!\n", kind);
  }
  return 0;
}

static inline uint64_t _get_binop_value_r(uint64_t r, uint64_t const_op, uint16_t kind, bool rhs) {
  // we aim to reverse the binary operation
  // if rhs:              const_op op v = r
  // if lhs (i.e., !rhs): v op const_op = r
  switch (kind) {
    case rgd::Add: return r - const_op; // v = r - const_op
    case rgd::Sub: return rhs ? const_op - r : r + const_op; // rhs: v = const_op - r; lhs: v = r + const_op
    case rgd::Mul: return r / const_op; // v = r / const_op
    case rgd::UDiv: return rhs ? const_op / r : r * const_op; // rhs: v = const_op / r; lhs: v = r * const_op
    case rgd::SDiv: return rhs ? (int64_t)const_op / (int64_t)r : (int64_t)r * (int64_t)const_op;
    case rgd::URem:
      if (rhs) {
        if (const_op < r) {
          WARNF("URem rhs const_op < r\n");
          return r;
        }
        // const_op % v = r
        // if const_op > r, const_op % (const_op - r) = r
        // if const_op == r, const_op % (const_op + 1) = const_op = r
        // if const_op < r, not possible
        return const_op > r ? const_op - r : const_op + 1;
      } else {
        // XXX: (v % const_op) % const_op == v % const_op = r
        return r;
      }
    case rgd::SRem:
      if (rhs) {
        if ((int64_t)const_op < (int64_t)r) {
          WARNF("SRem rhs const_op < r\n");
          return r;
        }
        return (int64_t)const_op > (int64_t)r ? (int64_t)const_op - (int64_t)r : (int64_t)const_op + 1;
      } else {
        return r;
      }
    case rgd::And: return (r & const_op) == r ? r : const_op; // XXX: when r = v & const_op, (r) & const_op = (v & const_op) & const_op = v & const_op = r
    case rgd::Or: return (r | const_op) == r ? r : const_op;  // XXX: (a | b) | b == a | b
    case rgd::Xor: return r ^ const_op; // v = r ^ const_op
    case rgd::Shl:
      if (rhs) {
        if (const_op == 1) {
          double log2 = std::log2(r);
          return static_cast<uint64_t>(log2);
        } else {
          WARNF("unsupported Shl (rhs) const_op %lu\n", const_op);
          return 0;
        }
      } else {
        return r >> const_op; // v = r >> const_op
      }
    case rgd::LShr:
      if (rhs) {
        WARNF("LShr rhs not supported\n");
        return r; // FIXME: r probably is not correct
      }
      return r << const_op; // v = r << diff
    case rgd::AShr:
      if (rhs) {
        WARNF("AShr rhs not supported");
        return r; // FIXME: r probably is not correct
      }
      return (int64_t)r << const_op;
    default: WARNF("Non-binary binop_value op %u!\n", kind);
  }
  return 0;
}

static uint64_t get_binop_value(std::shared_ptr<const Constraint> constraint,
    const AstNode &node, uint64_t value, uint64_t &const_op, bool &rhs) {
  auto &left = node.children(0);
  auto &right = node.children(1);
  uint64_t r = 0;
  if (left.kind() == Constant) {
    const_op = constraint->input_args[left.index()].second;
    r = _get_binop_value(const_op, value, node.kind());
    rhs = true;
  } else if (right.kind() == Constant) {
    const_op = constraint->input_args[right.index()].second;
    r = _get_binop_value(value, const_op, node.kind());
    rhs = false;
  }
  return r;
}

//===----------------------------------------------------------------------===//
// AST-guided input-to-state
//
// The value-based matching above looks for a *whole* compared operand in the
// input and inverts at most one binary operation sitting directly under the
// comparison.  Two shapes fall outside that:
//
//   - a lookup table (rgd::TLookup).  The compared value never appears in the
//     input at all; only the index into the table does, and the table's bytes
//     are carried in the node's constant args.
//   - nested arithmetic such as (dehex[a] << 4) + dehex[b]: several binop
//     kinds, more than one level, and an Add whose two operands are both
//     symbolic so neither is the "constant" the flat path needs.
//
// Both fall out of a pair of mutually recursive walks: an evaluator that
// computes a subtree's concrete value under a candidate input, and an inverter
// that pushes a wanted value down toward the Read leaves.  Where the inverter
// has to guess -- a non-injective table, a bitwise op with no exact inverse, an
// operand pinned at the value it happens to hold -- the guess is checked, both
// locally by re-evaluating the subtree and again at the top by re-evaluating
// the whole comparison.  Same discipline as the FP path (see solve_fcmp):
// speculate freely, claim SAT only on a verified candidate.
//
// Nodes these walks do not understand (FP kinds, Ite, Neg/Not, and the
// label-only stubs the parser leaves behind for a subexpression it has already
// emitted once in this constraint) make the walk fail.  A miss, never a guess.
//===----------------------------------------------------------------------===//

// How deep the walks will go.  Bounds both the work per attempt and the blowup
// from a non-injective table, where each level may try several entries.
static const uint32_t kI2SMaxDepth = 16;

// Separate, much larger bound for the Concat spine of a wide (memcmp-sized)
// buffer: that spine is one level per element, so a 64-byte target is 64 deep
// before any real expression is reached.
static const uint32_t kI2SMaxWideDepth = 256;

// Largest operand value set i2s_value_domain will enumerate.  Anything wider is
// reported as not enumerable rather than truncated, so the caller falls back to
// the single current value instead of searching a silently partial set.
static const size_t kI2SMaxDomain = 64;

// Total inversion steps allowed per top-level solve.  Enumerating an operand's
// domain multiplies the branching factor at every binop level, so a deep tree
// of tables could otherwise walk the solver into a stall; i2s is the cheap path
// and has to stay cheap.
static const uint32_t kI2SMaxSteps = 20000;

// A pending byte-level assignment: input offset -> new value.  Collected rather
// than written straight into out_buf so a failed branch (the wrong entry of a
// non-injective table, say) can be abandoned by truncating the vector, leaving
// no trace for the next candidate to trip over.
typedef std::vector<std::pair<size_t, uint8_t>> i2s_assignment_t;

// Map from label to the one fully-expanded node bearing it.  The parser emits
// each distinct label once per constraint and leaves a stub -- label and width
// only, kind rgd::Bool, no children -- everywhere else it appears (see the
// `visited` set in RGDAstParser::do_uta_rel).  Both walks below would stop dead
// at a stub, and they meet them constantly: `buff[i] >> 4` and `buff[i] % 16`
// share their Read, so the second lookup of a hex-encoding pair is all stub.
typedef std::unordered_map<uint32_t, const AstNode *> i2s_node_map_t;

// Everything the walks carry around.  Bundled because there are five of them
// and they are threaded through every recursive call.
struct i2s_ctx {
  std::shared_ptr<const Constraint> c;
  const uint8_t *in_buf;
  size_t in_size;
  i2s_node_map_t nodes;
  i2s_assignment_t assign;
  uint32_t steps;
};

// Read one input byte under the pending assignment.  Later entries win, so
// truncating the vector restores the previous view for free.
static inline uint8_t i2s_peek(const i2s_ctx &ctx, size_t offset, bool &ok) {
  for (size_t i = ctx.assign.size(); i > 0; --i) {
    if (ctx.assign[i - 1].first == offset) return ctx.assign[i - 1].second;
  }
  if (unlikely(offset >= ctx.in_size)) { ok = false; return 0; }
  return ctx.in_buf[offset];
}

// Mask to a node's width.  Callers reject widths above 64 bits, so the
// undefined 64-bit shift is unreachable.
static inline uint64_t i2s_mask(uint32_t bits) {
  return bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
}

// Sign-extend a value that is `bits` wide to a full 64-bit signed value.
static inline int64_t i2s_sext(uint64_t v, uint32_t bits) {
  if (bits >= 64) return (int64_t)v;
  uint32_t sh = 64 - bits;
  return ((int64_t)(v << sh)) >> sh;
}

// Reverse the low `bits` bits of `v`, which is what llvm.bitreverse does.  Its
// own inverse, so the same helper serves both evaluation and inversion.
static inline uint64_t i2s_bitrev(uint64_t v, uint32_t bits) {
  uint64_t r = 0;
  for (uint32_t i = 0; i < bits; ++i)
    r |= ((v >> i) & 1ULL) << (bits - 1 - i);
  return r;
}

// Index the fully-expanded nodes of a constraint so stubs can be redirected.
static void i2s_index_nodes(const AstNode &node, i2s_node_map_t &map,
                            uint32_t depth) {
  if (unlikely(depth > 1024)) return; // the AST is a tree, but be defensive
  // stubs are exactly the kind-Bool nodes; a real Bool carries no label either
  if (node.kind() != rgd::Bool && node.label() != 0)
    map.emplace(node.label(), &node);
  uint32_t n = node.children_size();
  for (uint32_t i = 0; i < n; ++i)
    i2s_index_nodes(node.children(i), map, depth + 1);
}

// Follow a stub to the node it stands for.  Returns nullptr for a stub whose
// label was never expanded, which makes the caller fail rather than guess.
static inline const AstNode *i2s_resolve(const i2s_ctx &ctx, const AstNode &node) {
  if (likely(node.kind() != rgd::Bool)) return &node;
  auto itr = ctx.nodes.find(node.label());
  return itr == ctx.nodes.end() ? nullptr : itr->second;
}

// Fetch element `idx` of the table packed into a TLookup node's constant args.
// Layout, starting at index() (see parsers/rgd-parser.cpp): the element count,
// then the raw bytes, 8 per arg, little-endian.
static bool i2s_table_elem(const i2s_ctx &ctx, const AstNode &node,
                           uint64_t idx, uint64_t &out) {
  auto const& args = ctx.c->input_args;
  uint32_t base = node.index();
  if (unlikely(base >= args.size())) return false;
  uint64_t num_elems = args[base].second;
  if (idx >= num_elems) return false; // out of range: not this table's business
  uint32_t elem_size = node.bits() / 8;
  if (unlikely(elem_size == 0 || elem_size > 8 || node.bits() % 8 != 0)) return false;
  uint64_t val = 0;
  for (uint32_t b = 0; b < elem_size; ++b) {
    uint64_t byte_off = idx * elem_size + b;
    size_t arg = base + 1 + (size_t)(byte_off / 8);
    if (unlikely(arg >= args.size())) return false;
    val |= ((args[arg].second >> ((byte_off % 8) * 8)) & 0xff) << (b * 8);
  }
  out = val;
  return true;
}

// Concrete value of a subtree under the current input plus any pending
// assignment.  Returns false on anything it cannot compute exactly.
static bool i2s_eval_int(i2s_ctx &ctx, const AstNode &n_, uint64_t &out,
                         uint32_t depth) {
  if (unlikely(depth > kI2SMaxDepth)) return false;
  const AstNode *np = i2s_resolve(ctx, n_);
  if (unlikely(np == nullptr)) return false;
  auto const& node = *np;
  if (unlikely(node.bits() == 0 || node.bits() > 64)) return false;
  switch (node.kind()) {
    case rgd::Constant: {
      if (unlikely(node.index() >= ctx.c->input_args.size())) return false;
      out = ctx.c->input_args[node.index()].second & i2s_mask(node.bits());
      return true;
    }
    case rgd::Read: {
      uint32_t bytes = node.bits() / 8;
      if (unlikely(bytes == 0 || bytes > 8 || node.bits() % 8 != 0)) return false;
      bool ok = true;
      uint64_t v = 0;
      for (uint32_t i = 0; i < bytes; ++i)
        v |= (uint64_t)i2s_peek(ctx, node.index() + i, ok) << (i * 8);
      if (unlikely(!ok)) return false;
      out = v;
      return true;
    }
    case rgd::ZExt: {
      auto const& ch = node.children(0);
      uint64_t v;
      if (!i2s_eval_int(ctx, ch, v, depth + 1)) return false;
      out = v & i2s_mask(ch.bits());
      return true;
    }
    case rgd::SExt: {
      auto const& ch = node.children(0);
      uint64_t v;
      if (!i2s_eval_int(ctx, ch, v, depth + 1)) return false;
      out = (uint64_t)i2s_sext(v, ch.bits()) & i2s_mask(node.bits());
      return true;
    }
    case rgd::Extract: {
      auto const& ch = node.children(0);
      uint64_t v;
      if (unlikely(ch.bits() > 64 || node.index() >= 64)) return false;
      if (!i2s_eval_int(ctx, ch, v, depth + 1)) return false;
      out = (v >> node.index()) & i2s_mask(node.bits());
      return true;
    }
    case rgd::Concat: {
      // children(1) holds the HIGH bits: z3-solver.cpp serializes this node as
      // concat(c2, c1), and z3's concat puts its first argument on top.
      auto const& lo = node.children(0);
      uint64_t lv, hv;
      if (unlikely(lo.bits() >= 64)) return false;
      if (!i2s_eval_int(ctx, lo, lv, depth + 1)) return false;
      if (!i2s_eval_int(ctx, node.children(1), hv, depth + 1)) return false;
      out = ((lv & i2s_mask(lo.bits())) | (hv << lo.bits())) & i2s_mask(node.bits());
      return true;
    }
    case rgd::TLookup: {
      uint64_t idx;
      if (!i2s_eval_int(ctx, node.children(0), idx, depth + 1)) return false;
      return i2s_table_elem(ctx, node, idx, out);
    }
    case rgd::BitReverse: {
      uint64_t v;
      if (!i2s_eval_int(ctx, node.children(0), v, depth + 1)) return false;
      out = i2s_bitrev(v, node.bits());
      return true;
    }
    default: break;
  }
  if (!isBinaryOperation(node.kind())) return false;
  uint64_t v1, v2;
  if (!i2s_eval_int(ctx, node.children(0), v1, depth + 1)) return false;
  if (!i2s_eval_int(ctx, node.children(1), v2, depth + 1)) return false;
  switch (node.kind()) {
    // an over-wide shift or a division by zero is poison in LLVM, so there is
    // no value to report -- fail instead of inventing one (and instead of
    // executing the matching UB in _get_binop_value)
    case rgd::Shl: case rgd::LShr: case rgd::AShr:
      if (v2 >= node.bits()) return false;
      break;
    case rgd::UDiv: case rgd::URem:
      if (v2 == 0) return false;
      break;
    case rgd::SDiv: case rgd::SRem:
      if (v2 == 0) return false;
      // INT_MIN / -1 traps on x86; poison in LLVM either way
      if (i2s_sext(v2, node.bits()) == -1 &&
          i2s_sext(v1, node.bits()) == i2s_sext(1ULL << (node.bits() - 1), node.bits()))
        return false;
      break;
    default: break;
  }
  // the signed operations are computed on 64-bit signed values, so the operands
  // have to carry their sign up from the node's width first
  switch (node.kind()) {
    case rgd::AShr:
      v1 = (uint64_t)i2s_sext(v1, node.bits());
      break;
    case rgd::SDiv: case rgd::SRem:
      v1 = (uint64_t)i2s_sext(v1, node.bits());
      v2 = (uint64_t)i2s_sext(v2, node.bits());
      break;
    default: break;
  }
  out = _get_binop_value(v1, v2, node.kind()) & i2s_mask(node.bits());
  return true;
}

// The distinct values a subtree can take, when that set is small and statically
// knowable.  Only a lookup table gives one: a TLookup can produce nothing but
// the values its table holds, and a width cast or an operation against a
// constant maps that set through.  Returns false as soon as the set stops being
// enumerable, leaving the caller to fall back to the single value the subtree
// holds under the current input.
static bool i2s_value_domain_r(i2s_ctx &ctx, const AstNode &n_,
                               std::vector<uint64_t> &out, uint32_t depth) {
  if (unlikely(depth > kI2SMaxDepth)) return false;
  const AstNode *np = i2s_resolve(ctx, n_);
  if (unlikely(np == nullptr)) return false;
  auto const& node = *np;
  if (unlikely(node.bits() == 0 || node.bits() > 64)) return false;
  uint64_t m = i2s_mask(node.bits());
  auto emit = [&out, m](uint64_t v) -> bool {
    v &= m;
    for (auto e : out) if (e == v) return true;
    if (out.size() >= kI2SMaxDomain) return false;
    out.push_back(v);
    return true;
  };
  switch (node.kind()) {
    case rgd::TLookup: {
      if (unlikely(node.index() >= ctx.c->input_args.size())) return false;
      uint64_t num_elems = ctx.c->input_args[node.index()].second;
      if (num_elems == 0 || num_elems > kI2SMaxDomain) return false;
      for (uint64_t i = 0; i < num_elems; ++i) {
        uint64_t elem = 0;
        if (!i2s_table_elem(ctx, node, i, elem)) return false;
        if (!emit(elem)) return false;
      }
      return true;
    }
    case rgd::ZExt: case rgd::SExt: case rgd::Extract: {
      auto const& ch = node.children(0);
      std::vector<uint64_t> sub;
      if (!i2s_value_domain_r(ctx, ch, sub, depth + 1)) return false;
      if (node.kind() == rgd::Extract && node.index() >= 64) return false;
      for (auto v : sub) {
        uint64_t r;
        if (node.kind() == rgd::ZExt) r = v & i2s_mask(ch.bits());
        else if (node.kind() == rgd::SExt) r = (uint64_t)i2s_sext(v, ch.bits());
        else r = v >> node.index();
        if (!emit(r)) return false;
      }
      return true;
    }
    case rgd::BitReverse: {
      // a bijection on the same width, so it maps a domain through one-for-one
      std::vector<uint64_t> sub;
      if (!i2s_value_domain_r(ctx, node.children(0), sub, depth + 1)) return false;
      for (auto v : sub)
        if (!emit(i2s_bitrev(v, node.bits()))) return false;
      return true;
    }
    // deliberately no Concat: the cross product of two domains is not small
    default: break;
  }
  // A binary operation against a constant maps the other operand's domain
  // through it -- (dehex[a] << 4) has the same 16-element domain that dehex
  // does, scaled.  Division and remainder are left out rather than guarded
  // against their poison cases; nothing needs them here.
  switch (node.kind()) {
    case rgd::Add: case rgd::Sub: case rgd::Mul: case rgd::Xor:
    case rgd::And: case rgd::Or:
    case rgd::Shl: case rgd::LShr: case rgd::AShr:
      break;
    default: return false;
  }
  auto const& l = node.children(0);
  auto const& r = node.children(1);
  bool sym_is_rhs;
  if (l.kind() == rgd::Constant) sym_is_rhs = true;
  else if (r.kind() == rgd::Constant) sym_is_rhs = false;
  else return false;
  uint64_t const_op = 0;
  if (!i2s_eval_int(ctx, sym_is_rhs ? l : r, const_op, depth + 1)) return false;
  std::vector<uint64_t> sub;
  if (!i2s_value_domain_r(ctx, sym_is_rhs ? r : l, sub, depth + 1)) return false;
  for (auto v : sub) {
    uint64_t v1 = sym_is_rhs ? const_op : v;
    uint64_t v2 = sym_is_rhs ? v : const_op;
    switch (node.kind()) {
      // an over-wide shift is poison, so there is no value to report
      case rgd::Shl: case rgd::LShr: case rgd::AShr:
        if (v2 >= node.bits()) return false;
        if (node.kind() == rgd::AShr) v1 = (uint64_t)i2s_sext(v1, node.bits());
        break;
      default: break;
    }
    if (!emit(_get_binop_value(v1, v2, node.kind()))) return false;
  }
  return true;
}

// Values worth pinning an operand at, best first.  Always begins with the value
// the operand already holds, so a constraint that solves today keeps taking the
// same route; a table-derived operand then contributes the rest of its range.
//
// The extra values are what split an Add whose operands are both symbolic and
// neither of which can reach the target alone.  In
// (dehex[a] << 4) + dehex[b] == 0xab the left operand can only be a multiple of
// 16 and the right only 0..15, so pinning either at whatever it happens to hold
// never finds the 0xa0 + 0x0b split; enumerating one side's 16 values does.
static void i2s_value_domain(i2s_ctx &ctx, const AstNode &node, uint64_t cur,
                             std::vector<uint64_t> &out, uint32_t depth) {
  out.clear();
  if (!i2s_value_domain_r(ctx, node, out, depth)) out.clear();
  for (size_t i = 0; i < out.size(); ++i) {
    if (out[i] == cur) { std::swap(out[0], out[i]); return; }
  }
  out.insert(out.begin(), cur);
}

// Reverse a binary operation for its symbolic operand: given the other
// operand's value `const_op`, the wanted result `target`, and the value the
// symbolic operand holds right now (`cur`), produce the value it should take.
// `rhs` says the symbolic operand is on the right of the operation.
//
// The kinds handled explicitly are the ones that do NOT determine every bit of
// their operand -- a shift drops bits off one end, a mask keeps only the bits
// the constant selects, a remainder fixes only the residue.  Those bits are
// filled back in from `cur` rather than zeroed, which is what makes a
// hex-encoding pair work: `x >> 4` and `x % 16` constrain different nibbles of
// the same input byte, and each has to leave the other's nibble alone.
// Everything else falls through to _get_binop_value_r, whose rejects are
// screened here because they would otherwise warn and return a placeholder
// (solving for a shift amount) or divide by zero.
//
// Returns false when the target is unreachable through this operation.
static bool i2s_binop_invert(uint16_t kind, bool rhs, uint64_t const_op,
                             uint64_t target, uint64_t cur, uint32_t bits,
                             uint64_t &want) {
  uint64_t m = i2s_mask(bits);
  target &= m; const_op &= m; cur &= m;
  switch (kind) {
    case rgd::And: {
      // v & c == r: r may not set a bit that c clears, and the bits c clears
      // are unconstrained in v, so keep them
      if ((target & ~const_op & m) != 0) return false;
      want = (target & const_op) | (cur & ~const_op & m);
      return true;
    }
    case rgd::Or: {
      // v | c == r: every bit c sets must be set in r, and those bits of v are
      // free
      if ((const_op & ~target & m) != 0) return false;
      want = (target & ~const_op & m) | (cur & const_op);
      return true;
    }
    case rgd::Shl: case rgd::LShr: case rgd::AShr: {
      if (rhs) return false; // solving for the shift amount is not supported
      if (const_op >= bits) return false;
      if (const_op == 0) { want = target; return true; }
      if (kind == rgd::Shl) {
        // v << c == r: the low c bits of r must be zero; the top c bits of v
        // are shifted out and keep whatever they hold
        if ((target & i2s_mask((uint32_t)const_op)) != 0) return false;
        uint64_t det = i2s_mask(bits - (uint32_t)const_op);
        want = ((target >> const_op) & det) | (cur & ~det & m);
      } else {
        // v >> c == r: the low c bits of v are shifted out and keep whatever
        // they hold.  An AShr target that disagrees with the sign it implies is
        // left for the caller's re-evaluation to reject.
        if (kind == rgd::LShr && (target >> (bits - (uint32_t)const_op)) != 0)
          return false; // r too wide to have come from a logical shift
        uint64_t det = ~i2s_mask((uint32_t)const_op) & m;
        want = ((target << const_op) & det) | (cur & ~det & m);
      }
      return true;
    }
    case rgd::URem: case rgd::SRem: {
      if (rhs) return false; // solving for the divisor is not supported
      if (const_op == 0 || target >= const_op) return false;
      // v % c == r: only the residue is pinned, so stay on the multiple of c
      // that `cur` already sits on
      want = ((cur / const_op) * const_op + target) & m;
      return true;
    }
    case rgd::Mul:
      if (const_op == 0) return false; // v = r / const_op, either side
      break;
    case rgd::UDiv: case rgd::SDiv:
      // lhs: v = r * const_op.  rhs: v = const_op / r, so r must be a safe divisor
      if (rhs && (target == 0 || (int64_t)target == -1)) return false;
      break;
    case rgd::Add: case rgd::Sub: case rgd::Xor:
      break;
    default:
      return false;
  }
  want = _get_binop_value_r(target, const_op, kind, rhs) & m;
  return true;
}

// Push `target` down the AST toward the Read leaves, recording the byte writes
// it implies in ctx.assign.  On failure ctx.assign is left as it was on entry.
static bool i2s_invert(i2s_ctx &ctx, const AstNode &n_, uint64_t target,
                       uint32_t depth) {
  if (unlikely(depth > kI2SMaxDepth || ctx.steps == 0)) return false;
  ctx.steps--;
  const AstNode *np = i2s_resolve(ctx, n_);
  if (unlikely(np == nullptr)) return false;
  auto const& node = *np;
  if (unlikely(node.bits() == 0 || node.bits() > 64)) return false;
  target &= i2s_mask(node.bits());
  DEBUGF("i2s-invert: %*skind %u, bits %u, target 0x%lx\n", depth * 2, "",
         node.kind(), node.bits(), target);
  switch (node.kind()) {
    case rgd::Read: {
      uint32_t bytes = node.bits() / 8;
      if (unlikely(bytes == 0 || bytes > 8 || node.bits() % 8 != 0)) return false;
      if (unlikely(node.index() + bytes > ctx.in_size)) return false;
      for (uint32_t i = 0; i < bytes; ++i)
        ctx.assign.push_back({node.index() + i, (uint8_t)(target >> (i * 8))});
      return true;
    }
    case rgd::Constant:
      // nothing to rewrite; reachable only if it already holds the wanted value
      return node.index() < ctx.c->input_args.size() &&
             (ctx.c->input_args[node.index()].second & i2s_mask(node.bits())) == target;
    case rgd::ZExt: {
      auto const& ch = node.children(0);
      // the extended bits are zero by construction, so a target that sets any
      // of them is simply unreachable
      if (ch.bits() < 64 && (target >> ch.bits()) != 0) return false;
      return i2s_invert(ctx, ch, target, depth + 1);
    }
    case rgd::SExt: {
      auto const& ch = node.children(0);
      int64_t s = i2s_sext(target, node.bits());
      // must be representable in the narrower child, or nothing extends to it
      if (i2s_sext((uint64_t)s, ch.bits()) != s) return false;
      return i2s_invert(ctx, ch, (uint64_t)s, depth + 1);
    }
    case rgd::Extract: {
      // only the extracted window is constrained; hold the rest of the child at
      // whatever it evaluates to now
      auto const& ch = node.children(0);
      if (unlikely(ch.bits() > 64 || node.index() + node.bits() > ch.bits()))
        return false;
      uint64_t cur = 0;
      if (!i2s_eval_int(ctx, ch, cur, depth + 1)) return false;
      uint64_t win = i2s_mask(node.bits()) << node.index();
      return i2s_invert(ctx, ch, (cur & ~win) | (target << node.index()), depth + 1);
    }
    case rgd::Concat: {
      auto const& lo = node.children(0);
      auto const& hi = node.children(1);
      if (unlikely(lo.bits() >= 64)) return false;
      size_t mark = ctx.assign.size();
      if (!i2s_invert(ctx, lo, target & i2s_mask(lo.bits()), depth + 1) ||
          !i2s_invert(ctx, hi, target >> lo.bits(), depth + 1)) {
        ctx.assign.resize(mark);
        return false;
      }
      return true;
    }
    case rgd::TLookup: {
      // Scan the table for an entry equal to the wanted output and drive the
      // index expression to its position.  Tables are routinely non-injective
      // (a dehex table maps both '0'..'9' and 'a'..'f' onto 0..15), so try each
      // matching entry in turn and keep the first whose index actually inverts.
      // The re-evaluation matters: inverting through a bitwise op is a guess.
      if (unlikely(node.index() >= ctx.c->input_args.size())) return false;
      uint64_t num_elems = ctx.c->input_args[node.index()].second;
      for (uint64_t i = 0; i < num_elems; ++i) {
        uint64_t elem = 0;
        if (!i2s_table_elem(ctx, node, i, elem)) return false;
        if (elem != target) continue;
        size_t mark = ctx.assign.size();
        if (i2s_invert(ctx, node.children(0), i, depth + 1)) {
          uint64_t check = 0;
          if (i2s_eval_int(ctx, node.children(0), check, depth + 1) && check == i)
            return true;
        }
        ctx.assign.resize(mark);
      }
      return false;
    }
    case rgd::BitReverse:
      // its own inverse, and it determines every bit of its operand, so this is
      // exact rather than a guess: reverse the target and push it down
      return i2s_invert(ctx, node.children(0),
                        i2s_bitrev(target, node.bits()), depth + 1);
    default: break;
  }
  if (!isBinaryOperation(node.kind())) return false;

  // Binary operation.  With one Constant child there is a single way down, and
  // _get_binop_value_r is an exact inverse for most kinds.  With two symbolic
  // children -- the (dehex[a] << 4) + dehex[b] shape -- neither side is fixed,
  // so pin one at the value it takes under the current input and invert the
  // other as if that were the constant; try both orders.  Pinning is only valid
  // while the pinned side's bytes stay put, which is exactly what the
  // re-evaluation at the bottom of the loop checks.
  auto const& l = node.children(0);
  auto const& r = node.children(1);
  const AstNode *sym[2] = {nullptr, nullptr};
  bool sym_is_rhs[2] = {false, false};
  size_t n_try = 0;
  if (l.kind() == rgd::Constant) {
    sym[n_try] = &r; sym_is_rhs[n_try] = true; n_try++;
  } else if (r.kind() == rgd::Constant) {
    sym[n_try] = &l; sym_is_rhs[n_try] = false; n_try++;
  } else {
    sym[0] = &l; sym_is_rhs[0] = false;
    sym[1] = &r; sym_is_rhs[1] = true;
    n_try = 2;
  }
  std::vector<uint64_t> domain;
  for (size_t k = 0; k < n_try; ++k) {
    auto const& other = sym_is_rhs[k] ? l : r;
    uint64_t other_cur = 0, cur = 0;
    if (!i2s_eval_int(ctx, other, other_cur, depth + 1)) continue;
    // the symbolic side's present value, so that an operation which does not
    // determine all of its operand's bits can carry the rest over unchanged
    if (!i2s_eval_int(ctx, *sym[k], cur, depth + 1)) continue;
    if (other.kind() == rgd::Constant) domain.assign(1, other_cur);
    else i2s_value_domain(ctx, other, other_cur, domain, depth + 1);
    for (uint64_t const_op : domain) {
      uint64_t want = 0;
      if (!i2s_binop_invert(node.kind(), sym_is_rhs[k], const_op, target, cur,
                            node.bits(), want))
        continue;
      size_t mark = ctx.assign.size();
      // A pin at a value the operand does not already hold has to be made true,
      // not just assumed -- drive that side first, then the other.  The two can
      // land on the same input byte, which is what the whole-node re-evaluation
      // below is here to catch.
      bool pinned = const_op == other_cur ||
                    i2s_invert(ctx, other, const_op, depth + 1);
      if (pinned && i2s_invert(ctx, *sym[k], want, depth + 1)) {
        uint64_t check = 0;
        if (i2s_eval_int(ctx, node, check, depth) &&
            (check & i2s_mask(node.bits())) == target)
          return true;
      }
      ctx.assign.resize(mark);
    }
  }
  return false;
}

// Walk a Concat spine, handing each leaf the slice of `target` it covers.
// `bit_off` is the leaf's position within the buffer, low bits first: byte 0 of
// a memcmp target is the low end, the same convention the direct path in
// solve_memcmp writes with.  The whole spine is split here rather than in
// i2s_invert because every level would otherwise eat one of that walk's depth
// budget, and a 16-element buffer is 15 levels deep before any real expression
// begins.
//
// With invert=false this only re-evaluates and compares, which is how the whole
// candidate is verified once every leaf has been written -- leaves are inverted
// independently, so two of them sharing an input byte can only be caught at the
// end.
static bool i2s_walk_wide(i2s_ctx &ctx, const AstNode &n_, const uint8_t *target,
                          size_t target_size, size_t bit_off, bool invert,
                          uint32_t depth) {
  if (unlikely(depth > kI2SMaxWideDepth)) return false;
  const AstNode *np = i2s_resolve(ctx, n_);
  if (unlikely(np == nullptr)) return false;
  auto const& node = *np;
  if (unlikely(node.bits() == 0 || node.bits() % 8 != 0)) return false;
  if (node.kind() == rgd::Concat) {
    auto const& lo = node.children(0);
    return i2s_walk_wide(ctx, lo, target, target_size, bit_off, invert, depth + 1) &&
           i2s_walk_wide(ctx, node.children(1), target, target_size,
                         bit_off + lo.bits(), invert, depth + 1);
  }
  if (unlikely(bit_off % 8 != 0)) return false;
  // A contiguous read wider than 64 bits is NOT a Concat spine -- the parser
  // emits one Read whose bits are the byte count times eight -- so it needs a
  // base case of its own or it falls off the width test below and the whole
  // walk declines.  The split is exact rather than a guess: byte i of the read
  // is input byte index() + i, in the same low-end-first order `target` uses.
  if (node.bits() > 64 && node.kind() == rgd::Read) {
    size_t byte_off = bit_off / 8;
    size_t n = node.bits() / 8;
    if (unlikely(byte_off + n > target_size)) return false;
    if (invert) {
      if (unlikely(node.index() + n > ctx.in_size)) return false;
      for (size_t i = 0; i < n; ++i)
        ctx.assign.push_back({node.index() + i, target[byte_off + i]});
      return true;
    }
    bool ok = true;
    for (size_t i = 0; i < n; ++i) {
      if (i2s_peek(ctx, node.index() + i, ok) != target[byte_off + i]) return false;
      if (unlikely(!ok)) return false;
    }
    return true;
  }
  if (unlikely(node.bits() > 64)) return false;
  size_t byte_off = bit_off / 8;
  size_t n = node.bits() / 8;
  if (unlikely(byte_off + n > target_size)) return false;
  uint64_t want = 0;
  for (size_t i = 0; i < n; ++i)
    want |= (uint64_t)target[byte_off + i] << (i * 8);
  if (invert)
    return i2s_invert(ctx, node, want, 0);
  uint64_t got = 0;
  return i2s_eval_int(ctx, node, got, 0) && got == want;
}

// already be masked to `bits`.
static bool i2s_eval_icmp(uint32_t comparison, uint64_t a, uint64_t b,
                          uint32_t bits) {
  int64_t sa = i2s_sext(a, bits), sb = i2s_sext(b, bits);
  switch (comparison) {
    case rgd::Equal:    return a == b;
    case rgd::Distinct: return a != b;
    case rgd::Ult:      return a < b;
    case rgd::Ule:      return a <= b;
    case rgd::Ugt:      return a > b;
    case rgd::Uge:      return a >= b;
    case rgd::Slt:      return sa < sb;
    case rgd::Sle:      return sa <= sb;
    case rgd::Sgt:      return sa > sb;
    case rgd::Sge:      return sa >= sb;
    default:            return false;
  }
}

I2SSolver::I2SSolver(): matches(0), mismatches(0) {
  binop_mask.set(rgd::Add);
  binop_mask.set(rgd::Sub);
  binop_mask.set(rgd::Mul);
  binop_mask.set(rgd::UDiv);
  binop_mask.set(rgd::SDiv);
  binop_mask.set(rgd::URem);
  binop_mask.set(rgd::SRem);
  binop_mask.set(rgd::And);
  // binop_mask.set(rgd::Or);
  binop_mask.set(rgd::Xor);
  // binop_mask.set(rgd::Shl);
  binop_mask.set(rgd::LShr);
  binop_mask.set(rgd::AShr);

  // FP ops that input-to-state cannot invert: FRem, FNeg, and all FP casts and
  // intrinsics/libcalls, i.e. [FRem, FpLrint] -- everything from FRem up to (but
  // not including) the first invertible transcendental kind (FpExp).  The FP
  // relational kinds are left out so a direct FCmp (input -> compare against a
  // constant) is not rejected; the invertible FP binops (FAdd/FSub/FMul/FDiv),
  // the transcendentals (FpExp..FpLog1p) and FpPow are also left out so an
  // "f(x) <cmp> K" / "x op C <cmp> K" constraint reaches solve_fcmp.
  for (uint16_t k = rgd::FRem; k < rgd::FpExp; ++k)
    fp_ops_mask.set(k);

  // Invertible FP binops handled by solve_fcmp's arith fallback: [FAdd, FRem)
  // plus FpPow (binary, one constant operand).
  for (uint16_t k = rgd::FAdd; k < rgd::FRem; ++k)
    fp_arith_mask.set(k);
  fp_arith_mask.set(rgd::FpPow);

  // Invertible unary FP transcendentals handled by solve_fcmp: [FpExp, FpPow).
  for (uint16_t k = rgd::FpExp; k < rgd::FpPow; ++k)
    fp_trans_mask.set(k);
}

solver_result_t
I2SSolver::solve_fcmp(std::shared_ptr<const Constraint> const& c,
                      std::unique_ptr<ConsMeta> const& cm,
                      uint32_t comparison,
                      const uint8_t *in_buf, size_t in_size,
                      uint8_t *out_buf, size_t &out_size) {

  uint32_t predicate = fcmp_predicate(comparison);

  // Same 64-bit ceiling as solve_icmp, and for the same reason: c->op1/op2 are
  // extended to 64 bits by the instrumentation.  It bites harder here, because
  // fp_decode only knows 32- and 64-bit IEEE layouts and returns 0.0 for
  // anything else -- an fp80 or fp128 compare would be "solved" against two
  // zeroes rather than declined.
  auto const& cmp_root = *c->get_root();
  if (cmp_root.children(0).bits() > 64 || cmp_root.children(1).bits() > 64)
    return SOLVER_TIMEOUT;

  // Classify the comparison by AST structure (not by value matching): is one
  // operand produced by a single invertible FP arith op against a constant, or
  // is it a direct compare of an input operand?  Deciding by structure avoids a
  // false "direct" match when an arith result happens to equal the raw input
  // bytes (e.g. 0.0 * C == 0.0 on an all-zero seed).
  auto const& root = *c->get_root();
  auto const& lc = root.children(0);
  auto const& rc = root.children(1);
  const AstNode *arith = nullptr;
  bool arith_is_lhs = false;
  if (isFPArithKind(lc.kind())) { arith = &lc; arith_is_lhs = true; }
  else if (isFPArithKind(rc.kind())) { arith = &rc; arith_is_lhs = false; }
  const AstNode *trans = nullptr;
  bool trans_is_lhs = false;
  if (isFPTransKind(lc.kind())) { trans = &lc; trans_is_lhs = true; }
  else if (isFPTransKind(rc.kind())) { trans = &rc; trans_is_lhs = false; }

  uint16_t arith_kind = 0;
  uint16_t trans_kind = 0;
  uint64_t cst_bits = 0;
  bool const_is_rhs = false;
  // combined set of invertible FP ops (arith incl pow, and transcendentals):
  // i2s can only handle a SINGLE such op that is a direct child of the compare.
  std::bitset<rgd::LastOp> invertible = (fp_arith_mask | fp_trans_mask) & c->ops;
  DEBUGF("i2s fcmp: lc.kind=%u rc.kind=%u arith=%p(lhs=%d) trans=%p invertible.count=%zu "
         "trans_any=%d arith_any=%d ncand=%zu\n",
         lc.kind(), rc.kind(), (void*)arith, arith_is_lhs, (void*)trans,
         invertible.count(), (int)(fp_trans_mask & c->ops).any(),
         (int)(fp_arith_mask & c->ops).any(), cm->i2s_candidates.size());
  if ((fp_trans_mask & c->ops).any()) {
    // f(x) <cmp> K for a unary transcendental f; invert via the libm inverse.
    if (trans == nullptr || invertible.count() != 1) {
      return SOLVER_TIMEOUT;
    }
    trans_kind = trans->kind();
  } else if ((fp_arith_mask & c->ops).any()) {
    // FP arithmetic is involved; i2s can only invert a SINGLE arith op that is a
    // direct child of the comparison and has a constant operand.  Anything else
    // (nested/multiple arith, or two symbolic operands) is left for z3.
    if (arith == nullptr || invertible.count() != 1 ||
        !fp_binop_const(c, *arith, cst_bits, const_is_rhs)) {
      DEBUGF("i2s fcmp: arith branch reject arith=%p count=%zu\n",
             (void*)arith, invertible.count());
      return SOLVER_TIMEOUT;
    }
    arith_kind = arith->kind();
    DEBUGF("i2s fcmp: arith accepted kind=%u cst_bits=0x%lx const_is_rhs=%d\n",
           arith_kind, cst_bits, const_is_rhs);
  }

  // Structural anchor by INPUT OFFSET.  The value-only structural checks below
  // can be fooled when two operands hold coincidentally-equal values.  For
  // example `fa == fb + C` on a seed where fa == fb: feeding fa through `+ C`
  // yields the same value as fb+C, so the fa candidate passes the value check
  // and the inverted result gets written to fa -- the WRONG input.  When the
  // operand we intend to modify is a plain Read, its AST node records the exact
  // input offset it reads (Read::index()); only accept the candidate at that
  // offset.  If the operand is not a plain Read (transformed input, offset not
  // determinable), fall back to the value-only check to preserve behavior.
  auto read_offset = [](const AstNode &n, size_t &off) -> bool {
    if (n.kind() == rgd::Read) { off = n.index(); return true; }
    return false;
  };
  size_t sym_off = 0;
  bool have_sym_off = false;   // arith/trans: offset of the symbolic operand
  if (trans != nullptr) {
    have_sym_off = read_offset(trans->children(0), sym_off);
  } else if (arith != nullptr) {
    have_sym_off = read_offset(arith->children(const_is_rhs ? 0 : 1), sym_off);
  }
  size_t lc_off = 0, rc_off = 0;   // direct compare: offsets of each side
  bool have_lc_off = read_offset(lc, lc_off);
  bool have_rc_off = read_offset(rc, rc_off);

  for (auto const& candidate : cm->i2s_candidates) {
    size_t offset = candidate.first;
    uint32_t bytes = candidate.second;
    // only IEEE single/double are decoded here
    if (bytes != 4 && bytes != 8) {
      continue;
    }
    uint64_t mask = (bytes == 8) ? ~0ULL : 0xffffffffULL;
    uint64_t value = 0;
    memcpy(&value, &in_buf[offset], bytes);
    value &= mask;
    // Every guess below is verified with i2s_eval_fcmp before we claim SAT, so a
    // heuristic guess that does not satisfy the relation (e.g. OGT against the
    // max representable value, or an FP inversion broken by rounding) is skipped
    // and left for z3.
    bool sym_is_lhs;
    uint64_t r = 0;
    if (trans != nullptr) {
      // f(x) <cmp> K -- invert the transcendental to recover x (e.g. exp -> log).
      // anchor: only the input bytes the transcendental actually reads
      if (have_sym_off && offset != sym_off) continue;
      sym_is_lhs = trans_is_lhs;
      double x_in = fp_decode(value, bytes);
      // structural check: confirm these input bytes really produce the recorded
      // transcendental-side operand value (guards against a coincidental match).
      uint64_t fwd_bits = fp_encode(fp_trans_eval(x_in, trans_kind, bytes), bytes) & mask;
      uint64_t trans_side = (sym_is_lhs ? c->op1 : c->op2) & mask;
      if (fwd_bits != trans_side) continue;
      // pick a target for the function *result*, then invert to recover the input.
      double k = fp_decode((sym_is_lhs ? c->op2 : c->op1) & mask, bytes);
      double s = fp_i2s_target(predicate, k, sym_is_lhs, bytes);
      double x_new = fp_trans_invert(s, trans_kind);
      r = fp_encode(x_new, bytes) & mask;
      // verify end-to-end: re-apply the transcendental to the value we would write.
      double res = fp_trans_eval(fp_decode(r, bytes), trans_kind, bytes);
      double a = sym_is_lhs ? res : k;
      double b = sym_is_lhs ? k : res;
      if (!i2s_eval_fcmp(predicate, a, b)) continue;
    } else if (arith != nullptr) {
      // (x op C) <cmp> K -- invert the arith op to recover x, mirroring the
      // integer binop path in solve_icmp.
      // anchor: only the input bytes the arith's symbolic operand actually reads
      if (have_sym_off && offset != sym_off) continue;
      sym_is_lhs = arith_is_lhs;
      double x_in = fp_decode(value, bytes);
      double cst = fp_decode(cst_bits & mask, bytes);
      // structural check: confirm these input bytes really produce the recorded
      // arith-side operand value (guards against a coincidental offset match).
      uint64_t fwd_bits =
          fp_encode(fp_binop_eval(x_in, cst, arith_kind, const_is_rhs, bytes), bytes) & mask;
      uint64_t arith_side = (sym_is_lhs ? c->op1 : c->op2) & mask;
      DEBUGF("i2s fcmp arith cand off=%zu bytes=%u x_in=%g cst=%g fwd=0x%lx arith_side=0x%lx\n",
             offset, bytes, x_in, cst, fwd_bits, arith_side);
      if (fwd_bits != arith_side) continue;
      // pick a target for the arith *result*, then invert to recover the input.
      double k = fp_decode((sym_is_lhs ? c->op2 : c->op1) & mask, bytes);
      double s = fp_i2s_target(predicate, k, sym_is_lhs, bytes);
      double x_new = fp_binop_invert(s, cst, arith_kind, const_is_rhs);
      r = fp_encode(x_new, bytes) & mask;
      // verify end-to-end: re-apply the arith op to the value we would write.
      double res = fp_binop_eval(fp_decode(r, bytes), cst, arith_kind, const_is_rhs, bytes);
      double a = sym_is_lhs ? res : k;
      double b = sym_is_lhs ? k : res;
      if (!i2s_eval_fcmp(predicate, a, b)) continue;
    } else {
      // direct FCmp: the input bytes are one of the comparison operands, and the
      // other is the concrete constant we compare against.  Anchor to the Read
      // offset of each side (when it is a plain Read) so an unrelated candidate
      // that merely holds the same value is not mistaken for the operand.
      uint64_t const_bits;
      if ((c->op1 & mask) == value && (!have_lc_off || offset == lc_off)) {
        sym_is_lhs = true;
        const_bits = c->op2 & mask;
      } else if ((c->op2 & mask) == value && (!have_rc_off || offset == rc_off)) {
        sym_is_lhs = false;
        const_bits = c->op1 & mask;
      } else {
        continue; // input does not feed this comparison directly
      }
      double k = fp_decode(const_bits, bytes);
      double s = fp_i2s_target(predicate, k, sym_is_lhs, bytes);
      r = fp_encode(s, bytes) & mask;
      double sv = fp_decode(r, bytes); // re-decode: verify the exact stored value
      double a = sym_is_lhs ? sv : k;
      double b = sym_is_lhs ? k : sv;
      if (!i2s_eval_fcmp(predicate, a, b)) continue;
    }
    DEBUGF("i2s: fcmp pred %u @ %lu (%u bytes) sym_lhs=%d -> 0x%lx\n",
           predicate, offset, bytes, sym_is_lhs, r);
    if (out_size == 0) memcpy(out_buf, in_buf, in_size); // make a copy
    out_size = in_size;
    memcpy(&out_buf[offset], &r, bytes);
    matches++;
    return SOLVER_SAT;
  }
  return SOLVER_TIMEOUT;
}

solver_result_t
I2SSolver::solve_icmp(std::shared_ptr<const Constraint> const& c,
                      std::unique_ptr<ConsMeta> const& cm,
                      uint32_t comparison,
                      const uint8_t *in_buf, size_t in_size,
                      uint8_t *out_buf, size_t &out_size) {

  uint64_t value = 0, value_r = 0;
  uint64_t r = 0;
  // c->op1 and c->op2 are the operand values the trace recorded, and the
  // instrumentation extends them to 64 bits -- so for a comparison wider than
  // that they hold only the LOW half.  Every match below compares them against
  // reassembled input bytes, and a match on the low half of a 128-bit operand
  // says nothing about the high half: the value written back would satisfy 64
  // bits of a 128-bit constraint.  Decline; the recursive helpers already stop
  // at 64 bits (i2s_eval_int, i2s_invert), this is the entry that does not.
  //
  // This is a limit of the *traced value* transport, NOT of input-to-state.
  // solve_memcmp_ast does width-agnostic i2s: it assembles the wanted bytes
  // from consecutive input_args slots and matches them through i2s_walk_wide,
  // which needs no traced value at all.  A WideConst operand lands in exactly
  // that multi-slot form, so an equality against one routes there instead.
  // Only equality: get_i2s_value, which is what turns a relation into a wanted
  // value, is uint64 and has no wide counterpart.
  if (c->get_root()->children(0).bits() > 64 ||
      c->get_root()->children(1).bits() > 64) {
    if (comparison == rgd::Equal)
      return solve_memcmp_ast(c, in_buf, in_size, out_buf, out_size);
    return SOLVER_TIMEOUT;
  }
  // Structural anchor by INPUT OFFSET (mirrors solve_fcmp).  The value-only
  // direct-match checks below can be fooled when two symbolic operands hold
  // coincidentally-equal values (e.g. `b + 1 == a` on a seed where a == b): the
  // b candidate's raw bytes equal op2's value, so op2's inverted result would be
  // written to b -- the WRONG input.  When a compared side is a plain Read, its
  // AST node records the exact input offset it reads (Read::index()); only accept
  // a direct match at that offset.  When a side is not a plain Read (e.g. a binop,
  // handled structurally by the binop branch below), fall back to the value check.
  auto const& root = *c->get_root();
  auto const& lc = root.children(0);
  auto const& rc = root.children(1);
  auto read_offset = [](const AstNode &n, size_t &off) -> bool {
    if (n.kind() == rgd::Read) { off = n.index(); return true; }
    return false;
  };
  size_t lc_off = 0, rc_off = 0;
  bool have_lc_off = read_offset(lc, lc_off);
  bool have_rc_off = read_offset(rc, rc_off);
  // A bit-reversed side is a trap for the value match specifically because the
  // reversal is an involution.  A palindromic byte -- 0x24, 0x18, 0x81, and 14
  // others -- reverses to itself, so the compared value IS the input byte it
  // came from, the match fires as if the side were a plain Read, and the
  // replacement gets written without being reversed.  A confident wrong answer,
  // not a miss.  Exclude the shape and let it fall through to the AST walk,
  // which pushes the target down through the reversal and then verifies.
  // (Only bitreverse is special-cased here.  The value match is a one-sample
  // guess and any non-Read side can mislead it -- bswap has the same
  // involution trap, through its Extract/Concat decomposition -- but checking
  // every candidate is a change to every integer target, not to this op.)
  auto through_casts = [](const AstNode &n) -> const AstNode * {
    const AstNode *p = &n;
    for (int i = 0; i < 4 && p->children_size() == 1; ++i) {
      switch (p->kind()) {
        case rgd::ZExt: case rgd::SExt: case rgd::Extract:
          p = &p->children(0);
          continue;
        default: return p;
      }
    }
    return p;
  };
  bool lc_reversed = through_casts(lc)->kind() == rgd::BitReverse;
  bool rc_reversed = through_casts(rc)->kind() == rgd::BitReverse;
  for (auto const& candidate : cm->i2s_candidates) {
    size_t offset = candidate.first;
    uint32_t bytes = candidate.second;
    if (bytes > 8) {
      // FIXME: support larger int size
      continue;
    }
    auto atoi = c->atoi_info.find(offset);
    if (likely(atoi == c->atoi_info.end())) {
      // size can be not a power of 2
      memcpy(&value, &in_buf[offset], bytes);
      value_r = SWAP64(value) >> (64 - bytes * 8);
      DEBUGF("i2s: try %lu, length %u = 0x%016lx, 0x%016lx, comparison = %d\n",
          offset, bytes, value, value_r, comparison);
      if (!lc_reversed && c->op1 == value && (!have_lc_off || offset == lc_off)) {
        matches++;
        r = get_i2s_value(comparison, c->op2, false);
      } else if (!rc_reversed && c->op2 == value && (!have_rc_off || offset == rc_off)) {
        matches++;
        r = get_i2s_value(comparison, c->op1, true);
      } else if (!lc_reversed && c->op1 == value_r && (!have_lc_off || offset == lc_off)) {
        matches++;
        r = get_i2s_value(comparison, c->op2, false);
        r = SWAP64(r) >> (64 - bytes * 8);
      } else if (!rc_reversed && c->op2 == value_r && (!have_rc_off || offset == rc_off)) {
        matches++;
        r = get_i2s_value(comparison, c->op1, true);
        r = SWAP64(r) >> (64 - bytes * 8);
      } else if ((binop_mask & c->ops).count() == 1) {
        // try some simple binary operations
        auto &left = c->get_root()->children(0);
        auto &right = c->get_root()->children(1);
        uint64_t const_op = 0;
        uint64_t mask = (1ULL << (bytes * 8)) - 1;
        uint16_t kind = 0;
        // true if the input is on the right hand side of the comparison
        bool rhs = false;
        // true if the input is on the right hand side of the binary operation
        // NOTE, not the right hand side of the comparison
        bool bop_rhs = false;
        // check reverse too
        bool is_reversed = false;
        // check if lhs of the comparison is a simple binary operation with a constant
        if (isBinaryOperation(left.kind())) {
          r = get_binop_value(c, left, value, const_op, bop_rhs);
          r &= mask; // mask the result to avoid overflow
          DEBUGF("i2s: binop (lhs) %lx (%d) %lx = %lx =? %lx\n", value, left.kind(), const_op, r, c->op1);
          if (r == c->op1) {
            // binop result matches op1 of the comparison
            kind = left.kind();
            rhs = false;
          } else {
            // check value_r
            r = get_binop_value(c, left, value_r, const_op, bop_rhs);
            r &= mask; // mask the result to avoid overflow
            DEBUGF("i2s: binop (lhs) %lx (%d) %lx = %lx =? %lx\n", value_r, left.kind(), const_op, r, c->op1);
            if (r == c->op1) {
              kind = left.kind();
              rhs = false;
              is_reversed = true;
            } else {
              const_op = 0;
            }
          }
        }
        if (isBinaryOperation(right.kind())) {
          r = get_binop_value(c, right, value, const_op, bop_rhs);
          r &= mask; // mask the result to avoid overflow
          DEBUGF("i2s: binop (rhs) %lx (%d) %lx = %lx =? %lx\n", value, right.kind(), const_op, r, c->op2);
          if (r == c->op2) {
            // binop result matches op2 of the comparison
            kind = right.kind();
            rhs = true;
          } else {
            // check value_r
            r = get_binop_value(c, right, value_r, const_op, bop_rhs);
            r &= mask; // mask the result to avoid overflow
            DEBUGF("i2s: binop (lhs) %lx (%d) %lx = %lx =? %lx\n", value_r, left.kind(), const_op, r, c->op1);
            if (r == c->op2) {
              kind = right.kind();
              rhs = true;
              is_reversed = true;
            } else {
              const_op = 0;
            }
          }
        }
        if (const_op == 0) {
          continue; // nothing matches next offset
        }
        matches++;
        // get the expected value
        r = get_i2s_value(comparison, rhs ? c->op1 : c->op2, rhs);
        // apply the diff
        r = _get_binop_value_r(r, const_op, kind, bop_rhs);
        r &= mask; // mask the result to avoid overflow
        // reverse the result if necessary
        if (is_reversed) {
          r = SWAP64(r) >> (64 - bytes * 8);
        }
      } else {
        continue; // next offset
      }
      DEBUGF("i2s: %lu = 0x%lx\n", offset, r);
      if (out_size == 0) memcpy(out_buf, in_buf, in_size); // make a copy
      out_size = in_size;
      memcpy(&out_buf[offset], &r, bytes);
      return SOLVER_SAT;
    } else {
      // atoi
      uint32_t base = std::get<1>(atoi->second);
      uint32_t old_len = std::get<2>(atoi->second);
      DEBUGF("i2s: try atoi %lu, base %u, old_len %u\n", offset, base, old_len);
      long num = 0;
      unsigned long unum = 0;
      bool is_signed = false;
      if (old_len > 0) {
        char buf[old_len + 1];
        memcpy(buf, &in_buf[offset], old_len);
        buf[old_len] = 0;
        is_signed = (buf[0] == '-');
        unum = strtoul(buf, NULL, base); // all operands are unsgined in symsan
      }
      if (c->op1 == unum) {
        matches++;
        r = get_i2s_value(comparison, c->op2, false);
      } else if (c->op2 == unum) {
        matches++;
        r = get_i2s_value(comparison, c->op1, true);
      } else {
        continue; // next offset
      }
      DEBUGF("i2s-atoi: %lu = %lx\n", offset, r);
      const char *format = nullptr;
      switch (base) {
        case 2: format = "%lb"; break;
        case 8: format = "%lo"; break;
        case 10: format = is_signed ? "%ld" : "%lu"; break;
        case 16: format = "%lx"; break;
        default: {
          WARNF("unsupported base %d\n", base);
          continue;
        }
      }
      const size_t max_len = 64; // FIXME: make configurable?
      char *saved = nullptr;
      size_t copy_len = in_size - offset - old_len;
      if (out_size == 0) {
        memcpy(out_buf, in_buf, offset);
      } else {
        copy_len = out_size - offset - old_len;
        saved = (char*)malloc(copy_len);
        memcpy(saved, (char*)out_buf + offset + old_len, copy_len);
      }
      // extend size as in cmplog
      size_t num_len;
      if (is_signed) {
        num_len = snprintf((char*)out_buf + offset, max_len, format, (long)r);
      } else {
        num_len = snprintf((char*)out_buf + offset, max_len, format, r);
      }
      if (out_size == 0) {
        memcpy(out_buf + offset + num_len, in_buf + offset + old_len, copy_len);
        out_size = in_size + num_len - old_len;
      } else {
        memcpy((char*)out_buf + offset + num_len, saved, copy_len);
        free(saved);
        out_size += num_len - old_len;
      }
      return SOLVER_SAT;
    }
  }
  // No offset in the input holds the compared value (or its byte-reverse), and
  // no single binop under the comparison explains one.  Fall back to walking
  // the AST, which is the only route to a table lookup -- whose output is never
  // in the input -- or to nested arithmetic.  Placed after the loop rather than
  // inside it so nothing above changes behaviour.
  return solve_ast(c, comparison, in_buf, in_size, out_buf, out_size);
}

solver_result_t
I2SSolver::solve_ast(std::shared_ptr<const Constraint> const& c,
                     uint32_t comparison,
                     const uint8_t *in_buf, size_t in_size,
                     uint8_t *out_buf, size_t &out_size) {

  auto const& root = *c->get_root();
  if (unlikely(root.children_size() != 2)) return SOLVER_TIMEOUT;
  auto const& lc = root.children(0);
  auto const& rc = root.children(1);
  uint32_t bits = lc.bits();
  if (unlikely(bits == 0 || bits > 64 || rc.bits() != bits)) return SOLVER_TIMEOUT;

  DEBUGF("i2s: try ast, comparison = %u, bits = %u\n", comparison, bits);

  i2s_ctx ctx{c, in_buf, in_size, {}, {}, kI2SMaxSteps};
  i2s_index_nodes(root, ctx.nodes, 0);
  // Try each side as the one to rewrite: pin the other at the value it takes
  // under the current input, aim for whatever makes the comparison hold, and
  // push that down the AST.
  for (int side = 0; side < 2; ++side) {
    auto const& sym = side == 0 ? lc : rc;
    auto const& fixed = side == 0 ? rc : lc;
    if (sym.kind() == rgd::Constant) continue;
    ctx.assign.clear();
    uint64_t pinned = 0;
    if (!i2s_eval_int(ctx, fixed, pinned, 0)) continue;
    // get_i2s_value's rhs argument means "the rewritten side is the right hand
    // side of the comparison", so it is side != 0 here
    uint64_t target =
        get_i2s_value(comparison, pinned & i2s_mask(bits), side != 0) & i2s_mask(bits);
    if (!i2s_invert(ctx, sym, target, 0)) continue;
    // Verify.  Everything above may have guessed, so re-evaluate BOTH sides
    // under the candidate and check the relation really holds -- the pinned
    // side included, since inverting the other one may have moved bytes it
    // reads.
    uint64_t a = 0, b = 0;
    if (!i2s_eval_int(ctx, lc, a, 0)) continue;
    if (!i2s_eval_int(ctx, rc, b, 0)) continue;
    if (!i2s_eval_icmp(comparison, a & i2s_mask(bits), b & i2s_mask(bits), bits))
      continue;
    matches++;
    if (out_size == 0) memcpy(out_buf, in_buf, in_size); // make a copy
    out_size = in_size;
    for (auto const& kv : ctx.assign) {
      if (likely(kv.first < in_size)) out_buf[kv.first] = (uint8_t)kv.second;
      DEBUGF("i2s-ast: %zu = 0x%02x\n", kv.first, kv.second);
    }
    return SOLVER_SAT;
  }
  return SOLVER_TIMEOUT;
}

solver_result_t
I2SSolver::solve_memcmp_ast(std::shared_ptr<const Constraint> const& c,
                            const uint8_t *in_buf, size_t in_size,
                            uint8_t *out_buf, size_t &out_size) {

  auto const& root = *c->get_root();
  if (unlikely(root.children_size() != 2)) return SOLVER_TIMEOUT;
  // Same restriction as the value-based path: only const-against-symbolic.
  // Which child holds the constant is fixed for a memcmp root but not for an
  // ICmp one -- __taint_union swaps the operands of a commutative op to order
  // the labels, so a wide equality can arrive either way round.
  bool const_first = root.children(0).kind() == rgd::Constant;
  auto const& want_node = const_first ? root.children(0) : root.children(1);
  auto const& sym = const_first ? root.children(1) : root.children(0);
  if (want_node.kind() != rgd::Constant) return SOLVER_TIMEOUT;
  uint32_t bits = sym.bits();
  if (unlikely(bits == 0 || bits % 8 != 0 || want_node.bits() != bits))
    return SOLVER_TIMEOUT;
  size_t nbytes = bits / 8;

  DEBUGF("i2s: try memcmp ast, %zu bytes\n", nbytes);

  // unpack the memcmp target: 8 bytes per constant arg, little-endian, in
  // increasing address order (parsers/rgd-parser.cpp packs it that way)
  uint32_t base = want_node.index();
  std::vector<uint8_t> want(nbytes);
  for (size_t i = 0; i < nbytes; ++i) {
    size_t arg = base + i / 8;
    if (unlikely(arg >= c->input_args.size())) return SOLVER_TIMEOUT;
    want[i] = (uint8_t)(c->input_args[arg].second >> ((i % 8) * 8));
  }

  i2s_ctx ctx{c, in_buf, in_size, {}, {}, kI2SMaxSteps};
  i2s_index_nodes(root, ctx.nodes, 0);
  if (!i2s_walk_wide(ctx, sym, want.data(), nbytes, 0, /*invert=*/true, 0))
    return SOLVER_TIMEOUT;
  if (!i2s_walk_wide(ctx, sym, want.data(), nbytes, 0, /*invert=*/false, 0))
    return SOLVER_TIMEOUT;

  matches++;
  if (out_size == 0) memcpy(out_buf, in_buf, in_size); // make a copy
  out_size = in_size;
  for (auto const& kv : ctx.assign) {
    if (likely(kv.first < in_size)) out_buf[kv.first] = (uint8_t)kv.second;
    DEBUGF("i2s-memcmp-ast: %zu = 0x%02x\n", kv.first, kv.second);
  }
  return SOLVER_SAT;
}

solver_result_t
I2SSolver::solve_memcmp(std::shared_ptr<const Constraint> const& c,
                        std::unique_ptr<ConsMeta> const& cm,
                        const uint8_t *in_buf, size_t in_size,
                        uint8_t *out_buf, size_t &out_size) {

  DEBUGF("i2s: try memcmp\n");

  size_t const_index = 0;
  for (auto const& arg : c->input_args) {
    if (!arg.first) break; // first constant arg
    const_index++;
  }
  if (const_index == c->input_args.size()) {
    // FIXME: only do memcmp(const, symbolic)
    mismatches++;
    return SOLVER_TIMEOUT;
  }
  if (cm->i2s_candidates.size() != 1) {
    // FIXME: only support single i2s candidate
    // The AST walk has no such restriction: it writes wherever the Read leaves
    // say, so scattered input bytes are fine.
    return solve_memcmp_ast(c, in_buf, in_size, out_buf, out_size);
  }
  size_t offset = cm->i2s_candidates[0].first;
  uint32_t size = cm->i2s_candidates[0].second;
  if (size != c->local_map.size()) {
    WARNF("input size mismatch\n");
    return solve_memcmp_ast(c, in_buf, in_size, out_buf, out_size);
  }
  // make a copy of the input if not already
  if (out_size == 0) memcpy(out_buf, in_buf, in_size);
  uint64_t value = 0;
  int i = 0;
  auto &right = c->get_root()->children(1);
  if (likely(right.kind() == rgd::Read)) {
    // the memcmp argument is directly from input
    for (size_t o = offset; o < offset + size; o++) {
      if (i == 0)
        value = c->input_args[const_index].second;
      uint8_t v = ((value >> i) & 0xff);
      out_buf[o] = v;
      DEBUGF("  %lu = %u\n", o, v);
      i += 8;
      if (i == 64) {
        const_index++; // move on to the next 64-bit chunk
        i = 0;
      }
    }
    out_size = in_size;
    return SOLVER_SAT;
  } else {
    // there could be transformations on the input
    //
    // Try the AST walk first.  Its answer is verified byte by byte, while the
    // one-sample guesses below are inferred from a single input/output pair and
    // can return a confident wrong answer: a `% 16` in the encoder puts SRem in
    // c->ops, and _get_binop_value_r reverses SRem-with-a-constant-divisor as
    // the identity, so the guess degenerates into copying the memcmp target
    // straight into the input.  Fall through to them only if the AST is not
    // enough (an encoding built from ops the walk does not model).
    if (solve_memcmp_ast(c, in_buf, in_size, out_buf, out_size) == SOLVER_SAT)
      return SOLVER_SAT;
    auto *info = __dfsan::get_label_info(c->get_root()->label());
    uint64_t sample = info->op2.i;
    uint16_t sample_len = info->size > 8 ? 8 : info->size;
    uint8_t sample_buf[sample_len];
    memcpy(sample_buf, &sample, sample_len);
#if DEBUG
    memcpy(&value, &in_buf[offset], size > 8 ? 8 : size);
    DEBUGF("i2s: memcmp encoded: %016lx => %016lx\n", value, sample);
#endif
    uint8_t encode_val = 0, touppwer = 0, tolower = 0;

    // we only have one sample, so we cannot to reliable guessing purely
    // based on input-output pairs, instead, we leverage the symbolic AST
    // to guide the guessing
    uint16_t kind = 0;
    for (uint16_t i = rgd::Add; i < rgd::Shl; ++i) {
      if (i == rgd::Not || i == rgd::Neg || i == rgd::And || i == rgd::Or)
        continue; // we cannot reverse bitwise And and Or
      if (c->ops.test(i)) {
        if (kind != 0) {
          kind = 0;
          break;
        } else {
          kind = i;
        }
      }
    }
    if (kind != 0) {
      // XXX: always assumes const_op is the rhs?
      encode_val = (uint8_t)_get_binop_value_r(sample_buf[0], in_buf[offset], kind, false);
    } else {
      for (auto i = 0; i < sample_len; ++i) {
        // check simple encoding
        tolower = ((in_buf[offset + i] | 0x20) == sample_buf[i]) ? 1 : 0;
        touppwer = ((in_buf[offset + i] & 0x5f) == sample_buf[i]) ? 1 : 0;
      }
    }

    if (encode_val) {
      DEBUGF("i2s: memcmp try encode val = %02x, op = %d\n", encode_val, kind);
      for (size_t o = offset; o < offset + size; o++) {
        if (i == 0)
          value = c->input_args[const_index].second;
        uint8_t v = ((value >> i) & 0xff);
        out_buf[o] = (uint8_t)_get_binop_value_r(v, encode_val, kind, false);
        DEBUGF("  %lu = %u\n", o, v);
        i += 8;
        if (i == 64) {
          const_index++; // move on to the next 64-bit chunk
          i = 0;
        }
      }
      out_size = in_size;
      return SOLVER_SAT;
    } else if (touppwer) {
      DEBUGF("i2s: memcmp try touppwer\n");
      for (size_t o = offset; o < offset + size; o++) {
        if (i == 0)
          value = c->input_args[const_index].second;
        uint8_t v = ((value >> i) & 0xff);
        out_buf[o] = v | 0x20;
        DEBUGF("  %lu = %u\n", o, v);
        i += 8;
        if (i == 64) {
          const_index++; // move on to the next 64-bit chunk
          i = 0;
        }
      }
      out_size = in_size;
      return SOLVER_SAT;
    } else if (tolower) {
      DEBUGF("i2s: memcmp try tolower\n");
      for (size_t o = offset; o < offset + size; o++) {
        if (i == 0)
          value = c->input_args[const_index].second;
        uint8_t v = ((value >> i) & 0xff);
        out_buf[o] = v & 0x5f;
        DEBUGF("  %lu = %u\n", o, v);
        i += 8;
        if (i == 64) {
          const_index++; // move on to the next 64-bit chunk
          i = 0;
        }
      }
      out_size = in_size;
      return SOLVER_SAT;
    } else {
      // the AST walk was already tried at the top of this branch
      return SOLVER_TIMEOUT;
    }
  }
  return SOLVER_TIMEOUT;
}

solver_result_t
I2SSolver::solve(std::shared_ptr<SearchTask> task,
                 const uint8_t *in_buf, size_t in_size,
                 uint8_t *out_buf, size_t &out_size) {

  // A nested task is not i2s's business.  With SYMSAN_USE_NESTED set, parse_cond
  // builds two tasks per clause: the last branch's constraints on their own, and
  // those plus every constraint sharing their input bytes.  The whole point of
  // the second one is that its constraints must hold *together*, and the loop
  // below does the opposite -- it stacks one rewrite per constraint and reports
  // SAT if any single one matched, so it would confidently emit a buffer in
  // which the last rewrite has stomped the earlier ones.  Leave it to z3, which
  // walks the base_task chain and solves the conjunction properly.
  //
  // SOLVER_TIMEOUT rather than SOLVER_UNSAT: UNSAT sets skip_next and drops the
  // task outright (ConcolicSession::next_solution), which would deny z3 the shot
  // this decline exists to hand it.
  if (task->base_task != nullptr) {
    DEBUGF("i2s: decline nested task\n");
    return SOLVER_TIMEOUT;
  }

  solver_result_t ret = SOLVER_TIMEOUT;
  size_t n = task->size();
  DEBUGF("i2s: new task with %zu constraints\n", n);
  out_size = 0; // use this to indicate whether a copy has been made
  for (size_t i = 0; i < n; ++i) {
    // iterate through all constraints, hoping the stacked mutations would work,
    // instead of destroying each other
    auto const& c = task->constraints(i);
    auto const& cm = task->consmetas(i);
    auto comparison = task->comparisons(i);
    // If the constraint involves an FP op that i2s cannot invert (FP
    // arithmetic, a cast such as FPToSI, or a libcall such as lrint()), the
    // input bytes reach the comparison through that transformation and no
    // longer appear literally in the compared value.  Attempting input-to-state
    // here would copy the constant into the raw FP bytes and yield a bogus
    // "solution"; reject and let z3 handle it.  A direct FCmp (input bytes
    // compared against a constant) sets no bit in fp_ops_mask and is handled
    // below by solve_fcmp.
    if (unlikely((c->ops & fp_ops_mask).any())) {
      DEBUGF("i2s: skip FP-derived constraint\n");
      mismatches++;
      continue;
    }
    if (likely(isRelationalKind(comparison))) {
      if (solve_icmp(c, cm, comparison, in_buf, in_size, out_buf, out_size) == SOLVER_SAT) {
        // be optimistic, as long as there's one match, we should try the output
        ret = SOLVER_SAT;
      } else {
        mismatches++;
      }
    } else if (isFPRelationalKind(comparison)) {
      if (solve_fcmp(c, cm, comparison, in_buf, in_size, out_buf, out_size) == SOLVER_SAT) {
        // be optimistic, as long as there's one match, we should try the output
        ret = SOLVER_SAT;
      } else {
        mismatches++;
      }
    } else if (comparison == rgd::Memcmp) {
      if (solve_memcmp(c, cm, in_buf, in_size, out_buf, out_size) == SOLVER_SAT) {
        // be optimistic, as long as there's one match, we should try the output
        ret = SOLVER_SAT;
      } else {
        mismatches++;
      }
    } else if (comparison == rgd::MemcmpN) {
      DEBUGF("i2s: try memcmpN\n");
      // copy the matching bytes
      if (out_size == 0) memcpy(out_buf, in_buf, in_size);
      size_t offset = cm->i2s_candidates[0].first;
      uint32_t size = cm->i2s_candidates[0].second;
      out_buf[offset] = in_buf[offset] + 8;
      out_size = in_size;
      ret = SOLVER_SAT;
    }
  }

  return ret;
}