#include "dfsan/dfsan.h"

#include "ast.h"
#include "task.h"
#include "union_find.h"
#include "parse-rgd.h"

#include <cmath>
#include <cstring>
#include <unordered_map>

using namespace rgd;

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define DEBUGF(_str...) do { fprintf(stderr, _str); } while (0)
#else
#undef DEBUGF
#define DEBUGF(_str...) do { } while (0)
#endif

#ifndef WARNF
#define WARNF(_str...) do { fprintf(stderr, _str); } while (0)
// #define WARNF(x...) do { \
//     SAYF(cYEL "[!] " cBRI "WARNING: " cRST x); \
//     SAYF(cRST "\n"); \
//   } while (0)
#endif

// REJECT: the WARNF prose, plus a short stable bucket key for the same event.
// The prose carries labels and addresses and is what you read when staring at
// one branch; the key must not, so that two occurrences of one cause land in
// one histogram bucket.  See ASTParser::last_error (include/parse.h).
#define REJECT(_reason, _str...) do { set_error(_reason); WARNF(_str); } while (0)

// REJECT_IF_UNSET: for an outer layer reporting that an *inner* parse failed.
// The inner site already named the cause and is the more specific bucket, so
// this only fills in when nothing did.  Innermost wins -- otherwise a wrapper
// message like "failed to construct task for clause" would overwrite
// "unsupported op strlen (77)" on every single occurrence, which is exactly the
// finding it is there to surface.
#define REJECT_IF_UNSET(_reason, _str...) do {                                 \
    if (last_error().empty()) set_error(_reason);                              \
    WARNF(_str);                                                               \
  } while (0)

// REJECT_OP: same, keyed by opcode.  At the two catch-all sites the op *is* the
// finding, and it is bounded (< LastOp), so it belongs in the key.
#define REJECT_OP(_prefix, _op, _str...) do {                                  \
    char _key[64];                                                             \
    snprintf(_key, sizeof(_key), _prefix " %s (%u)", dfsan_op_name(_op),       \
             (unsigned)((_op) & 0xff));                                        \
    set_error(_key);                                                           \
    WARNF(_str);                                                               \
  } while (0)

#if defined(__GNUC__)
static inline bool (likely)(bool x) { return __builtin_expect((x), true); }
static inline bool (unlikely)(bool x) { return __builtin_expect((x), false); }
#else
static inline bool (likely)(bool x) { return x; }
static inline bool (unlikely)(bool x) { return x; }
#endif

// Saturating add, for the size caches: they sum over children and so can
// overflow on a wide DAG, where a wrapped (tiny) result would look like a
// perfectly reasonable size.
static inline uint32_t sat_add(uint32_t a, uint32_t b) {
  uint32_t r = a + b;
  return r < a ? UINT32_MAX : r;
}

// input_args slots a tlookup's packed table occupies, 8 bytes per slot.
// Computed in 64 bits and clamped because num_elems comes straight off the
// label; do_uta_rel checks the geometry against the cached table, this does
// not (the table may not even have arrived yet).
static inline uint32_t tlookup_arg_slots(const dfsan_label_info *info) {
  uint64_t bytes = info->op2.i * (uint64_t)(info->size / 8);
  uint64_t slots = (bytes + 7) / 8;
  return slots > UINT32_MAX ? UINT32_MAX : (uint32_t)slots;
}

static const std::unordered_map<unsigned, std::pair<unsigned, const char*> > OP_MAP {
  {__dfsan::Extract, {rgd::Extract, "extract"}},
  {__dfsan::Trunc,   {rgd::Extract, "extract"}},
  {__dfsan::Concat,  {rgd::Concat, "concat"}},
  {__dfsan::ZExt,    {rgd::ZExt, "zext"}},
  {__dfsan::SExt,    {rgd::SExt, "sext"}},
  {__dfsan::Add,     {rgd::Add, "add"}},
  {__dfsan::Sub,     {rgd::Sub, "sub"}},
  {__dfsan::Mul,     {rgd::Mul, "mul"}},
  {__dfsan::UDiv,    {rgd::UDiv, "udiv"}},
  {__dfsan::SDiv,    {rgd::SDiv, "sdiv"}},
  {__dfsan::URem,    {rgd::URem, "urem"}},
  {__dfsan::SRem,    {rgd::SRem, "srem"}},
  {__dfsan::Shl,     {rgd::Shl, "shl"}},
  {__dfsan::LShr,    {rgd::LShr, "lshr"}},
  {__dfsan::AShr,    {rgd::AShr, "ashr"}},
  {__dfsan::And,     {rgd::And, "and"}},
  {__dfsan::Or,      {rgd::Or, "or"}},
  {__dfsan::Xor,     {rgd::Xor, "xor"}},
  {__dfsan::bitreverse, {rgd::BitReverse, "bitreverse"}},
  // relational comparisons
#define RELATIONAL_ICMP(cmp) (__dfsan::ICmp | (cmp << 8))
  {RELATIONAL_ICMP(__dfsan::bveq),  {rgd::Equal, "equal"}},
  {RELATIONAL_ICMP(__dfsan::bvneq), {rgd::Distinct, "distinct"}},
  {RELATIONAL_ICMP(__dfsan::bvugt), {rgd::Ugt, "ugt"}},
  {RELATIONAL_ICMP(__dfsan::bvuge), {rgd::Uge, "uge"}},
  {RELATIONAL_ICMP(__dfsan::bvult), {rgd::Ult, "ult"}},
  {RELATIONAL_ICMP(__dfsan::bvule), {rgd::Ule, "ule"}},
  {RELATIONAL_ICMP(__dfsan::bvsgt), {rgd::Sgt, "sgt"}},
  {RELATIONAL_ICMP(__dfsan::bvsge), {rgd::Sge, "sge"}},
  {RELATIONAL_ICMP(__dfsan::bvslt), {rgd::Slt, "slt"}},
  {RELATIONAL_ICMP(__dfsan::bvsle), {rgd::Sle, "sle"}},
#undef RELATIONAL_ICMP
  // floating-point arithmetic (FAdd/FSub/FMul/FDiv/FRem reuse LLVM opcodes)
  {__dfsan::FAdd,    {rgd::FAdd, "fadd"}},
  {__dfsan::FSub,    {rgd::FSub, "fsub"}},
  {__dfsan::FMul,    {rgd::FMul, "fmul"}},
  {__dfsan::FDiv,    {rgd::FDiv, "fdiv"}},
  {__dfsan::FRem,    {rgd::FRem, "frem"}},
  {__dfsan::fp_neg,  {rgd::FNeg, "fneg"}},
  // floating-point casts
  {__dfsan::FPToUI,  {rgd::FpToUi, "fptoui"}},
  {__dfsan::FPToSI,  {rgd::FpToSi, "fptosi"}},
  {__dfsan::UIToFP,  {rgd::UiToFp, "uitofp"}},
  {__dfsan::SIToFP,  {rgd::SiToFp, "sitofp"}},
  {__dfsan::FPTrunc, {rgd::FpTrunc, "fptrunc"}},
  {__dfsan::FPExt,   {rgd::FpExt, "fpext"}},
  // floating-point intrinsics / libcalls
  {__dfsan::fp_fabs,      {rgd::FpFabs, "fabs"}},
  {__dfsan::fp_sqrt,      {rgd::FpSqrt, "sqrt"}},
  {__dfsan::fp_round,     {rgd::FpRound, "fround"}},
  {__dfsan::fp_min,       {rgd::FpMin, "fmin"}},
  {__dfsan::fp_max,       {rgd::FpMax, "fmax"}},
  {__dfsan::fp_copysign,  {rgd::FpCopysign, "copysign"}},
  {__dfsan::fp_is_nan,    {rgd::FpIsNan, "isnan"}},
  {__dfsan::fp_is_inf,    {rgd::FpIsInf, "isinf"}},
  {__dfsan::fp_is_finite, {rgd::FpIsFinite, "isfinite"}},
  {__dfsan::fp_signbit,   {rgd::FpSignbit, "signbit"}},
  {__dfsan::fp_lrint,     {rgd::FpLrint, "lrint"}},
  // floating-point transcendentals (i2s-only: z3/jigsaw reject them)
  {__dfsan::fp_exp,       {rgd::FpExp, "exp"}},
  {__dfsan::fp_exp2,      {rgd::FpExp2, "exp2"}},
  {__dfsan::fp_log,       {rgd::FpLog, "log"}},
  {__dfsan::fp_log2,      {rgd::FpLog2, "log2"}},
  {__dfsan::fp_log10,     {rgd::FpLog10, "log10"}},
  {__dfsan::fp_log1p,     {rgd::FpLog1p, "log1p"}},
  {__dfsan::fp_pow,       {rgd::FpPow, "pow"}},
  // floating-point comparisons (predicate encoded in the high byte, same as ICmp)
#define RELATIONAL_FCMP(cmp) (__dfsan::FCmp | (cmp << 8))
  {RELATIONAL_FCMP(1),  {rgd::FOeq, "foeq"}},
  {RELATIONAL_FCMP(2),  {rgd::FOgt, "fogt"}},
  {RELATIONAL_FCMP(3),  {rgd::FOge, "foge"}},
  {RELATIONAL_FCMP(4),  {rgd::FOlt, "folt"}},
  {RELATIONAL_FCMP(5),  {rgd::FOle, "fole"}},
  {RELATIONAL_FCMP(6),  {rgd::FOne, "fone"}},
  {RELATIONAL_FCMP(7),  {rgd::FOrd, "ford"}},
  {RELATIONAL_FCMP(8),  {rgd::FUno, "funo"}},
  {RELATIONAL_FCMP(9),  {rgd::FUeq, "fueq"}},
  {RELATIONAL_FCMP(10), {rgd::FUgt, "fugt"}},
  {RELATIONAL_FCMP(11), {rgd::FUge, "fuge"}},
  {RELATIONAL_FCMP(12), {rgd::FUlt, "fult"}},
  {RELATIONAL_FCMP(13), {rgd::FUle, "fule"}},
  {RELATIONAL_FCMP(14), {rgd::FUne, "fune"}},
#undef RELATIONAL_FCMP
};

// The string-theory ops (dfsan.h 77-88).  Kept out of OP_MAP because none of
// them goes through the generic child walk below: their operands are not
// uniformly "l1 and l2 as subtrees, concrete side from op1/op2" -- the concrete
// side is a byte array that arrived out of band, and several carry a structural
// selector.  do_uta_str() handles all of them.
//
// PtrToInt is deliberately absent: it is only a string op when its operand is
// one, which takes a look at the operand's label.  See do_uta_rel().
static const std::unordered_map<unsigned, unsigned> STR_OP_MAP {
  {__dfsan::fstrlen,   rgd::StrLen},
  {__dfsan::fstrchr,   rgd::StrChr},
  {__dfsan::fstrrchr,  rgd::StrRChr},
  {__dfsan::fstrstr,   rgd::StrStr},
  {__dfsan::fstrpbrk,  rgd::StrPbrk},
  {__dfsan::fstr_off,  rgd::StrOff},
  {__dfsan::fsubstr,   rgd::SubStr},
  {__dfsan::fstrcat,   rgd::StrCat},
  {__dfsan::fstrcmp,   rgd::StrCmp},
  {__dfsan::fprefixof, rgd::PrefixOf},
  {__dfsan::fsuffixof, rgd::SuffixOf},
  {__dfsan::flength,   rgd::StrLength},
};

// The dfsan opcode as a short name, for the rejection reasons.  Only the low
// byte is looked up: the high byte carries the icmp predicate and the FP
// rounding mode, which would otherwise split one cause across a dozen buckets.
//
// Not folded into OP_MAP above, which is a *supported*-op table -- these two
// callers are the catch-alls for the ops that are not in it.  The LLVM half is
// built from Instruction.def exactly the way runtime/dfsan/dfsan.h builds the
// enum, so the two cannot drift, and a duplicate opcode would fail to compile
// rather than silently shadow.
static const char *dfsan_op_name(uint16_t op) {
  switch (op & 0xff) {
    case __dfsan::Not: return "not";
    case __dfsan::Neg: return "neg";
#define HANDLE_BINARY_INST(num, opcode, Class) case num: return #opcode;
#define HANDLE_MEMORY_INST(num, opcode, Class) case num: return #opcode;
#define HANDLE_CAST_INST(num, opcode, Class) case num: return #opcode;
#define HANDLE_OTHER_INST(num, opcode, Class) case num: return #opcode;
#include "llvm/IR/Instruction.def"
#undef HANDLE_BINARY_INST
#undef HANDLE_MEMORY_INST
#undef HANDLE_CAST_INST
#undef HANDLE_OTHER_INST
    // self-defined (dfsan.h 70-110).  Free and Arg never reach the parser, but
    // naming them costs a line and means an unexpected one reads as itself.
    case __dfsan::Free:         return "free";
    case __dfsan::Extract:      return "extract";
    case __dfsan::Concat:       return "concat";
    case __dfsan::Arg:          return "arg";
    case __dfsan::fmemcmp:      return "memcmp";
    case __dfsan::fsize:        return "fsize";
    case __dfsan::fatoi:        return "atoi";
    case __dfsan::fstrlen:      return "strlen";
    case __dfsan::fstrchr:      return "strchr";
    case __dfsan::fstrrchr:     return "strrchr";
    case __dfsan::fstrstr:      return "strstr";
    case __dfsan::fstrpbrk:     return "strpbrk";
    case __dfsan::fstr_off:     return "str_off";
    case __dfsan::fsubstr:      return "substr";
    case __dfsan::fstrcat:      return "strcat";
    case __dfsan::fstrcmp:      return "strcmp";
    case __dfsan::fprefixof:    return "prefixof";
    case __dfsan::fsuffixof:    return "suffixof";
    case __dfsan::flength:      return "length";
    case __dfsan::fp_neg:       return "fneg";
    case __dfsan::fp_fabs:      return "fabs";
    case __dfsan::fp_sqrt:      return "sqrt";
    case __dfsan::fp_round:     return "fround";
    case __dfsan::fp_min:       return "fmin";
    case __dfsan::fp_max:       return "fmax";
    case __dfsan::fp_copysign:  return "copysign";
    case __dfsan::fp_is_nan:    return "isnan";
    case __dfsan::fp_is_inf:    return "isinf";
    case __dfsan::fp_is_finite: return "isfinite";
    case __dfsan::fp_signbit:   return "signbit";
    case __dfsan::fp_lrint:     return "lrint";
    case __dfsan::fp_exp:       return "exp";
    case __dfsan::fp_exp2:      return "exp2";
    case __dfsan::fp_log:       return "log";
    case __dfsan::fp_log2:      return "log2";
    case __dfsan::fp_log10:     return "log10";
    case __dfsan::fp_log1p:     return "log1p";
    case __dfsan::fp_pow:       return "pow";
    case __dfsan::tlookup:      return "tlookup";
    case __dfsan::bitreverse:   return "bitreverse";
    case __dfsan::WideConst:    return "wideconst";
    default:                    return "unknown";
  }
}

// True when the concrete side of a string op is packed from memcmp_cache_
// rather than read out of op1/op2.  These are the ops backend/fastgen.cpp
// ships content for: exactly one of l1/l2 is CONST_LABEL and info->size is
// that side's byte count.  fstrchr/fstrrchr are here for their haystack; their
// needle is a single char in op2 and is handled separately.
static inline bool str_op_has_content(uint16_t op) {
  switch (op) {
    case __dfsan::fstrchr:
    case __dfsan::fstrrchr:
    case __dfsan::fstrstr:
    case __dfsan::fstrpbrk:
    case __dfsan::fstrcat:
    case __dfsan::fstrcmp:
    case __dfsan::fprefixof:
    case __dfsan::fsuffixof:
      return true;
    default:
      return false;
  }
}

static inline bool is_rel_cmp(uint16_t op, __dfsan::predicate pred) {
  return ((op & 0xff) == __dfsan::ICmp) && ((op >> 8) == pred);
}

static inline bool eval_icmp(uint16_t op, uint64_t op1, uint64_t op2) {
  if ((op & 0xff) == __dfsan::ICmp) {
    switch (op >> 8) {
      case __dfsan::bveq: return op1 == op2;
      case __dfsan::bvneq: return op1 != op2;
      case __dfsan::bvugt: return op1 > op2;
      case __dfsan::bvuge: return op1 >= op2;
      case __dfsan::bvult: return op1 < op2;
      case __dfsan::bvule: return op1 <= op2;
      case __dfsan::bvsgt: return (int64_t)op1 > (int64_t)op2;
      case __dfsan::bvsge: return (int64_t)op1 >= (int64_t)op2;
      case __dfsan::bvslt: return (int64_t)op1 < (int64_t)op2;
      case __dfsan::bvsle: return (int64_t)op1 <= (int64_t)op2;
      default: return false;
    }
  }
  return false;
}

// Decode an IEEE-754 bit pattern into a C double (widening 32-bit floats).
static inline double fp_decode(uint64_t bits_val, uint8_t bits) {
  if (bits == 64) {
    double d; memcpy(&d, &bits_val, sizeof(d)); return d;
  } else if (bits == 32) {
    uint32_t u = (uint32_t)bits_val; float f; memcpy(&f, &u, sizeof(f)); return (double)f;
  }
  // half and other widths: not decoded for concrete evaluation
  return 0.0;
}

// Concrete evaluation of an FCmp given the LLVM predicate (0..15) and the
// IEEE-754 bit patterns of the operands.  Used to constant-fold a fully
// concretized comparison during root discovery (mirrors eval_icmp).
static inline bool eval_fcmp(uint16_t predicate, uint64_t val1, uint64_t val2, uint8_t bits) {
  double a = fp_decode(val1, bits), b = fp_decode(val2, bits);
  bool ord = !(std::isnan(a) || std::isnan(b));
  switch (predicate) {
    case 0:  return false;         // FCMP_FALSE
    case 1:  return ord && a == b; // FCMP_OEQ
    case 2:  return ord && a > b;  // FCMP_OGT
    case 3:  return ord && a >= b; // FCMP_OGE
    case 4:  return ord && a < b;  // FCMP_OLT
    case 5:  return ord && a <= b; // FCMP_OLE
    case 6:  return ord && a != b; // FCMP_ONE
    case 7:  return ord;           // FCMP_ORD
    case 8:  return !ord;          // FCMP_UNO
    case 9:  return !ord || a == b; // FCMP_UEQ
    case 10: return !ord || a > b;  // FCMP_UGT
    case 11: return !ord || a >= b; // FCMP_UGE
    case 12: return !ord || a < b;  // FCMP_ULT
    case 13: return !ord || a <= b; // FCMP_ULE
    case 14: return !ord || a != b; // FCMP_UNE
    case 15: return true;           // FCMP_TRUE
    default: return false;
  }
}

static void printAst(FILE* f, const rgd::AstNode *node, int indent) {
  fprintf(f, "(%s, ", rgd::AstKindName[node->kind()]);
  fprintf(f, "%d, ", node->label());
  fprintf(f, "%d, ", node->bits());
  for(int i = 0; i < node->children_size(); i++) {
    printAst(f, &node->children(i), indent + 1);
    if (i != node->children_size() - 1) {
      fprintf(f, ", ");
    }
  }
  fprintf(f, ")\n");
}

int RGDAstParser::restart(std::vector<symsan::input_t> &inputs, bool copy_input) {
  // save a copy of the inputs
  inputs_cache = inputs;
  // clear caches
  memcmp_cache_.clear(); // inherited from ASTParser
  table_cache_.clear();  // ditto; both overrides skip ASTParser::restart
  root_expr_cache.clear();
  constraint_cache.clear();
  ast_size_cache.clear();
  arg_size_cache.clear(); // filled in lockstep with ast_size_cache
  nested_cmp_cache.clear();
  concretize_node.clear();
  branch_to_inputs.clear();

  // reset data-flow dependencies
  input_size_ = 0;
  for (auto &i: inputs) {
    input_size_ += i.second;
  }
  data_flow_deps.reset(input_size_);
  for (auto &s: input_to_branches) {
    s.clear();
  }
  input_to_branches.resize(input_size_);

  return 0;
}

uint32_t RGDAstParser::map_arg(uint32_t input_id, uint32_t offset, uint32_t length,
                               constraint_t constraint) {
  uint32_t hash = 0;
  auto *buf = inputs_cache[input_id].first;
  for (uint32_t i = 0; i < length; ++i, ++offset) {
    uint8_t val = buf[offset];
    uint32_t arg_index = 0;
    auto itr = constraint->local_map.find(offset); // FIXME: support input_id
    if (itr == constraint->local_map.end()) {
      arg_index = (uint32_t)constraint->input_args.size();
      constraint->inputs.insert({offset, val});
      constraint->local_map[offset] = arg_index;
      constraint->input_args.push_back(std::make_pair(true, 0)); // 0 is to be filled in the aggragation
    } else {
      arg_index = itr->second;
    }
    if (i == 0) {
      constraint->shapes[offset] = length;
      hash = rgd::xxhash(length * 8, rgd::Read, arg_index);
    } else {
      constraint->shapes[offset] = 0;
    }
  }
  return hash;
}

// Pack a concrete byte array into consecutive constant slots of @p constraint's
// input_args and configure @p node as the rgd::Constant that points at them.
//
// A memcmp target -- and, for the string ops, a needle or a character set --
// has nowhere else to live: AstNode has no blob field.  Putting the bytes in
// input_args rather than in the node is what lets two comparisons against
// different targets share one JIT'ed function, because the hash below excludes
// the content; see THE HASHING INVARIANT in include/ast.h.
bool RGDAstParser::pack_const_bytes(const uint8_t *content, uint32_t size,
                                    rgd::AstNode *node, constraint_t constraint) {
  // AstNode::bits_ is a uint16_t, so anything past 8191 bytes wraps to a wrong
  // -- and much smaller -- width that every downstream solver would then trust.
  // Fail the parse loudly instead of truncating.  (dfsan_label_info::size is
  // itself only 16 bits and carries its own FIXME, see runtime/dfsan/dfsan.h.)
  if (unlikely(size > UINT16_MAX / 8)) {
    REJECT("constant content too wide", "constant content too wide: %u bytes\n", size);
    return false;
  }
  node->set_kind(rgd::Constant);
  node->set_bits((uint16_t)(size * 8));
  node->set_label(0);
  uint32_t arg_index = (uint32_t)constraint->input_args.size();
  node->set_index(arg_index);
  uint32_t chunks = size / 8;
  uint32_t remain = size % 8;
  uint64_t val = 0;
  for (uint32_t i = 0; i < chunks; i++) {
    val = *(uint64_t*)&content[i * 8];
    constraint->input_args.push_back(std::make_pair(false, val));
    constraint->const_num += 1;
    DEBUGF("memcmp constant chunk %d = 0x%lx\n", i, val);
  }
  if (remain) {
    val = 0;
    for (uint32_t i = 0; i < remain; i++) {
      val |= (uint64_t)content[chunks * 8 + i] << (i * 8);
    }
    constraint->input_args.push_back(std::make_pair(false, val));
    constraint->const_num += 1;
    DEBUGF("memcmp constant remain = %lu\n", val);
  }
  node->set_hash(rgd::xxhash(size, rgd::Constant, arg_index));
  return true;
}

// A single concrete scalar operand -- a needle character, a GEP offset, an
// observed length.  Same convention as pack_const_bytes, one slot wide: the
// value goes to input_args and stays out of the hash, so two constraints that
// differ only in it share a JIT'ed function.
static void pack_const_scalar(uint64_t value, uint16_t bits,
                              rgd::AstNode *node,
                              std::shared_ptr<rgd::Constraint> constraint) {
  node->set_kind(rgd::Constant);
  node->set_bits(bits);
  node->set_label(0);
  uint32_t arg_index = (uint32_t)constraint->input_args.size();
  node->set_index(arg_index);
  constraint->input_args.push_back(std::make_pair(false, value));
  constraint->const_num += 1;
  node->set_hash(rgd::xxhash(bits, rgd::Constant, arg_index));
}

// One operand of a string op: a subtree when it is symbolic, otherwise the
// concrete bytes that arrived out of band.  backend/fastgen.cpp ships exactly
// one side of a content-carrying string op -- op1's buffer when l1 is
// CONST_LABEL, else op2's -- and info->size is that side's byte count, so
// looking the content up by the *op's* label (not the operand's, which is 0)
// is right for whichever side asks.
bool RGDAstParser::add_str_operand(dfsan_label label, dfsan_label operand,
                                   uint32_t content_size, rgd::AstNode *child,
                                   constraint_t constraint,
                                   std::unordered_set<dfsan_label> &visited) {
  if (operand >= CONST_OFFSET) {
    if (!do_uta_rel(operand, child, constraint, visited)) {
      return false;
    }
    visited.insert(operand);
    return true;
  }
  if (unlikely(!str_op_has_content(get_label_info(label)->op))) {
    // a caller wired an op fastgen.cpp does not ship bytes for to this path;
    // memcmp_cache_ would simply miss below, but say which mistake it was
    REJECT("string op ships no content",
           "string op %u carries no content for its concrete operand\n", label);
    return false;
  }
  if (unlikely(content_size == 0)) {
    // both sides symbolic (fastgen.cpp sends nothing then), or a concrete side
    // whose length the runtime could not determine
    REJECT("string operand has no length",
           "string op %u has a concrete operand with no length\n", label);
    return false;
  }
  auto itr = memcmp_cache_.find(label);
  if (unlikely(itr == memcmp_cache_.end())) {
    REJECT("string content missing", "string content not found for label %u\n", label);
    return false;
  }
  return pack_const_bytes(itr->second.get(), content_size, child, constraint);
}

// Lower one of the dfsan string ops into @p ret.  Parse only: no solver
// reasons about these kinds yet -- jigsaw's JIT and both z3 backends reject an
// unknown kind through their default: case, and i2s is gated on
// string_op_mask.  What building the node buys today is that the op is no
// longer an "invalid op" that fails do_uta_rel outright, so the rest of the
// clause survives and the sweep can show which ops actually occur; what it
// buys next is somewhere for an i2s string solver to hang off.
bool RGDAstParser::do_uta_str(dfsan_label label, dfsan_label_info *info,
                              uint16_t kind, rgd::AstNode *ret,
                              constraint_t constraint,
                              std::unordered_set<dfsan_label> &visited) {
  ret->set_kind(kind);
  ret->set_label(label);
  constraint->ops[kind] = true;

  // bits() is set per kind, never from info->size, which for most of these is a
  // content byte count and not a result width.  An Int- or String-sorted node
  // (see stringKindSort in include/ast.h) has no bitvector width at all, so it
  // gets the machine word -- what the position or pointer would occupy if it
  // were materialised -- and the kind carries the real sort.
  switch (kind) {
    case rgd::StrLen:
      ret->set_bits(info->size); // sizeof(size_t) * 8; a genuine BV width
      break;
    case rgd::StrCmp:
    case rgd::PrefixOf:
    case rgd::SuffixOf:
      ret->set_bits(32); // 0/1 in an i32, the way solvers/z3-ts.cpp builds it
      break;
    default:
      ret->set_bits(64);
      break;
  }

  rgd::AstNode *c0 = ret->add_children();
  if (unlikely(c0 == nullptr)) {
    REJECT("ast arena full", "failed to add children\n");
    return false;
  }
  rgd::AstNode *c1 = nullptr;
  bool unary = (kind == rgd::StrLength);
  if (!unary) {
    c1 = ret->add_children();
    if (unlikely(c1 == nullptr)) {
      REJECT("ast arena full", "failed to add children\n");
      return false;
    }
  }

  switch (kind) {
    case rgd::StrLen: {
      // l1 is 0 by construction (dfsan_custom.cpp follows the fsize/fatoi
      // pattern to dodge the Alloca rejection), l2 is the content.
      if (unlikely(info->l2 < CONST_OFFSET)) {
        REJECT("concrete string operand", "strlen over concrete content, label %u\n", label);
        return false;
      }
      if (!do_uta_rel(info->l2, c0, constraint, visited)) return false;
      visited.insert(info->l2);
      // the observed length; a value, so it rides in input_args
      pack_const_scalar(info->op2.i, 64, c1, constraint);
      // ...but whether the null terminator came from the input is structural:
      // it decides whether the length is even symbolic.  Stash it in index()
      // and fold it into the hash below, since isEqualAstRecursive ignores
      // index() (THE HASHING INVARIANT, include/ast.h).
      ret->set_index((uint32_t)info->op1.i);
      break;
    }
    case rgd::StrChr:
    case rgd::StrRChr: {
      // l1 = haystack (0 when concrete, content in memcmp_cache_ under this
      // label), l2 = needle char label (0 when concrete, char in op2's low
      // byte).  op2's high 32 bits hold the haystack base-pointer label under
      // USE_UCSAN_CUSTOM only (encode_strchr_op2); on the fuzzing path it is 0
      // and there is nothing to carry.
      if (!add_str_operand(label, info->l1, info->size, c0, constraint, visited))
        return false;
      if (info->l2 >= CONST_OFFSET) {
        if (!do_uta_rel(info->l2, c1, constraint, visited)) return false;
        visited.insert(info->l2);
      } else {
        pack_const_scalar(info->op2.i & 0xff, 8, c1, constraint);
      }
      break;
    }
    case rgd::StrStr:
    case rgd::StrPbrk:
    case rgd::StrCat:
    case rgd::StrCmp:
    case rgd::PrefixOf:
    case rgd::SuffixOf: {
      // Exactly one side is concrete and info->size is that side's byte count,
      // so both operands ask add_str_operand with the same size and only the
      // concrete one uses it.  Order is preserved: of these only fstrcmp is in
      // is_commutative(), and there the swap already put the concrete side in
      // l1, which is where fmemcmp expects it too.
      if (!add_str_operand(label, info->l1, info->size, c0, constraint, visited))
        return false;
      if (!add_str_operand(label, info->l2, info->size, c1, constraint, visited))
        return false;
      break;
    }
    case rgd::StrOff: {
      // l1 = the string op whose result was GEP'd, op2 = the signed byte offset
      if (unlikely(info->l1 < CONST_OFFSET)) {
        REJECT("concrete string operand", "str_off over a concrete position, label %u\n", label);
        return false;
      }
      if (!do_uta_rel(info->l1, c0, constraint, visited)) return false;
      visited.insert(info->l1);
      pack_const_scalar(info->op2.i, 64, c1, constraint);
      break;
    }
    case rgd::SubStr: {
      // l1 = the string, l2 = the position or length (0 when concrete, the
      // value then in op1).  Unlike the ops above, fsubstr never calls
      // __taint_trace_memcmp, so a concrete l1 means the bytes are simply not
      // on the wire and there is nothing to build.
      if (unlikely(info->l1 < CONST_OFFSET)) {
        REJECT("concrete string operand", "substr of a string with no content, label %u\n", label);
        return false;
      }
      if (!do_uta_rel(info->l1, c0, constraint, visited)) return false;
      visited.insert(info->l1);
      if (info->l2 >= CONST_OFFSET) {
        if (!do_uta_rel(info->l2, c1, constraint, visited)) return false;
        visited.insert(info->l2);
      } else {
        pack_const_scalar(info->op1.i, 64, c1, constraint);
      }
      // op2 picks prefix (0) or suffix (1) mode -- two different operations,
      // not two values -- so it goes in index() and into the hash.
      ret->set_index((uint32_t)info->op2.i);
      break;
    }
    case rgd::StrLength: {
      // Unary.  No producer creates flength today (only solvers/z3-ts.cpp
      // consumes it), so this arm is defensive; keep it faithful anyway.
      if (unlikely(info->l1 < CONST_OFFSET)) {
        REJECT("concrete string operand", "length of a concrete string, label %u\n", label);
        return false;
      }
      if (!do_uta_rel(info->l1, c0, constraint, visited)) return false;
      visited.insert(info->l1);
      break;
    }
    default:
      REJECT("unhandled string kind", "unhandled string kind %u\n", kind);
      return false;
  }

  uint32_t hash;
  if (unary) {
    hash = rgd::xxhash(ret->bits(), kind, c0->hash());
  } else {
    hash = rgd::xxhash(c0->hash(), (kind << 16) | ret->bits(), c1->hash());
  }
  // Fold the structural selectors in; see the set_index() calls above.
  if (kind == rgd::StrLen || kind == rgd::SubStr) {
    hash = rgd::xxhash(hash, ret->index(), kind);
  }
  ret->set_hash(hash);
  return true;
}

// this combines both AST construction and arg mapping
[[gnu::hot]]
bool RGDAstParser::do_uta_rel(dfsan_label label, rgd::AstNode *ret,
                              constraint_t constraint,
                              std::unordered_set<dfsan_label> &visited) {

  // needed for recursion?
  if (unlikely(label < CONST_OFFSET || label == __dfsan::kInitializingLabel)) {
    REJECT("invalid label", "invalid label: %d\n", label);
    return false;
  }

  dfsan_label_info *info = get_label_info(label);
  DEBUGF("do_uta_real: %u = (l1:%u, l2:%u, op:%u, size:%u, op1:%lu, op2:%lu)\n",
         label, info->l1, info->l2, info->op, info->size, info->op1.i, info->op2.i);

  // we can't really reuse AST nodes across constraints,
  // but we still need to avoid duplicate nodes within a constraint
  if (visited.count(label)) {
    // if a node has been visited, just record its label without expanding
    ret->set_label(label);
    ret->set_bits(info->size);
    return true;
  }

  // terminal node
  if (info->op == 0) {
    // input
    ret->set_kind(rgd::Read);
    ret->set_bits(8);
    ret->set_label(label);
    uint32_t input_id = info->op2.i;
    uint32_t offset = info->op1.i;
    // this check should have been done during label scanning
    // if (unlikely(offset >= buf_size)) {
    //   WARNF("invalid offset: %lu >= %lu\n", offset, buf_size);
    //   return false;
    // }
    ret->set_index(offset);
    // map arg
    uint32_t hash = map_arg(input_id, offset, 1, constraint);
    ret->set_hash(hash);
    return true;
  } else if (info->op == __dfsan::Load) {
    ret->set_kind(rgd::Read);
    ret->set_bits(info->l2 * 8);
    ret->set_label(label);
    uint32_t input_id = get_label_info(info->l1)->op2.i;
    uint32_t offset = get_label_info(info->l1)->op1.i;
    // this check should have been done during label scanning
    // if (unlikely(offset + info->l2 > buf_size)) {
    //   WARNF("invalid offset: %lu + %u > %lu\n", offset, info->l2, buf_size);
    //   return false;
    // }
    ret->set_index(offset);
    // map arg
    uint32_t hash = map_arg(input_id, offset, info->l2, constraint);
    ret->set_hash(hash);
    return true;
  } else if (info->op == __dfsan::WideConst) {
    // A concrete operand of an operation wider than 64 bits, carried as a leaf
    // label because the label's two op slots together are exactly 128 bits.
    // Lower it to the multi-slot rgd::Constant convention that z3-solver.cpp
    // and jit.cc already read: consecutive input_args, LOW half first.
    ret->set_kind(rgd::Constant);
    ret->set_bits(info->size);
    ret->set_label(label);
    uint32_t arg_index = (uint32_t)constraint->input_args.size();
    ret->set_index(arg_index);
    constraint->input_args.push_back(std::make_pair(false, info->op1.i));
    constraint->input_args.push_back(std::make_pair(false, info->op2.i));
    constraint->const_num += 2;
    uint32_t hash = rgd::xxhash(info->size, rgd::Constant, arg_index);
    ret->set_hash(hash);
    return true;
  } else if (info->op == __dfsan::fmemcmp) {
    rgd::AstNode *s1 = ret->add_children();
    if (unlikely(s1 == nullptr)) {
      REJECT("ast arena full", "failed to add children\n");
      return false;
    }
    if (info->l1 >= CONST_OFFSET) {
      if (!do_uta_rel(info->l1, s1, constraint, visited)) {
        return false;
      }
      visited.insert(info->l1);
    } else {
      // s1 is a constant array
      // use constant args to pass the array
      auto itr = memcmp_cache_.find(label);
      if (unlikely(itr == memcmp_cache_.end())) {
        REJECT("memcmp target missing", "memcmp target not found for label %u\n", label);
        return false;
      }
      if (!pack_const_bytes(itr->second.get(), info->size, s1, constraint)) {
        return false;
      }
    }
    rgd::AstNode *s2 = ret->add_children();
    if (unlikely(s2 == nullptr)) {
      REJECT("ast arena full", "failed to add children\n");
      return false;
    }
    if (!do_uta_rel(info->l2, s2, constraint, visited)) {
      return false;
    }
    visited.insert(info->l2);
    ret->set_kind(rgd::Memcmp);
    ret->set_bits(1);
    ret->set_label(label);
    uint32_t hash = rgd::xxhash(s1->hash(), rgd::Memcmp, s2->hash());
    ret->set_hash(hash);
    return true;
  } else if (info->op == __dfsan::tlookup) {
    // A load from a read-only global table at a symbolic index.  The single
    // child is the index expression; the loaded value is what this node stands
    // for.  Table contents travel out of band (table_type messages, cached by
    // base address) because the solver is in another process, and they are
    // packed into input_args the same way a memcmp target is -- AstNode has
    // nowhere else to carry a blob.  Layout, starting at index():
    //
    //   [0]            num_elems
    //   [1 .. 1+n-1]   the table bytes, 8 per arg, little-endian
    //
    // so the node is self-describing to solvers/i2s-solver.cpp, the only
    // consumer.  jigsaw and z3 decline this kind.
    auto itr = table_cache_.find(info->op1.i);
    if (unlikely(itr == table_cache_.end())) {
      REJECT("table contents missing",
             "table contents not found for %#lx (label %u)\n", info->op1.i, label);
      return false;
    }
    uint64_t num_elems = info->op2.i;
    size_t tbl_size = itr->second.size;
    if (unlikely(info->size == 0 || info->size % 8 != 0 ||
                 num_elems * (info->size / 8) != tbl_size)) {
      REJECT("table geometry mismatch",
             "table geometry mismatch for label %u: %lu x %u vs %lu bytes\n",
            label, num_elems, info->size / 8, tbl_size);
      return false;
    }
    rgd::AstNode *index = ret->add_children();
    if (unlikely(index == nullptr)) {
      REJECT("ast arena full", "failed to add children\n");
      return false;
    }
    if (unlikely(info->l1 < CONST_OFFSET)) {
      // a concrete index would have left the load concrete in the first place
      REJECT("concrete tlookup index", "table lookup with concrete index, label %u\n", label);
      return false;
    }
    if (!do_uta_rel(info->l1, index, constraint, visited)) {
      return false;
    }
    visited.insert(info->l1);
    // pack num_elems then the contents, folding both into a content hash
    uint32_t arg_index = (uint32_t)constraint->input_args.size();
    constraint->input_args.push_back(std::make_pair(false, num_elems));
    constraint->const_num += 1;
    uint32_t thash = rgd::xxhash((uint32_t)num_elems, rgd::TLookup, (uint32_t)tbl_size);
    const uint8_t *tbl = itr->second.data.get();
    for (size_t i = 0; i < tbl_size; i += 8) {
      uint64_t val = 0;
      size_t chunk = tbl_size - i < 8 ? tbl_size - i : 8;
      for (size_t j = 0; j < chunk; j++) {
        val |= (uint64_t)tbl[i + j] << (j * 8);
      }
      constraint->input_args.push_back(std::make_pair(false, val));
      constraint->const_num += 1;
      thash = rgd::xxhash(thash, (uint32_t)val, (uint32_t)(val >> 32));
    }
    ret->set_kind(rgd::TLookup);
    ret->set_bits(info->size);
    ret->set_label(label);
    ret->set_index(arg_index);
    constraint->ops[rgd::TLookup] = true;
    // The contents must be in the hash: isEqualAstRecursive falls back to
    // hash() when the kinds match and ignores index(), so two lookups over
    // different tables with the same index expression would otherwise be
    // conflated by the constraint/function caches.  Hashing the bytes rather
    // than the base address also keeps this stable across ASLR.
    ret->set_hash(rgd::xxhash(index->hash(),
                              (rgd::TLookup << 16) | info->size, thash));
    return true;
  } else if (info->op == __dfsan::fatoi) {
    if (unlikely(info->l1 != 0 || info->l2 < CONST_OFFSET)) {
      REJECT("invalid atoi label", "invalid atoi label %u\n", label);
      return false;
    }
    dfsan_label_info *src = get_label_info(info->l2);
    // The consumed digits are represented either as a Load label (len > 1) or,
    // when a single digit was consumed, as the raw input-byte label directly
    // (op == 0).
    dfsan_label_info *byte;
    if (src->op == __dfsan::Load) {
      byte = get_label_info(src->l1);
    } else if (src->op == 0) {
      byte = src;
    } else {
      REJECT("invalid atoi source", "invalid atoi source label %u, op = %u\n", info->l2, src->op);
      return false;
    }
    visited.insert(info->l2);
    uint32_t input_id = byte->op2.i;
    uint32_t offset = byte->op1.i;
    // this check should have been done during label scanning
    // if (unlikely(offset >= buf_size)) {
    //   WARNF("invalid offset: %lu >= %lu\n", offset, buf_size);
    //   return false;
    // }
    ret->set_bits(info->size);
    ret->set_label(label);
    ret->set_index(offset);
    // special handling for atoi, we are introducing the result/output of
    // atoi as fake inputs, and solve constraints over the output,
    // once solved, we convert it back to string
    // however, because the input is fake, we need to map it specially
    ret->set_kind(rgd::Read);
    auto itr = constraint->local_map.find(offset); // FIXME: support input_id
    if (itr != constraint->local_map.end()) {
      REJECT("atoi input reused elsewhere",
             "atoi inputs should not be involved in other constraints\n");
      return false;
    }
    uint32_t hash = 0;
    uint32_t length = info->size / 8; // bits to bytes
    // record the offset, base, and original length
    constraint->atoi_info[offset] = std::make_tuple(length, (uint32_t)info->op1.i, (uint32_t)info->op2.i);
    for (uint32_t i = 0; i < length; ++i, ++offset) {
      uint8_t val = 0; // XXX: use 0 as initial value?
      // because this is fake input, we always map it to a new index
      uint32_t arg_index = (uint32_t)constraint->input_args.size();
      constraint->inputs.insert({offset, val});
      constraint->local_map[offset] = arg_index; // FIXME: support input_id
      constraint->input_args.push_back(std::make_pair(true, 0)); // 0 is to be filled in the aggragation
      if (i == 0) {
        constraint->shapes[offset] = length;
        // from solver's perspective, atoi and read are the same
        // they both introduce a new symbolic input as arg_index
        hash = rgd::xxhash(length * 8, rgd::Read, arg_index);
      } else {
        constraint->shapes[offset] = 0;
      }
    }
    ret->set_hash(hash);
    return true;
  } else if (info->op == __dfsan::fsize) {
    // do nothing now
    REJECT("fsize unsupported", "fsize not supported yet\n");
    return false;
  } else if (info->op == __dfsan::PtrToInt) {
    // PtrToInt is a string op only when its operand is one: the position a
    // search op returns is relative to its haystack, while a pointer
    // difference is absolute, so the two differ by the haystack's offset in
    // the input.  That offset is not precomputed here the way
    // solvers/z3-ts.cpp precomputes it from string_info_cache_ -- it is
    // reachable from the AST, as the index() of the leftmost Read under the
    // haystack subtree, and a solver that needs it can walk there.
    //
    // A PtrToInt over anything else still falls through to the OP_MAP lookup
    // and is rejected; passing those through would be a separate change.
    if (info->l1 >= CONST_OFFSET &&
        __dfsan::is_string_op(get_label_info(info->l1)->op)) {
      ret->set_kind(rgd::StrPtrToInt);
      ret->set_bits(info->size); // a real pointer width here
      ret->set_label(label);
      constraint->ops[rgd::StrPtrToInt] = true;
      rgd::AstNode *c0 = ret->add_children();
      if (unlikely(c0 == nullptr)) {
        REJECT("ast arena full", "failed to add children\n");
        return false;
      }
      if (!do_uta_rel(info->l1, c0, constraint, visited)) {
        return false;
      }
      visited.insert(info->l1);
      ret->set_hash(rgd::xxhash(info->size, rgd::StrPtrToInt, c0->hash()));
      return true;
    }
  } else {
    auto str_itr = STR_OP_MAP.find(info->op);
    if (str_itr != STR_OP_MAP.end()) {
      return do_uta_str(label, info, (uint16_t)str_itr->second, ret,
                        constraint, visited);
    }
  }

  // common ops, make sure no special ops.
  // FP arithmetic (FAdd/FSub/FMul/FDiv) and fp_sqrt may carry a rounding-mode
  // selector in the high byte of `op` (see instrumentation/TaintPass.cpp and
  // driver/smttest.cpp); FRem never carries one (frem has no rounding).  cmp
  // ops keep their predicate packed in the high byte and have per-predicate
  // OP_MAP entries, so only mask the FP-arith kinds before the lookup.
  uint16_t op_lo = info->op & 0xff;
  bool is_fp_arith_rm =
      op_lo == __dfsan::FAdd || op_lo == __dfsan::FSub ||
      op_lo == __dfsan::FMul || op_lo == __dfsan::FDiv ||
      op_lo == __dfsan::fp_sqrt;
  uint16_t lookup_op = is_fp_arith_rm ? op_lo : info->op;
  auto op_itr = OP_MAP.find(lookup_op);
  if (op_itr == OP_MAP.end()) {
    REJECT_OP("unsupported op", info->op, "invalid op: %u\n", info->op);
    return false;
  }
  ret->set_kind(op_itr->second.first);
  ret->set_bits(info->size);
  ret->set_label(label);

  // record op
  constraint->ops[ret->kind()] = true;

  // in case we needs concretization
  uint8_t needs_concretization = 0;
  auto node_itr = concretize_node.find(label);
  if (node_itr != concretize_node.end()) {
    needs_concretization = node_itr->second;
  }

  // now we visit the children
  rgd::AstNode *left = ret->add_children();
  if (unlikely(left == nullptr)) {
    REJECT("ast arena full", "failed to add children\n");
    return false;
  }
  if (likely(needs_concretization != 1) && (info->l1 >= CONST_OFFSET)) {
    if (!do_uta_rel(info->l1, left, constraint, visited)) {
      return false;
    }
    visited.insert(info->l1);
  } else {
    if (unlikely(needs_concretization)) {
      if (unlikely(!rgd::isRelationalKind(ret->kind()) &&
                   !rgd::isFPRelationalKind(ret->kind()))) {
        REJECT("invalid concretization kind", "invalid kind for concretization %u\n", ret->kind());
        return false;
      }
    }
    // constant
    left->set_kind(rgd::Constant);
    left->set_label(0);
    uint32_t size = info->size;
    // size of concat the sum of the two operands
    // to get the size of the constant, we need to subtract the size
    // of the other operand
    if (info->op == __dfsan::Concat) {
      if (unlikely(info->l2 == 0)) {
        REJECT("invalid concat node", "invalid concat node %u\n", info->l2);
        return false;
      }
      size -= get_label_info(info->l2)->size;
    }
    left->set_bits(size);
    // map args
    uint32_t arg_index = (uint32_t)constraint->input_args.size();
    left->set_index(arg_index);
    constraint->input_args.push_back(std::make_pair(false, info->op1.i));
    constraint->const_num += 1;
    uint32_t hash = rgd::xxhash(size, rgd::Constant, arg_index);
    left->set_hash(hash);
  }

  // unary ops.  FP casts (FPToUI/FPToSI/UIToFP/SIToFP/FPTrunc/FPExt), FP
  // unary intrinsics (fneg/fabs/sqrt/round), the FP predicate/rounding
  // libcalls (isnan/isinf/finite/signbit/lrint) and the unary transcendentals
  // (exp/exp2/log/log2/log10/log1p) all take a single operand in l1, so they
  // short-circuit here before a (nonexistent) right child is built.  (pow is
  // binary and goes through the normal binary path below.)
  // fp_sqrt may carry a rounding selector in the high byte, so compare on op_lo.
  bool is_fp_unary =
      info->op == __dfsan::FPToUI || info->op == __dfsan::FPToSI ||
      info->op == __dfsan::UIToFP || info->op == __dfsan::SIToFP ||
      info->op == __dfsan::FPTrunc || info->op == __dfsan::FPExt ||
      info->op == __dfsan::fp_neg || info->op == __dfsan::fp_fabs ||
      op_lo == __dfsan::fp_sqrt || info->op == __dfsan::fp_round ||
      info->op == __dfsan::fp_is_nan || info->op == __dfsan::fp_is_inf ||
      info->op == __dfsan::fp_is_finite || info->op == __dfsan::fp_signbit ||
      info->op == __dfsan::fp_lrint ||
      info->op == __dfsan::fp_exp || info->op == __dfsan::fp_exp2 ||
      info->op == __dfsan::fp_log || info->op == __dfsan::fp_log2 ||
      info->op == __dfsan::fp_log10 || info->op == __dfsan::fp_log1p;
  if (info->op == __dfsan::ZExt || info->op == __dfsan::SExt ||
      info->op == __dfsan::Extract || info->op == __dfsan::Trunc ||
      info->op == __dfsan::bitreverse ||
      is_fp_unary) {
    // Extract carries a bit offset in op2; fp_round carries its rounding-mode
    // selector (fp_rounding_mode) in op1; constrained fp_sqrt carries its
    // selector in the high byte of op.  All are stashed in index().
    uint64_t offset = info->op == __dfsan::Extract ? info->op2.i :
                      (info->op == __dfsan::fp_round ? info->op1.i :
                       (op_lo == __dfsan::fp_sqrt ? (info->op >> 8) : 0));
    uint32_t hash = rgd::xxhash(info->size, ret->kind(), left->hash());
    // Fold the rounding selector into the hash for FP ops whose codegen depends
    // on it (fp_round: floor/ceil/trunc; fp_sqrt: directed rounding).  fCache
    // buckets by hash() and confirms with isEqualAstRecursive, which ignores
    // index() -- so without this, floor vs ceil (or RNE vs directed sqrt) over
    // the same child would collide and reuse wrong-mode compiled code.
    if (info->op == __dfsan::fp_round || op_lo == __dfsan::fp_sqrt)
      hash = rgd::xxhash(hash, (uint32_t)offset, ret->kind());
    ret->set_hash(hash);
    ret->set_index(offset);
    return true;
  }

  rgd::AstNode *right = ret->add_children();
  if (unlikely(right == nullptr)) {
    REJECT("ast arena full", "failed to add children\n");
    return false;
  }
  if (likely(needs_concretization != 2) && (info->l2 >= CONST_OFFSET)) {
    if (!do_uta_rel(info->l2, right, constraint, visited)) {
      return false;
    }
    visited.insert(info->l2);
  } else {
    if (unlikely(needs_concretization)) {
      if (unlikely(!rgd::isRelationalKind(ret->kind()) &&
                   !rgd::isFPRelationalKind(ret->kind()))) {
        REJECT("invalid concretization kind", "invalid kind for concretization %u\n", ret->kind());
        return false;
      }
    }
    // constant
    right->set_kind(rgd::Constant);
    right->set_label(0);
    uint32_t size = info->size;
    // size of concat the sum of the two operands
    // to get the size of the constant, we need to subtract the size
    // of the other operand
    if (info->op == __dfsan::Concat) {
      if (unlikely(info->l1 == 0)) {
        REJECT("invalid concat node", "invalid concat node %u\n", info->l1);
        return false;
      }
      size -= get_label_info(info->l1)->size;
    }
    right->set_bits(size);
    // map args
    uint32_t arg_index = (uint32_t)constraint->input_args.size();
    right->set_index(arg_index);
    constraint->input_args.push_back(std::make_pair(false, info->op2.i));
    constraint->const_num += 1;
    uint32_t hash = rgd::xxhash(size, rgd::Constant, arg_index);
    right->set_hash(hash);
  }

  // record comparison operands.  These are the values the trace saw, extended
  // to 64 bits by combineShadows -- so for a comparison wider than that they
  // hold only the LOW half, and a consumer that treats them as the whole value
  // gets a wrong answer rather than no answer.  Both consumers are guarded:
  // I2SSolver::solve_icmp/solve_fcmp never read them at that width (a wide
  // equality routes to solve_memcmp_ast, which works off input_args instead,
  // and anything else declines), and jigsaw never sees one because addFunction()
  // rejects a wide comparison during codegen, which fails the whole task in
  // jit-solver.cpp before try_i2s can run.
  if (rgd::isRelationalKind(ret->kind()) || rgd::isFPRelationalKind(ret->kind())) {
    constraint->op1 = info->op1.i;
    constraint->op2 = info->op2.i;
  }

  // binary ops, we don't really care about comparison ops in jigsaw,
  // as long as the operands are the same, we can reuse the AST/function
  uint32_t kind = rgd::isRelationalKind(ret->kind()) ? rgd::Bool : ret->kind();
  uint32_t hash = rgd::xxhash(left->hash(), (kind << 16) | ret->bits(), right->hash());
  // FP arithmetic (FAdd/FSub/FMul/FDiv; not FRem) may carry a rounding selector
  // in the high byte of op.  Stash it in index() so the JIT (jit.cc) and the RGD
  // z3 path (z3-solver.cpp) emit rounding-mode-correct arithmetic, and fold it
  // into the hash so fCache never reuses wrong-mode code (isEqualAstRecursive
  // ignores index()).  sqrt is unary and returned above.
  if (op_lo == __dfsan::FAdd || op_lo == __dfsan::FSub ||
      op_lo == __dfsan::FMul || op_lo == __dfsan::FDiv) {
    uint32_t sel = info->op >> 8;
    ret->set_index(sel);
    hash = rgd::xxhash(hash, sel, kind);
  }
  ret->set_hash(hash);

  return true;
}

[[gnu::hot]]
RGDAstParser::constraint_t RGDAstParser::parse_constraint(dfsan_label label) {
  DEBUGF("constructing constraint for label %u\n", label);
  // make sure root is a comparison node
  // XXX: root should never go oob?
  dfsan_label_info *info = get_label_info(label);
  if (unlikely(((info->op & 0xff) != __dfsan::ICmp) &&
               ((info->op & 0xff) != __dfsan::FCmp) &&
               (info->op != __dfsan::fmemcmp))) {
    REJECT("non-comparison root",
           "invalid root node %u, non-comparison root op: %u\n", label, info->op);
    return nullptr;
  }

  // retrieve the ast size
  if (unlikely(ast_size_cache.size() <= label)) {
    REJECT("label beyond ast size cache",
           "invalid label %u, larger than ast_size_cache: %lu\n", label, ast_size_cache.size());
    return nullptr;
  }
  auto size = ast_size_cache.at(label);
  if (unlikely(size == 0)) {
    REJECT("ast size zero", "invalid label %u, ast_size_cache is 0\n", label);
    return nullptr;
  }
  std::unordered_set<dfsan_label> visited;
  try {
    // arg_size_cache is filled in lockstep with ast_size_cache, so the bounds
    // check above covers both
    constraint_t constraint =
        std::make_shared<rgd::Constraint>(size, arg_size_cache.at(label));
#if DEBUG
    size_t reserved = constraint->input_args.capacity();
#endif
    if (!do_uta_rel(label, constraint->ast.get(), constraint, visited)) {
      return nullptr;
    }
#if DEBUG
    // scan_labels is supposed to bound this.  Growing is safe, but it means a
    // node kind packs more slots than scan_labels accounts for -- worth
    // knowing about when adding one.
    if (constraint->input_args.size() > reserved) {
      WARNF("input_args under-reserved for %u: %lu > %lu\n", label,
            constraint->input_args.size(), reserved);
    }
#endif
    return constraint;
  } catch (std::bad_alloc &e) {
    REJECT("out of memory", "failed to allocate memory for constraint\n");
    return nullptr;
  } catch (std::out_of_range &e) {
    REJECT("ast out of range", "AST %u goes out of range at %s\n", label, e.what());
    return nullptr;
  }
}

[[gnu::hot]]
task_t RGDAstParser::construct_task(const clause_t &clause) {
  task_t task = std::make_shared<rgd::SearchTask>();
  for (auto const& node: clause) {
    auto itr = constraint_cache.find(node->label());
    if (itr != constraint_cache.end()) {
      task->add_constraint(itr->second, node->kind());
      continue;
    }
    // save the comparison op because we may have negated it
    // during transformation
    constraint_t constraint = parse_constraint(node->label());
    // to maximize the resuability of the AST, the relational operator
    // is recorded elsewhere
    if (likely(constraint != nullptr)) {
      task->add_constraint(constraint, node->kind());
      constraint_cache.insert({node->label(), constraint});
    }
  }
  if (!task->empty()) {
    task->finalize();
    return task;
  }
  // every constraint in the clause failed to parse.  Each parse_constraint()
  // above already named its own cause and that is the more useful bucket, so
  // only speak up if the clause was empty to begin with.
  if (last_error().empty()) set_error("empty clause");
  return nullptr;
}

// sometimes llvm will zext bool
dfsan_label RGDAstParser::strip_zext(dfsan_label label) {
  dfsan_label_info *info = get_label_info(label);
  while (info->op == __dfsan::ZExt) {
    dfsan_label child = info->l1;
    info = get_label_info(child);
    if (info->size == 1) {
      // extending a boolean value
      return child;
    } else if ((info->op & 0xff) == __dfsan::ICmp ||
               (info->op & 0xff) == __dfsan::FCmp ||
               info->op == __dfsan::fmemcmp) {
      // extending the result of icmp, fcmp or memcmp
      return child;
    }
  }
  return label;
}

[[gnu::hot]]
int RGDAstParser::find_roots(dfsan_label label, AstNode *ret,
                             std::unordered_set<dfsan_label> &subroots) {
  // assume the root label has been checked by the caller
  // if (label < CONST_OFFSET || label == kInitializingLabel) {
  //   WARNF("invalid label: %d\n", label);
  //   return INVALID_NODE;
  // }

  std::vector<dfsan_label> stack;
  dfsan_label root = label;
  dfsan_label prev = 0;
  std::vector<AstNode*> node_stack;
  AstNode *root_node = ret;
  std::unordered_set<dfsan_label> visited;

  try{
  while (root != 0 || !stack.empty()) {
    if (root != 0) {
      // check if the node has been visited before
      if (visited.find(root) != visited.end()) {
        // already visited, skip the subtree
        prev = root;
        root = 0;
        continue;
      }
      // mark to be visit in the future, for in-order and post-order visitors
      stack.push_back(root);
      node_stack.push_back(root_node);
      auto *info = get_label_info(root);
      if (nested_cmp_cache[info->l1] == 0) {
        // no nested comparison in the left child, stop going down
        // again, we only collect a partial AST with comparison nodes as leafs
        // so the traversal should stop before reaching any actual leaf node
        root = 0;
      } else {
        root = strip_zext(info->l1);
        if (root) {
          // create a child node before going down
          root_node = root_node->add_children();
          if (unlikely(root_node == nullptr)) {
            REJECT("ast arena full", "failed to add children\n");
            return INVALID_NODE;
          }
        }
      }
    } else {
      // we have reached some leaf node, going up the tree
      auto curr = stack.back();
      auto info = get_label_info(curr);
      auto zsl2 = strip_zext(info->l2);
      if (nested_cmp_cache[zsl2] > 0 && prev != zsl2) {
        // we have a right child, and we haven't visited it yet,
        // and there is a nested comparison, going down the right tree
        root = zsl2;
        root_node = node_stack.back()->add_children();
        if (unlikely(root_node == nullptr)) {
          REJECT("ast arena full", "failed to add children\n");
          return INVALID_NODE;
        }
      } else {
        DEBUGF("label %d, l1 %d, l2 %d, op %d, size %d, op1 %ld, op2 %ld\n",
               curr, info->l1, info->l2, info->op, info->size, info->op1.i, info->op2.i);
        // both children nodes have been visited, process the node (post-order)
        auto node = node_stack.back();

        if (info->op == __dfsan::Not) {
          DEBUGF("simplify not: %d, %d\n", info->l2, info->size);
          if (unlikely(node->children_size() != 1)) {
            REJECT("bool child width", "child node size != 1\n");
            return INVALID_NODE;
          }
          if (unlikely(info->size != 1)) {
            REJECT("bool node width", "info size != 1\n");
            return INVALID_NODE;
          }
          rgd::AstNode *child = node->mutable_children(0);
          node->set_bits(1);
          if (child->kind() == rgd::Bool) {
            node->set_kind(rgd::Bool);
            node->set_boolvalue(!child->boolvalue());
            node->clear_children();
          } else {
            node->set_kind(rgd::LNot);
          }
        } else if (info->op == __dfsan::And) {
          // if And apprears, it must be LAnd, try to simplify
          DEBUGF("simplify land: %d LAnd %d, %d\n", info->l1, info->l2, info->size);
          if (unlikely(node->children_size() == 0)) {
            REJECT("empty child", "child node size == 0\n");
            return INVALID_NODE;
          }
          if (unlikely(info->size != 1)) {
            REJECT("bool node width", "info size != 1\n");
            return INVALID_NODE;
          }
          uint32_t child = 0;
          rgd::AstNode *left = nullptr;
          rgd::AstNode *right = nullptr;
          if (nested_cmp_cache[info->l1] > 0) {
            left = node->mutable_children(0);
            child = 1; // if left child exists, rhs will be child 1
          }
          if (nested_cmp_cache[info->l2] > 0) {
            right = node->mutable_children(child);
          }
          node->set_bits(1);

          if (unlikely(info->l1 == 0)) {
            // lhs is a constant
            if (info->op1.i == 0) { // 0 LAnd x = 0
              node->set_kind(rgd::Bool);
              node->set_boolvalue(0);
              node->clear_children();
            } else if (info->op1.i == 1) { // 1 LAnd x = x
              if (unlikely(right == nullptr)) {
                REJECT("null child", "right child is null\n");
                return INVALID_NODE;
              }
              node->CopyFrom(*right);
            } else {
              REJECT("invalid constant", "invalid constant %ld\n", info->op1.i);
              return INVALID_NODE;
            }
          } else {
            if (unlikely(left == nullptr)) {
              REJECT("null child", "left child is null\n");
              return INVALID_NODE;
            }
            if (unlikely(right == nullptr)) {
              REJECT("null child", "right child is null\n");
              return INVALID_NODE;
            }
            // check for constant
            if (left->kind() == rgd::Bool) {
              if (left->boolvalue() == 0) { // 0 LAnd x = 0
                node->set_kind(rgd::Bool);
                node->set_boolvalue(0);
                node->clear_children();
              } else if (right->kind() == rgd::Bool) {
                // both lhs and rhs are constants
                node->set_kind(rgd::Bool);
                node->set_boolvalue(right->boolvalue()); // 1 LAnd b = b
                node->clear_children();
              } else { // 1 LAnd x = x
                // lhs is 1, rhs is not
                node->CopyFrom(*right);
              }
            } else if (right->kind() == rgd::Bool) {
              // lhs is not a constant, check rhs
              if (right->boolvalue() == 0) { // x LAnd 0 = 0
                node->set_kind(rgd::Bool);
                node->set_boolvalue(0);
                node->clear_children();
              } else { // x LAnd 1 = x
                // rhs is 1, lhs is not
                node->CopyFrom(*left);
              }
            } else {
              // both sides are symbolic
              node->set_kind(rgd::LAnd);
            }
          }
        } else if (info->op == __dfsan::Or) {
          DEBUGF("simplify lor: %d LOr %d, %d\n", info->l1, info->l2, info->size);
          if (unlikely(node->children_size() == 0)) {
            REJECT("empty child", "child node size == 0\n");
            return INVALID_NODE;
          }
          if (unlikely(info->size != 1)) {
            REJECT("bool node width", "info size != 1\n");
            return INVALID_NODE;
          }
          uint32_t child = 0;
          rgd::AstNode *left = nullptr;
          rgd::AstNode *right = nullptr;
          if (nested_cmp_cache[info->l1] > 0) {
            left = node->mutable_children(0);
            child = 1; // if left child exists, rhs will be child 1
          }
          if (nested_cmp_cache[info->l2] > 0) {
            right = node->mutable_children(child);
          }
          node->set_bits(1);

          if (unlikely(info->l1 == 0)) {
            // lhs is a constant
            if (info->op1.i == 1) { // x LOr 1 = 1
              node->set_kind(rgd::Bool);
              node->set_boolvalue(1);
              node->clear_children();
            } else if (info->op1.i == 0) { // 0 LOr x = x
              if (unlikely(right == nullptr)) {
                REJECT("null child", "right child is null\n");
                return INVALID_NODE;
              }
              node->CopyFrom(*right);
            } else {
              REJECT("invalid constant", "invalid constant %ld\n", info->op1.i);
              return INVALID_NODE;
            }
          } else {
            if (unlikely(left == nullptr)) {
              REJECT("null child", "left child is null\n");
              return INVALID_NODE;
            }
            if (unlikely(right == nullptr)) {
              REJECT("null child", "right child is null\n");
              return INVALID_NODE;
            }
            // check for constant
            if (left->kind() == rgd::Bool) {
              if (left->boolvalue() == 1) { // 1 LOr x = 1
                node->set_kind(rgd::Bool);
                node->set_boolvalue(1);
                node->clear_children();
              } else if (right->kind() == rgd::Bool) {
                // both lhs and rhs are constants
                node->set_kind(rgd::Bool);
                node->set_boolvalue(right->boolvalue()); // 0 LOr b = b
                node->clear_children();
              } else { // 0 LOr x = x
                // lhs is 0, rhs is not
                node->CopyFrom(*right);
              }
            } else if (right->kind() == rgd::Bool) {
              if (right->boolvalue() == 1) { // x LOr 1 = 1
                node->set_kind(rgd::Bool);
                node->set_boolvalue(1);
                node->clear_children();
              } else { // x LOr 0 = x
                // rhs is 0, lhs is not
                node->CopyFrom(*left);
              }
            } else {
              // both sides are symbolic
              node->set_kind(rgd::LOr);
            }
          }
        } else if (info->op == __dfsan::Xor) {
          DEBUGF("simplify lxor: %d LXOr %d, %d\n", info->l1, info->l2, info->size);
          if (unlikely(node->children_size() == 0)) {
            REJECT("empty child", "child node size == 0\n");
            return INVALID_NODE;
          }
          if (unlikely(info->size != 1)) {
            REJECT("bool node width", "info size != 1\n");
            return INVALID_NODE;
          }
          uint32_t child = 0;
          rgd::AstNode *left = nullptr;
          rgd::AstNode *right = nullptr;
          if (nested_cmp_cache[info->l1] > 0) {
            left = node->mutable_children(0);
            child = 1; // if left child exists, rhs will be child 1
          }
          if (nested_cmp_cache[info->l2] > 0) {
            right = node->mutable_children(child);
          }
          node->set_bits(1);

          if (likely(info->l1 == 0)) {
            // lhs is a constant
            if (unlikely(right == nullptr)) {
              REJECT("null child", "right child is null\n");
              return INVALID_NODE;
            }
            if (unlikely(right->kind() == rgd::Bool)) {
              // rhs is a constant
              node->set_kind(rgd::Bool);
              node->set_boolvalue(right->boolvalue() ^ (uint32_t)info->op1.i);
              node->clear_children();
            } else {
              // rhs is symbolic
              if (info->op1.i == 1) { // 1 LXor x = LNot x
                node->set_kind(rgd::LNot);
              } else { // 0 LXor x = x
                node->CopyFrom(*right);
              }
            }
          } else {
            if (unlikely(left == nullptr)) {
              REJECT("null child", "left child is null\n");
              return INVALID_NODE;
            }
            if (unlikely(right == nullptr)) {
              REJECT("null child", "right child is null\n");
              return INVALID_NODE;
            }
            // check for constant
            if (unlikely(left->kind() == rgd::Bool)) {
              if (unlikely(right->kind() == rgd::Bool)) {
                // both lhs and rhs are constants
                node->set_kind(rgd::Bool);
                node->set_boolvalue(right->boolvalue() ^ left->boolvalue());
                node->clear_children();
              } else if (left->boolvalue() == 0) { // 0 LXor x = x
                node->CopyFrom(*right);
              } else { // 1 LXor x = LNot x
                node->set_kind(rgd::LNot);
              }
            } else if (unlikely(right->kind() == rgd::Bool)) {
              // rhs is constant, lhs is not
              if (right->boolvalue() == 0) { // x LXor 0 = x
                node->CopyFrom(*left);
              } else { // x LXor 1 = LNot x
                node->set_kind(rgd::LNot);
              }
            } else {
              // both sides are symbolic
              node->set_kind(rgd::Xor);
            }
          }
        } else if ((info->op & 0xff) == __dfsan::ICmp) {
          // cmp node
          node->set_bits(1);
          if (likely(node->children_size() == 0)) {
            // if the node has no children, it's a leaf node
            // check size, concretize if too large
            auto size = ast_size_cache.at(curr);
            // load previous value as previous concretization could have
            // changed the ast size used for allocation
            auto itr = concretize_node.find(curr);
            uint8_t concretize = (itr != concretize_node.end() ? itr->second : 0);
            if (size > max_ast_size_) {
              DEBUGF("AST size too large: %d = %u\n", curr, size);
              auto left_size = ast_size_cache.at(info->l1);
              auto right_size = ast_size_cache.at(info->l2);
              if (left_size > max_ast_size_) {
                // concretize left
                concretize |= 1;
                // update new size
                size -= (left_size - 1);
              }
              if (right_size > max_ast_size_) {
                // concretize right
                concretize |= 2;
                // update new size
                size -= (right_size - 1);
              }
              DEBUGF("new size: %d = %u\n", curr, size);
              ast_size_cache[curr] = size;
              concretize_node[curr] = concretize;
            }

            // check for concrete ops
            uint8_t concrete_ops = concretize;
            concrete_ops |= info->l1 == 0 ? 1 : 0;
            concrete_ops |= info->l2 == 0 ? 2 : 0;
            if (concrete_ops == 3) {
              // well, both sides have been concretized, simplify the node
              node->set_kind(rgd::Bool);
              node->set_boolvalue(eval_icmp(info->op, info->op1.i, info->op2.i));
            } else {
              auto itr = OP_MAP.find(info->op);
              if (unlikely(itr == OP_MAP.end())) {
                REJECT("invalid icmp predicate", "invalid icmp op: %d\n", info->op);
                return INVALID_NODE;
              }
              node->set_kind(itr->second.first);
              node->set_label(curr);
#ifdef DEBUG
              subroots.insert(curr);
#endif
            }
          } else if (node->children_size() == 1) {
            // one side has another icmp, must be simplifiable
            if (!is_rel_cmp(info->op, __dfsan::bveq) && !is_rel_cmp(info->op, __dfsan::bvneq)) {
              REJECT("unexpected icmp", "unexpected icmp: %d\n", info->op);
              // unexpected icmp, set as a constant boolean
              node->set_kind(rgd::Bool);
              node->set_boolvalue(eval_icmp(info->op, info->op1.i, info->op2.i));
            } else {
              if (nested_cmp_cache[info->l1]) {
                // nested icmp in the lhs
                rgd::AstNode *left = node->mutable_children(0);
                if (unlikely(left->bits() != 1)) {
                  REJECT("nested icmp lhs width", "nested icmp lhs bits != 1\n");
                  return INVALID_NODE;
                }
                if (likely(info->l2 == 0)) {
                  if (is_rel_cmp(info->op, __dfsan::bveq)) {
                    if (info->op2.i == 1) { // checking bool == true
                      node->CopyFrom(*left);
                    } else { // checking bool == false
                      node->set_kind(rgd::LNot);
                    }
                  } else { // bvneq
                    if (info->op2.i == 0) { // checking bool != false
                      node->CopyFrom(*left);
                    } else { // checking bool != true
                      node->set_kind(rgd::LNot);
                    }
                  }
                } else {
                  // l2 != 0, bool icmp bool ?!
                  REJECT("bool icmp bool", "bool icmp bool ?!\n");
                  node->set_kind(rgd::Bool);
                  node->set_boolvalue(0);
                  node->clear_children();
                }
              } else if (nested_cmp_cache[info->l2] > 0) {
                // nested icmp in the rhs
                rgd::AstNode *right = node->mutable_children(0);
                if (unlikely(right->bits() != 1)) {
                  REJECT("nested icmp rhs width", "nested icmp rhs bits != 1\n");
                  return INVALID_NODE;
                }
                if (likely(info->l1 == 0)) {
                  if (is_rel_cmp(info->op, __dfsan::bveq)) {
                    if (info->op1.i == 1) { // checking true == bool
                      node->CopyFrom(*right);
                    } else { // checking false == bool
                      node->set_kind(rgd::LNot);
                    }
                  } else { // bvneq
                    if (info->op1.i == 0) { // checking false != bool
                      node->CopyFrom(*right);
                    } else { // checking true != bool
                      node->set_kind(rgd::LNot);
                    }
                  }
                } else {
                  // l1 != 0, bool icmp bool ?!
                  REJECT("bool icmp bool", "bool icmp bool ?!\n");
                  node->set_kind(rgd::Bool);
                  node->set_boolvalue(0);
                  node->clear_children();
                }
              } else {
                REJECT("icmp without nested icmp", "icmp with child yet no nested icmp?!\n");
                return INVALID_NODE;
              }
            }
          } else {
            // both sides have another icmp, set as a constant boolean
            node->set_kind(rgd::Bool);
            node->set_boolvalue(eval_icmp(info->op, info->op1.i, info->op2.i));
            node->clear_children();
          }
        } else if ((info->op & 0xff) == __dfsan::FCmp) {
          // fcmp node (relational leaf).  Unlike icmp, both operands are FP
          // values, so an fcmp never has a nested comparison child -- the
          // children_size should always be 0 here.
          node->set_bits(1);
          if (likely(node->children_size() == 0)) {
            // check size, concretize if too large (mirror the icmp leaf path)
            auto size = ast_size_cache.at(curr);
            auto citr = concretize_node.find(curr);
            uint8_t concretize = (citr != concretize_node.end() ? citr->second : 0);
            if (size > max_ast_size_) {
              DEBUGF("AST size too large: %d = %u\n", curr, size);
              auto left_size = ast_size_cache.at(info->l1);
              auto right_size = ast_size_cache.at(info->l2);
              if (left_size > max_ast_size_) {
                concretize |= 1;
                size -= (left_size - 1);
              }
              if (right_size > max_ast_size_) {
                concretize |= 2;
                size -= (right_size - 1);
              }
              DEBUGF("new size: %d = %u\n", curr, size);
              ast_size_cache[curr] = size;
              concretize_node[curr] = concretize;
            }

            // check for concrete ops
            uint8_t concrete_ops = concretize;
            concrete_ops |= info->l1 == 0 ? 1 : 0;
            concrete_ops |= info->l2 == 0 ? 2 : 0;
            if (concrete_ops == 3) {
              // both sides concrete, constant-fold the comparison.  For a cmp
              // node info->size is the operand width (see TaintPass), which is
              // exactly what eval_fcmp needs to decode the IEEE bit patterns.
              node->set_kind(rgd::Bool);
              node->set_boolvalue(eval_fcmp(info->op >> 8, info->op1.i, info->op2.i, info->size));
            } else {
              auto itr = OP_MAP.find(info->op);
              if (unlikely(itr == OP_MAP.end())) {
                REJECT("invalid fcmp predicate", "invalid fcmp op: %d\n", info->op);
                return INVALID_NODE;
              }
              node->set_kind(itr->second.first);
              node->set_label(curr);
#ifdef DEBUG
              subroots.insert(curr);
#endif
            }
          } else {
            // unexpected nested comparison inside an FP operand; constant-fold
            uint32_t opw = 64;
            if (info->l1 != 0) opw = get_label_info(info->l1)->size;
            else if (info->l2 != 0) opw = get_label_info(info->l2)->size;
            REJECT("nested cmp under fcmp", "unexpected nested cmp under fcmp: %d\n", info->op);
            node->set_kind(rgd::Bool);
            node->set_boolvalue(eval_fcmp(info->op >> 8, info->op1.i, info->op2.i, opw));
            node->clear_children();
          }
        } else if (info->op == __dfsan::fmemcmp) {
          // memcmp is also considered as a root node (relational comparison)
          if (unlikely(node->children_size() != 0)) {
            REJECT("nested icmp under memcmp", "memcmp should not have additional icmp");
            return INVALID_NODE;
          }
          node->set_bits(1); // XXX: treat memcmp as a boolean
          node->set_kind(rgd::Memcmp); // fix later
          node->set_label(curr);
#ifdef DEBUG
          subroots.insert(curr);
#endif
        } else {
          REJECT_OP("invalid root op", info->op, "Invalid AST node: op = %d\n", info->op);
          return INVALID_NODE;
        }

        // mark as visited and pop from stack
        visited.insert(curr);
        prev = curr;
        stack.pop_back();
        node_stack.pop_back();
      }
    }
  }
  } catch (std::out_of_range &e) {
    REJECT("ast out of range", "AST %u goes out of range at %s\n", label, e.what());
    return INVALID_NODE;
  }

  return 0;
}

[[gnu::hot]]
bool RGDAstParser::scan_labels(dfsan_label label) {
  // assuming label has been checked by caller
  // assuming the last label scanned is the size of the cache
  // turns out linear scan is way faster than tree traversal
  for (size_t i = ast_size_cache.size(); i <= label; i++) {
    if (i == 0) { // the constant label
      ast_size_cache.push_back(1); // constant takes one node too
      arg_size_cache.push_back(1); // and one constant arg slot
      branch_to_inputs.emplace_back(input_dep_t(input_size_));
      nested_cmp_cache.push_back(0);
      continue;
    }
    dfsan_label_info *info = get_label_info(i);
    // conservatively check validity of labels
    // so following parsing will not throw exceptions
    if (unlikely(info->l1 >= size_ || info->l2 >= size_)) {
      REJECT("invalid label", "invalid label: %lu, l1=%u, l2=%u\n", i, info->l1, info->l2);
      return false;
    }
    if (info->op == 0) {
      // AST nodes
      ast_size_cache.push_back(1); // one Read node
      arg_size_cache.push_back(1); // map_arg maps one byte
      // input deps
      uint32_t input_id = info->op2.i;
      uint32_t offset = info->op1.i;
      // skip if invalid
      if (unlikely(input_id >= inputs_cache.size())) {
        REJECT("invalid input id", "invalid input id: %u\n", input_id);
        return false;
      }
      size_t buf_size = inputs_cache[input_id].second;
      if (unlikely(offset >= buf_size)) {
        REJECT("invalid input offset", "invalid input offset: %u >= %lu\n", offset, buf_size);
        return false;
      }
      branch_to_inputs.emplace_back(input_dep_t(input_size_));
      // get flattened index
      size_t idx = input_to_dep_idx(input_id, offset);
      auto &itr = branch_to_inputs[i];
      itr.set(idx); // flattened location
#if DEBUG
      assert(branch_to_inputs[i].find_first() == idx);
#endif
      // nested cmp?
      nested_cmp_cache.push_back(0);
    } else if (info->op == __dfsan::Load) {
      // AST nodes
      ast_size_cache.push_back(1); // one Read node
      arg_size_cache.push_back(info->l2); // map_arg maps l2 bytes
      // input deps
      uint32_t input_id = get_label_info(info->l1)->op2.i;
      uint32_t offset = get_label_info(info->l1)->op1.i;
      // skip if invalid
      if (unlikely(input_id >= inputs_cache.size())) {
        REJECT("invalid input id", "invalid input id: %u\n", input_id);
        return false;
      }
      size_t buf_size = inputs_cache[input_id].second;
      if (unlikely(offset + info->l2 > buf_size)) {
        REJECT("invalid input offset",
               "invalid input offset: %u + %u > %lu\n", offset, info->l2, buf_size);
        return false;
      }
      branch_to_inputs.emplace_back(input_dep_t(input_size_));
      // get flattened index
      size_t idx = input_to_dep_idx(input_id, offset);
      auto &itr = branch_to_inputs[i];
      for (size_t n = 0; n < info->l2; ++n) {
        // DEBUGF("adding input: %lu <- %lu\n", i, offset + n);
        itr.set(idx + n); // input offsets
      }
#if DEBUG
      if (likely(info->l2 > 0))
        assert(branch_to_inputs[i].find_first() == idx);
#endif
      // nested cmp?
      nested_cmp_cache.push_back(0);
    } else {
      // AST nodes
      uint32_t left  = info->l1 == 0 ? 1 : ast_size_cache[info->l1];
      uint32_t right = info->l2 == 0 ? 1 : ast_size_cache[info->l2];
      ast_size_cache.push_back(left + right + 1);
      // input_args slots.  Mirrors do_uta_rel's packing, but only as an UPPER
      // bound: it double counts a subtree reached twice (do_uta_rel expands it
      // once, tracked by `visited`) and an input offset two reads share
      // (map_arg dedups those through local_map).  Over-estimating only wastes
      // capacity and under-estimating just falls back to growing the vector,
      // so neither is a correctness concern -- unlike ast_size_cache, which
      // AstNode::add_children() treats as a hard limit.
      uint32_t largs = info->l1 == 0 ? 1 : arg_size_cache[info->l1];
      uint32_t rargs = info->l2 == 0 ? 1 : arg_size_cache[info->l2];
      uint32_t args;
      switch (info->op) {
        case __dfsan::WideConst:
          // lowered to the two-slot rgd::Constant convention, low half first
          args = 2;
          break;
        case __dfsan::fmemcmp:
          // a concrete target is packed 8 bytes per slot; a symbolic one is
          // just another subtree
          args = sat_add(info->l1 == 0 ? (info->size + 7) / 8 : largs, rargs);
          break;
        case __dfsan::tlookup:
          // num_elems, then the table contents, 8 bytes per slot
          args = sat_add(largs, sat_add(1, tlookup_arg_slots(info)));
          break;
        case __dfsan::fatoi:
          // the result is introduced as fake input bytes, one slot each
          args = info->size / 8;
          break;
        case __dfsan::fstrchr:
        case __dfsan::fstrrchr:
          // a concrete haystack is packed 8 bytes per slot; the needle is a
          // single char out of op2, one slot
          args = sat_add(info->l1 == 0 ? (info->size + 7) / 8 : largs,
                         info->l2 == 0 ? 1 : rargs);
          break;
        case __dfsan::fstrstr:
        case __dfsan::fstrpbrk:
        case __dfsan::fstrcat:
        case __dfsan::fstrcmp:
        case __dfsan::fprefixof:
        case __dfsan::fsuffixof:
          // exactly one side is concrete and info->size is THAT side's byte
          // count, so only one of these two terms uses the packed figure
          args = sat_add(info->l1 == 0 ? (info->size + 7) / 8 : largs,
                         info->l2 == 0 ? (info->size + 7) / 8 : rargs);
          break;
        default:
          args = sat_add(largs, rargs);
      }
      arg_size_cache.push_back(args);
      // input deps
      branch_to_inputs.emplace_back(input_dep_t(input_size_));
      auto &itr = branch_to_inputs[i];
      if (info->l1 != 0) itr |= branch_to_inputs[info->l1];
      if (info->l2 != 0) itr |= branch_to_inputs[info->l2];
      // nested cmp?
      uint8_t nested = 0;
      nested += info->l1 == 0 ? 0 : nested_cmp_cache[info->l1];
      nested += info->l2 == 0 ? 0 : nested_cmp_cache[info->l2];
      if (info->op == __dfsan::fmemcmp || (info->op & 0xff) == __dfsan::ICmp ||
          (info->op & 0xff) == __dfsan::FCmp)
        nested += 1;
      nested_cmp_cache.push_back(nested);
    }
  }
#if DEBUG
  DEBUGF("ast_size: %d = %u\n", label, ast_size_cache[label]);
  DEBUGF("input deps %d:", label);
  auto &itr = branch_to_inputs[label];
  for (auto i = itr.find_first(); i != input_dep_t::npos; i = itr.find_next(i)) {
    DEBUGF("%lu ", i);
  }
  DEBUGF("\n");
  DEBUGF("nested cmp: %d = %d\n", label, nested_cmp_cache[label]);
#endif
  return true;
}

bool RGDAstParser::note_deps(dfsan_label label, input_dep_t &acc) {
  if (label < CONST_OFFSET || label == __dfsan::kInitializingLabel || label >= size_) {
    set_error("invalid label");
    return false;
  }
  // usually a no-op: the cache is filled linearly, so any earlier parse_cond()
  // or note_deps() for a higher label has already covered this one
  if (!scan_labels(label)) {
    return false;
  }
  if (acc.size() != input_size_) {
    acc.resize(input_size_);
  }
  acc |= branch_to_inputs[label];
  return true;
}

RGDAstParser::expr_t RGDAstParser::get_root_expr(dfsan_label label) {
  if (label < CONST_OFFSET || label == __dfsan::kInitializingLabel || label >= size_) {
    // label 0 lands here on every loop that exits by a concrete test: the
    // runtime forwards the cond message anyway.  It is still a "no task", and
    // the caller is what decides whether to count it -- see the loop-exit
    // carve-out in driver/fgtest.cpp.
    set_error("invalid label");
    return nullptr;
  }

  expr_t root = nullptr;
  auto itr = root_expr_cache.find(label);
  if (itr != root_expr_cache.end()) {
    root = itr->second;
  } else {
    // update ast_size and branch_to_inputs caches
    if (!scan_labels(label)) {
      return nullptr;
    }
    root = std::make_shared<rgd::AstNode>();
    std::unordered_set<dfsan_label> subroots;
    // we start by constructing a boolean formula with relational expressions
    // as leaf nodes
    if (find_roots(label, root.get(), subroots) != 0) {
      return nullptr;
    }
    root_expr_cache.insert({label, root});
#if DEBUG
    for (auto const& subroot : subroots) {
      DEBUGF("subroot: %d\n", subroot);
    }
#endif
  }
#if DEBUG
  printAst(stderr, root.get(), 0);
#endif

  return root;
}

[[gnu::hot]]
int RGDAstParser::to_nnf(bool expected_r, rgd::AstNode *node) {
  int ret = 0;
  if (!expected_r) {
    // we're looking for a negated formula
    if (node->kind() == rgd::LNot) {
      // double negation
      if (unlikely(node->children_size() != 1)) {
        REJECT("malformed LNot", "LNot expect a singple child\n");
        return INVALID_NODE;
      }
      rgd::AstNode *child = node->mutable_children(0);
      // transform the child, now looking for a true formula
      ret = to_nnf(true, child);
      if (unlikely(ret != 0)) { return ret; }
      node->CopyFrom(*child);
    } else if (node->kind() == rgd::LAnd) {
      // De Morgan's law
      if (unlikely(node->children_size() != 2)) {
        REJECT("malformed LAnd", "LAnd expect two children\n");
        return INVALID_NODE;
      }
      node->set_kind(rgd::LOr);
      ret = to_nnf(false, node->mutable_children(0));
      if (unlikely(ret != 0)) { return ret; }
      ret = to_nnf(false, node->mutable_children(1));
      if (unlikely(ret != 0)) { return ret; }
    } else if (node->kind() == rgd::LOr) {
      // De Morgan's law
      if (unlikely(node->children_size() != 2)) {
        REJECT("malformed LOr", "LOr expect two children\n");
        return INVALID_NODE;
      }
      node->set_kind(rgd::LAnd);
      ret = to_nnf(false, node->mutable_children(0));
      if (unlikely(ret != 0)) { return ret; }
      ret = to_nnf(false, node->mutable_children(1));
      if (unlikely(ret != 0)) { return ret; }
    } else {
      // leaf node
      if (rgd::isRelationalKind(node->kind()) ||
          rgd::isFPRelationalKind(node->kind())) {
        node->set_kind(rgd::negate_cmp(node->kind()));
      } else if (node->kind() == rgd::Memcmp) {
        // memcmp is also considered as a leaf node (relational comparison)
        // memcmp == 0 actually means s1 == s2
        // so we don't need to negate it
      } else {
        REJECT("unexpected node kind", "Unexpected node kind %d\n", node->kind());
        return INVALID_NODE;
      }
    }
  } else {
    // we're looking for a true formula
    if (node->kind() == rgd::LNot) {
      if (unlikely(node->children_size() != 1)) {
        REJECT("malformed LNot", "LNot expect a singple child\n");
        return INVALID_NODE;
      }
      rgd::AstNode *child = node->mutable_children(0);
      // negate the child, now looking for a false formula
      ret = to_nnf(false, child);
      if (unlikely(ret != 0)) { return ret; }
      node->CopyFrom(*child);
    } else if (node->kind() == rgd::Memcmp) {
      // memcmp is also considered as a leaf node (relational comparison)
      // memcmp == 1 actually means s1 != s2
      // so we negate it
      node->set_kind(rgd::MemcmpN);
    } else {
      for (int i = 0; i < node->children_size(); i++) {
        ret = to_nnf(expected_r, node->mutable_children(i));
        if (unlikely(ret != 0)) { return ret; }
      }
    }
  }

  return 0;
}

[[gnu::hot]]
void RGDAstParser::to_dnf(const rgd::AstNode *node, formula_t &formula) {
  if (node->kind() == rgd::LAnd) {
    formula_t left, right;
    to_dnf(&node->children(0), left);
    to_dnf(&node->children(1), right);
    for (auto const& sub1: left) {
      for (auto const& sub2: right) {
        clause_t clause;
        clause.insert(clause.end(), sub1.begin(), sub1.end());
        clause.insert(clause.end(), sub2.begin(), sub2.end());
        formula.push_back(clause);
      }
    }
    if (left.size() == 0) {
      formula = right;
    }
  } else if (node->kind() == rgd::LOr) {
    // copy the clauses from the children
    to_dnf(&node->children(0), formula);
    to_dnf(&node->children(1), formula);
  } else {
    clause_t clause;
    clause.push_back(node);
    formula.push_back(clause);
  }
}

int RGDAstParser::parse_cond(dfsan_label label, bool result, bool add_nested,
                             std::vector<uint64_t> &tasks) {
  // a reason left over from the previous call would otherwise be attributed to
  // this one, silently, on any path that comes back empty without setting one
  clear_error();

  // given a condition, we want to parse them into a DNF form of
  // relational sub-expressions, where each sub-expression only contains
  // one relational operator at the root
  expr_t orig_root = get_root_expr(label);
  if (orig_root == nullptr) {
    REJECT_IF_UNSET("no root expr", "failed to get root expr for label %u\n", label);
    return -1;
  } else if (orig_root->kind() == rgd::Bool) {
    // if the simplified formula is a boolean constant, nothing to do
    DEBUGF("cond simplified to be a constant\n");
    // no task, and worth saying so: this is the single largest source of
    // branches we never attempt on a real target, and roughly half of it is
    // our own folding rather than the program's own dead test
    set_error("cond folded to constant");
    return 0;
  }

  // duplication the original root for transformation
  expr_t root = std::make_shared<rgd::AstNode>();
  root->CopyFrom(*orig_root);

  // next, convert the formula to NNF form, possibly negate the root
  // if we are looking for a false formula
  bool target_direction = !result;
  if (to_nnf(target_direction, root.get()) != 0) {
    REJECT_IF_UNSET("nnf conversion failed", "failed to convert to NNF\n");
    return -1;
  }
#if DEBUG
  printAst(stderr, root.get(), 0);
#endif
  // then we need to convert the boolean formula into a DNF form
  formula_t dnf;
  to_dnf(root.get(), dnf);

  // finally, we construct a search task for each clause in the DNF
  for (auto const& clause : dnf) {
    task_t task = construct_task(clause);
    if (task != nullptr) {
      tasks.push_back(save_task(task));
    } else {
      REJECT_IF_UNSET("no parsable constraint in clause", "failed to construct task for clause\n");
      continue; // skip the nested task if the current task is invalid
    }

    if (solve_nested_) {
      // collect dependencies based on data-flow (i.e., shared input bytes)
      clause_t nested_caluse;
      std::unordered_set<dfsan_label> inserted;
      // first, copy the last branch constraints
      nested_caluse.insert(nested_caluse.end(), clause.begin(), clause.end());
      for (auto const& var : clause) inserted.insert(var->label());
      bool has_nested = false;
      // then, iterate each var in the clause
      for (auto const& var: clause) {
        const dfsan_label l = var->label();
        // assert(branch_to_inputs.size() > l);
        auto &itr = branch_to_inputs[l];
        auto citr = concretize_node.find(l);
        if (unlikely(citr != concretize_node.end())) {
          // skip dependencies if the operand is concretized
          if (citr->second == 1) {
            // if the lhs is concretized, use the rhs deps only
            itr = branch_to_inputs[get_label_info(l)->l2];
          } else if (citr->second == 2) {
            // if the rhs is concretized, use the lhs deps only
            itr = branch_to_inputs[get_label_info(l)->l1];
          }
        }
        if (unlikely(itr.find_first() == input_dep_t::npos)) {
          // not actual input dependency, skip
          continue;
        }
        // for each input byte used in the var, we collect additional constraints
        // first, we use union find to add additional related input bytes
        std::unordered_set<size_t> related_inputs;
        for (auto input = itr.find_first(); input != input_dep_t::npos;
             input = itr.find_next(input)) {
          data_flow_deps.get_set(input, related_inputs); // FIXME: should be fine?
        }
        // then, we collect the branch constraints for each related input byte
        for (auto input: related_inputs) {
          auto const& bucket = input_to_branches[input];
          for (auto const& nc : bucket) {
            if (inserted.count(nc->label())) continue;
            inserted.insert(nc->label());
            has_nested = true;
#if DEBUG
            fprintf(stderr, "add nested constraint: (%d, %d)\n", nc->label(), nc->kind());
#endif
            nested_caluse.push_back(nc.get()); // XXX: borrow the raw ptr, should be fine?
          }
        }
      }
      if (has_nested) { // only add nested task if there are additional constraints
        task_t nested_task = construct_task(nested_caluse);
        if (nested_task != nullptr) {
          nested_task->base_task = task;
          tasks.push_back(save_task(nested_task));
        }
      }
    }
  }

  if (solve_nested_ && add_nested) {
    save_constraint(orig_root, result);
  }

  return 0;
}

bool RGDAstParser::save_constraint(expr_t expr, bool result) {
  // assumes scan_labels has been called

  // make a copy of the expr, just in case
  expr_t root = std::make_shared<rgd::AstNode>();
  root->CopyFrom(*expr);

  // first, convert the formula to NNF form, possibly negate the root
  // if we are looking for a false formula
  if (to_nnf(result, root.get()) != 0) {
    return false;
  }
#if DEBUG
  printAst(stderr, root.get(), 0);
#endif
  // then we need to convert the boolean formula into a DNF form
  // NOTE: all ptrs in the formula are raw ptrs *temporarily*
  // burrowed from the root expr, they will be gone after return
  formula_t dnf;
  to_dnf(root.get(), dnf);

  // now we associate the constraints with input bytes
  for (auto const& clause : dnf) {
    // each clause is a conjunction of relational expressions
    // that need to be evaluated to true (satisfied)
    // we associate that with the corresponding input bytes
    for (auto const& var : clause) {
      // copy the node, as the original node will be gone after return
      expr_t node = std::make_shared<rgd::AstNode>();
      node->CopyFrom(*var);
      // get the input bytes
      const dfsan_label l = node->label();
#if DEBUG
      assert(branch_to_inputs.size() > l);
#endif
      auto &itr = branch_to_inputs[l];
      auto citr = concretize_node.find(l);
      if (unlikely(citr != concretize_node.end())) {
        if (citr->second == 1) {
          // if the lhs is concretized, use the rhs deps only
          itr = branch_to_inputs[get_label_info(l)->l2];
        } else if (citr->second == 2) {
          // if the rhs is concretized, use the lhs deps only
          itr = branch_to_inputs[get_label_info(l)->l1];
        }
      }
      auto root = itr.find_first();
      if (root == input_dep_t::npos) {
        // not actual input dependency, skip
        // this can happen for atoi
        continue;
      }
      // update uion find
      for (auto input = itr.find_next(root); input != input_dep_t::npos;
           input = itr.find_next(input)) {
#if DEBUG
        DEBUGF("union input bytes: (%zu, %zu)\n", root, input);
#endif
        root = data_flow_deps.merge(root, input);
        if (unlikely(root == rgd::UnionFind::INVALID)) {
          REJECT("union find failed", "invalid input to union find\n");
          return false;
        }
      }
      // add the constraint
      auto &bucket = input_to_branches[root];
      bucket.push_back(node);
      // we need to record the kind as it may be negated during transformation
#if DEBUG
      DEBUGF("add df constraint: %zu <- (%d, %d)\n", root, l, node->kind());
#endif
    }
  }

  return true;
}

void RGDAstParser::add_nested_constraint(task_t task, const clause_t &nested_caluse) {
  for (auto const& node: nested_caluse) {
    // check cache, should happen most of the time
    auto itr = constraint_cache.find(node->label());
    if (likely(itr != constraint_cache.end())) {
      task->add_constraint(itr->second, node->kind());
      continue;
    }
    // otherwise, parse the AST into a constraint
    constraint_t constraint = parse_constraint(node->label());
    if (likely(constraint != nullptr)) {
      task->add_constraint(constraint, node->kind());
      constraint_cache.insert({node->label(), constraint});
    }
  }
}

int RGDAstParser::parse_gep(dfsan_label ptr_label, uptr ptr,
                            dfsan_label index_label, int64_t index,
                            uint64_t num_elems, uint64_t elem_size,
                            int64_t current_offset, bool enum_index,
                            std::vector<uint64_t> &tasks) {
  // see parse_cond: a stale reason would be read as this call's
  clear_error();

  // check validity of the labels
  if (index_label < CONST_OFFSET || index_label == __dfsan::kInitializingLabel
      || index_label >= size_) {
    set_error("invalid label");
    return -1;
  }

  // update ast_size and branch_to_inputs caches
  // if the index_label has been scanned before, it won't be scanned again
  if (!scan_labels(index_label)) {
    return -1;
  }

  // sanity checks
  if (unlikely(ast_size_cache.size() <= index_label)) {
    REJECT("label beyond ast size cache",
           "invalid label %u, larger than ast_size_cache: %lu\n",
           index_label, ast_size_cache.size());
    return -1;
  }
  if (unlikely(nested_cmp_cache.at(index_label) > 0)) {
    REJECT("nested cmp in gep index",
           "unexpected nested cmp in parse_gep for %u, skip\n", index_label);
    return -1;
  }

  auto ast_size = ast_size_cache.at(index_label);
  if (unlikely(ast_size == 0)) {
    REJECT("ast size zero", "invalid label %u, ast_size_cache is 0\n", index_label);
    return 0;
  } else if (unlikely(ast_size > max_ast_size_)) {
    DEBUGF("skip large AST (%lu) in parse_gep for %u\n", ast_size, index_label);
    // DEBUGF, so silent in a release build -- but it still costs a branch, and
    // the sweep should be able to see how many
    set_error("ast too large");
    return 0; // not an error, just skip
  }

  // early return if nothing to do
  if (!enum_index || // if we are not enumerating the index
      (num_elems == 0 && // if the GEP type is not an array,
       // and we also don't have a pointer label
       ptr_label)) {
    return 0;
  }

  // hmm, since the gep constraints we want to solve are not in the union table,
  // which means parse_constraint will not work,
  // so we have to construct the tasks directly here
  //

  // first, parse the index_label into a partial constraint
  // again, the index_label is not a cmp node
  constraint_t partial_constraint = nullptr;
  // check cache first
  auto itr = constraint_cache.find(index_label);
  if (itr != constraint_cache.end()) {
    partial_constraint = itr->second;
  } else {
    // otherwise, parse the AST into a constraint
    std::unordered_set<dfsan_label> visited;
    // +1 arg slot for the placeholder constant node added just below
    partial_constraint = std::make_shared<rgd::Constraint>(
        ast_size + 3, // leave extra one buffer?
        sat_add(arg_size_cache.at(index_label), 1));

    // add the constant node first
    auto const_node = partial_constraint->ast->add_children();
    const_node->set_kind(rgd::Constant);
    const_node->set_label(0);
    uint32_t size = get_label_info(index_label)->size;
    const_node->set_bits(size); // size of the index
    // map args
    uint32_t arg_index = 0; // first arg
    const_node->set_index(arg_index);
    partial_constraint->input_args.push_back(std::make_pair(false, 0)); // use 0 as a temporary placeholder
    partial_constraint->const_num += 1;
    uint32_t hash = rgd::xxhash(size, rgd::Constant, arg_index);
    const_node->set_hash(hash);

    // now, parse the index_label
    auto index_node = partial_constraint->ast->add_children();
    try {
      if (!do_uta_rel(index_label, index_node, partial_constraint, visited)) {
        REJECT_IF_UNSET("gep index parse failed", "failed to parse index_label %u\n", index_label);
        return -1;
      }
    } catch (std::bad_alloc &e) {
      REJECT("out of memory", "failed to allocate memory for gep constraint\n");
      return -1;
    } catch (std::out_of_range &e) {
      REJECT("ast out of range", "AST %u goes out of range at %s\n", index_label, e.what());
      return -1;
    }

    // setup root cmp node
    auto cmp_node = partial_constraint->ast.get();
    cmp_node->set_kind(rgd::Equal); // a placeholder, not really useful
    cmp_node->set_label(0); // so jigsaw will not cache it as visited
    cmp_node->set_bits(1);
    // again, in jigsaw, we don't care about actual cmp kind
    hash = rgd::xxhash(const_node->hash(), (rgd::Bool << 16) | 1, index_node->hash());
    cmp_node->set_hash(hash);

    // done parsing, add to cache
    constraint_cache.insert({index_label, partial_constraint});
  }

  if (unlikely(partial_constraint == nullptr)) {
    REJECT_IF_UNSET("gep index parse failed", "failed to parse index_label %u\n", index_label);
    return -1;
  }

  // next, retrive nested constraints if needed
  clause_t nested_caluse;
  if (solve_nested_) {
    auto &itr = branch_to_inputs[index_label];
    if (unlikely(itr.find_first() != input_dep_t::npos)) {
      // use union find to add additional related input bytes
      std::unordered_set<size_t> related_inputs;
      for (auto input = itr.find_first(); input != input_dep_t::npos;
           input = itr.find_next(input)) {
        data_flow_deps.get_set(input, related_inputs); // FIXME: should be fine?
      }
      // collect the branch constraints for each related input byte
      std::unordered_set<dfsan_label> inserted;
      for (auto input: related_inputs) {
        auto const& bucket = input_to_branches[input];
        for (auto const& nc : bucket) {
          if (inserted.insert(nc->label()).second) {
#if DEBUG
            fprintf(stderr, "add nested constraint for gep: (%d, %d)\n", nc->label(), nc->kind());
#endif
            nested_caluse.push_back(nc.get()); // XXX: borrow the raw ptr, should be fine?
          }
        }
      }
    }
  }

  // finally, we are ready to construct GEP tasks
  //

  if (enum_index) {
    // TODO:
  }

  // bounds solving are seperated from index enumeration now

  return 0;
}

int RGDAstParser::add_constraints(dfsan_label label, uint64_t result) {
  // offset constraint should be in the form of r = (offset == label) = true
  if (!solve_nested_) {
    // only matters in nested mode
    return 0;
  }
  // see parse_cond: a stale reason would be read as this call's
  clear_error();

  // check validity of the label
  if (label < CONST_OFFSET || label == __dfsan::kInitializingLabel || label >= size_) {
    set_error("invalid label");
    return -1;
  }
  // check validity of the result
  if (result != 1) {
    REJECT("unexpected offset constraint result",
           "unexpected result in add_constraints: %lu\n", result);
    return -1;
  }

  expr_t root = nullptr;
  auto itr = root_expr_cache.find(label);
  if (itr != root_expr_cache.end()) {
    // the constraint has already been added, skip
    return 0;
  }

  // update ast_size and branch_to_inputs caches
  if (!scan_labels(label)) {
    return -1;
  }
  // other sanitity checks
  // 1. there shouldn't be any nested cmp
  if (nested_cmp_cache[label] > 0) {
    REJECT("nested cmp in offset constraint",
           "unexpected nested cmp in add_constraints for %u\n", label);
    return -1;
  }
  dfsan_label_info *info = get_label_info(label);
  // 2. the label should be a bveq one
  if (!is_rel_cmp(info->op, __dfsan::bveq)) {
    REJECT("non-eq offset constraint",
           "unexpected cmp op (%d) in add_constraints for %u\n", info->op, label);
    return -1;
  }
  // 3. one operand should be a constant
  if (info->l1 != 0) {
    REJECT("non-constant offset operand",
           "unexpected non-constant operand1 (%u) in add_constraints for %u\n", info->l1, label);
    return -1;
  }
  // check for ast size
  if (ast_size_cache[info->l2] > max_ast_size_) {
    DEBUGF("skip large AST (%lu) in add_constraints for %u\n", ast_size_cache[label], label);
    set_error("ast too large"); // see parse_gep: DEBUGF, so otherwise invisible
    return 0; // not an error, just skip
  }
  // setup node
  root = std::make_shared<rgd::AstNode>(1);
  root->set_bits(1);
  root->set_kind(rgd::Equal);
  root->set_label(label);
  root_expr_cache.insert({label, root});

  if (!save_constraint(root, true)) {
    return -1;
  }

  return 0;
}
