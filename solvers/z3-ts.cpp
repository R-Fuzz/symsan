#include "dfsan/dfsan.h"

#include "parse-z3.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <unistd.h>

using namespace symsan;

#define FILTER_WRONG_AST 1

static const std::unordered_map<unsigned, const char*> OP_MAP {
  {__dfsan::Extract, "Extract"},
  {__dfsan::Trunc,   "Trunc"},
  {__dfsan::Concat,  "Concat"},
  {__dfsan::ZExt,    "Zext"},
  {__dfsan::SExt,    "Sext"},
  {__dfsan::Add,     "Add"},
  {__dfsan::Sub,     "Sub"},
  {__dfsan::Mul,     "Mul"},
  {__dfsan::UDiv,    "Udiv"},
  {__dfsan::SDiv,    "Sdiv"},
  {__dfsan::URem,    "Urem"},
  {__dfsan::SRem,    "Srem"},
  {__dfsan::Shl,     "Shl"},
  {__dfsan::LShr,    "Lshr"},
  {__dfsan::AShr,    "Ashr"},
  {__dfsan::And,     "And"},
  {__dfsan::Or,      "Or"},
  {__dfsan::Xor,     "Xor"},
  // relational comparisons
#define RELATIONAL_ICMP(cmp) (__dfsan::ICmp | (cmp << 8))
  {RELATIONAL_ICMP(__dfsan::bveq),  "Equal"},
  {RELATIONAL_ICMP(__dfsan::bvneq), "Distinct"},
  {RELATIONAL_ICMP(__dfsan::bvugt), "Ugt"},
  {RELATIONAL_ICMP(__dfsan::bvuge), "Uge"},
  {RELATIONAL_ICMP(__dfsan::bvult), "Ult"},
  {RELATIONAL_ICMP(__dfsan::bvule), "Ule"},
  {RELATIONAL_ICMP(__dfsan::bvsgt), "Sgt"},
  {RELATIONAL_ICMP(__dfsan::bvsge), "Sge"},
  {RELATIONAL_ICMP(__dfsan::bvslt), "Slt"},
  {RELATIONAL_ICMP(__dfsan::bvsle), "Sle"},
#undef RELATIONAL_ICMP
  // higher-order string ops
  {__dfsan::fstrchr,  "strchr"},
  {__dfsan::fstrrchr, "strrchr"},
  {__dfsan::fstrstr,  "strstr"},
  {__dfsan::fstrpbrk, "strpbrk"},
  {__dfsan::fstr_off, "stroff"},
  {__dfsan::fsubstr,  "substr"},
  {__dfsan::fstrcat,  "strcat"},
  {__dfsan::fprefixof, "prefixof"},
  {__dfsan::fsuffixof, "suffixof"},
  {__dfsan::flength, "length"},
};

static std::string get_op_name(uint32_t op) {
  auto itr = OP_MAP.find(op);
  if (itr != OP_MAP.end()) {
    return itr->second;
  }
  return std::to_string(op);
}

// Check if an op is a string operation (fstr_op_start to fstr_op_end)
static inline bool is_string_op(uint16_t op) {
  return op >= __dfsan::fstr_op_start && op < __dfsan::fstr_op_end;
}

// Check if an op is an indexOf-type operation (returns position, not content)
// These are: fstrchr, fstrrchr, fstrstr, fstrpbrk, fstr_off
static inline bool is_indexof_op(uint16_t op) {
  return op >= __dfsan::fstrchr && op <= __dfsan::fstr_off;
}

// Check if an op is a content-type string operation (fsubstr, fstrcat)
static inline bool is_content_string_op(uint16_t op) {
  return op == __dfsan::fsubstr || op == __dfsan::fstrcat;
}

// Helper function to check if label tree contains indexOf operations
// (used to skip validation since op1 is repurposed for haystack pointer)
bool Z3AstParser::label_contains_indexof(dfsan_label label) {
  if (label < CONST_OFFSET) return false;

  dfsan_label_info *info = get_label_info(label);
  if (is_indexof_op(info->op)) return true;

  // Recursively check dependencies
  if (info->l1 >= CONST_OFFSET && label_contains_indexof(info->l1)) return true;
  if (info->l2 >= CONST_OFFSET && label_contains_indexof(info->l2)) return true;

  return false;
}

// Decode Z3's escaped string format (e.g., "\u{1}\u{2}" -> bytes 0x01, 0x02)
static std::vector<uint8_t> decode_z3_string(const std::string &str) {
  std::vector<uint8_t> result;
  size_t i = 0;
  while (i < str.size()) {
    if (i + 3 < str.size() && str[i] == '\\' && str[i+1] == 'u' && str[i+2] == '{') {
      // Parse \u{XXXX} escape sequence
      size_t end = str.find('}', i + 3);
      if (end != std::string::npos) {
        std::string hex_str = str.substr(i + 3, end - (i + 3));
        uint32_t code_point = std::stoul(hex_str, nullptr, 16);
        // For simplicity, assume code points fit in a byte (for ASCII/Latin-1)
        result.push_back((uint8_t)(code_point & 0xFF));
        i = end + 1;
        continue;
      }
    }
    // Regular character
    result.push_back((uint8_t)str[i]);
    i++;
  }
  return result;
}

void Z3AstParser::dump_value_cache(dfsan_label label) {
  if (label >= value_cache_.size()) {
    throw z3::exception("invalid label for value cache");
  }
  dfsan_label_info *info = get_label_info(label);
  fprintf(stderr, "label %u = l1: %u, l2: %u, op: %s, size: %u, op1: %lu, op2: %lu\n",
          label, info->l1, info->l2, get_op_name(info->op).c_str(), info->size,
          info->op1.i, info->op2.i);
  fprintf(stderr, "recalcuated value: %lu = op1: %lu, op2: %lu\n",
          value_cache_[label], value_cache_[info->l1], value_cache_[info->l2]);
  if (info->l1 != 0)
    dump_value_cache(info->l1);
  if (info->l2 != 0)
    dump_value_cache(info->l2);
}

Z3AstParser::Z3AstParser(void *base, size_t size, z3::context &context)
  : ASTParser(base, size), context_(context) {
    input_name_format = "input-%u-%u";
    atoi_name_format = "atoi-%u-%u-%d-%lu";       // input, offset, base, original_len
    strlen_name_format = "strlen-%u-%u-%lu-%u";   // input, offset, original_len, null_from_input
    str_name_format = "str-%u-%u-%u";             // input, offset, length
    int_name_format = "int-%u-%u-%u";             // input, offset, bits
  }

int Z3AstParser::restart(std::vector<input_t> &inputs, bool copy_input) {

  // reset caches
  memcmp_cache_.clear();
  string_ranges_.clear();
  string_ranges_.resize(inputs.size()); // vector indexed by input_id
  tsize_cache_.clear();
  tsize_cache_.resize(1); // reserve for CONST_OFFSET
  for (Z3_ast ast : expr_cache_) {
    if (ast != nullptr) {
      Z3_dec_ref(context_, ast); // decrement reference count
    }
  }
  expr_cache_.clear();
  expr_cache_.resize(1); // reserve for CONST_OFFSET
  deps_cache_.clear();
  deps_cache_.resize(1); // reserve for CONST_OFFSET
#if FILTER_WRONG_AST
  value_cache_.clear();
  value_cache_.resize(1); // reserve for CONST_OFFSET
#endif
  // Label-level tracking caches
  is_label_bv_.clear();
  is_label_bv_.resize(1);  // reserve for CONST_OFFSET
  is_label_seq_.clear();
  is_label_seq_.resize(1); // reserve for CONST_OFFSET

  aux_constraints_.clear();
  minimize_hints_.clear();
  string_info_cache_.clear();
  branch_deps_.clear();
  branch_deps_.resize(inputs.size());
  for (size_t i = 0; i < inputs.size(); i++) {
    auto &input = inputs[i];
    branch_deps_[i].resize(input.second);
  }

  // Clear old cached data
  inputs_cache_.clear();
  inputs_copy_.clear();

#if FILTER_WRONG_AST
  if (copy_input) {
    // Copy input data and point inputs_cache_ to our owned copies
    inputs_copy_.resize(inputs.size());
    for (size_t i = 0; i < inputs.size(); i++) {
      auto &input = inputs[i];
      inputs_copy_[i].assign(input.first, input.first + input.second);
      inputs_cache_.emplace_back(inputs_copy_[i].data(), inputs_copy_[i].size());
    }
  } else {
    // Just store pointers (caller must keep data alive)
    for (size_t i = 0; i < inputs.size(); i++) {
      auto &input = inputs[i];
      inputs_cache_.emplace_back(input.first, input.second);
    }
  }
#endif

  return 0;
}

z3::expr Z3AstParser::read_concrete(dfsan_label label, uint16_t size) {
  auto itr = memcmp_cache_.find(label);
  if (itr == memcmp_cache_.end()) {
    throw z3::exception("cannot find memcmp content");
  }

  z3::expr val = context_.bv_val(itr->second[0], 8);
  for (uint8_t i = 1; i < size; i++) {
    val = z3::concat(context_.bv_val(itr->second[i], 8), val);
  }
  return val;
}

static z3::expr get_cmd(z3::expr const &lhs, z3::expr const &rhs, uint32_t predicate) {
  // For Int operands, unsigned comparisons reduce to regular Int comparisons
  // since Int variables are bounded to [0, 2^bits) by aux_constraints_
  bool is_int = lhs.get_sort().is_int();
  switch (predicate) {
    case __dfsan::bveq:  return lhs == rhs;
    case __dfsan::bvneq: return lhs != rhs;
    case __dfsan::bvugt: return is_int ? (lhs > rhs) : z3::ugt(lhs, rhs);
    case __dfsan::bvuge: return is_int ? (lhs >= rhs) : z3::uge(lhs, rhs);
    case __dfsan::bvult: return is_int ? (lhs < rhs) : z3::ult(lhs, rhs);
    case __dfsan::bvule: return is_int ? (lhs <= rhs) : z3::ule(lhs, rhs);
    case __dfsan::bvsgt: return lhs > rhs;
    case __dfsan::bvsge: return lhs >= rhs;
    case __dfsan::bvslt: return lhs < rhs;
    case __dfsan::bvsle: return lhs <= rhs;
    default:
      throw z3::exception("unsupported predicate");
      break;
  }
  // should never reach here
  // std::unreachable();
}

static bool eval_icmp(uint16_t predicate, uint64_t val1, uint64_t val2, uint8_t bits) {
  switch (predicate) {
    case __dfsan::bveq:  return val1 == val2;
    case __dfsan::bvneq: return val1 != val2;
    case __dfsan::bvugt: return val1 > val2;
    case __dfsan::bvuge: return val1 >= val2;
    case __dfsan::bvult: return val1 < val2;
    case __dfsan::bvule: return val1 <= val2;
    case __dfsan::bvsgt:
      switch(bits) {
        case 8:  return (int8_t)val1 > (int8_t)val2;
        case 16: return (int16_t)val1 > (int16_t)val2;
        case 32: return (int32_t)val1 > (int32_t)val2;
        case 64: return (int64_t)val1 > (int64_t)val2;
        default:
          throw z3::exception("unsupported bits for signed comparison");
      }
    case __dfsan::bvsge:
      switch(bits) {
        case 8:  return (int8_t)val1 >= (int8_t)val2;
        case 16: return (int16_t)val1 >= (int16_t)val2;
        case 32: return (int32_t)val1 >= (int32_t)val2;
        case 64: return (int64_t)val1 >= (int64_t)val2;
        default:
          throw z3::exception("unsupported bits for signed comparison");
      }
    case __dfsan::bvslt:
      switch(bits) {
        case 8:  return (int8_t)val1 < (int8_t)val2;
        case 16: return (int16_t)val1 < (int16_t)val2;
        case 32: return (int32_t)val1 < (int32_t)val2;
        case 64: return (int64_t)val1 < (int64_t)val2;
        default:
          throw z3::exception("unsupported bits for signed comparison");
      }
    case __dfsan::bvsle:
      switch(bits) {
        case 8:  return (int8_t)val1 <= (int8_t)val2;
        case 16: return (int16_t)val1 <= (int16_t)val2;
        case 32: return (int32_t)val1 <= (int32_t)val2;
        case 64: return (int64_t)val1 <= (int64_t)val2;
        default:
          throw z3::exception("unsupported bits for signed comparison");
      }
    default:
      throw z3::exception("unsupported predicate");
      return false; // unsupported predicate
  }
  // should never reach here
  // std::unreachable();
}

uint64_t Z3AstParser::serialize_input(dfsan_label label, uint32_t input, uint32_t offset,
                                      uint32_t bytes, input_dep_set_t &input_deps) {
  char name[256];
  snprintf(name, sizeof(name), input_name_format, input, offset);
  z3::symbol symbol = context_.str_symbol(name);
  z3::sort sort = context_.bv_sort(8);
  z3::expr first_byte = context_.constant(symbol, sort);
  z3::expr out = first_byte;
  { // for ucsan, due to lazy init, the input may be empty
    if (input >= branch_deps_.size()) branch_deps_.resize(input + 1);
    if (offset >= branch_deps_[input].size())
      branch_deps_[input].resize(offset + bytes);
  }
  // Cache first byte in branch_dependency for linking (linear scan: always new)
  set_branch_dep({input, offset}, std::make_unique<branch_dependency_t>(first_byte));
  uint64_t val = 0;
#if FILTER_WRONG_AST
  if (inputs_cache_.size() > input &&
      inputs_cache_[input].second > offset) {
    val = (uint64_t)inputs_cache_[input].first[offset];
  }
#endif
  for (uint32_t i = 1; i < bytes; i++) {
    snprintf(name, sizeof(name), input_name_format, input, offset + i);
    symbol = context_.str_symbol(name);
    z3::expr byte_expr = context_.constant(symbol, sort);
    out = z3::concat(byte_expr, out);
    input_deps.insert(std::make_pair(input, offset + i));
    // Cache each byte expr in branch_dependency (linear scan: always new)
    set_branch_dep({input, offset + i}, std::make_unique<branch_dependency_t>(byte_expr));
#if FILTER_WRONG_AST
    if (inputs_cache_.size() > input &&
        inputs_cache_[input].second > offset + i) {
      val |= (uint64_t)inputs_cache_[input].first[offset + i] << (i * 8);
    }
#endif
  }

  tsize_cache_.emplace_back(1);
  cache_expr(label, out);

  return val;
}

z3::expr Z3AstParser::serialize(dfsan_label label, input_dep_set_t &deps) {
  if (label < CONST_OFFSET || label == __dfsan::kInitializingLabel) {
    throw z3::exception("invalid label");
  }

  dfsan_label last_label = expr_cache_.size() - 1;
  if (label > expr_cache_.capacity()) {
    // reserve more caches if needed
    tsize_cache_.reserve(label + SIZE_INCREMENT);
    expr_cache_.reserve(label + SIZE_INCREMENT);
    deps_cache_.reserve(label + SIZE_INCREMENT);
#if FILTER_WRONG_AST
    value_cache_.reserve(label + SIZE_INCREMENT);
#endif
    is_label_bv_.reserve(label + SIZE_INCREMENT);
    is_label_seq_.reserve(label + SIZE_INCREMENT);
  }

  for (dfsan_label l = last_label + 1; l <= label; l++) {

#if FILTER_WRONG_AST
#define RECORD_VALUE(value) \
  value_cache_.emplace_back((uint64_t)(value))
#else
#define RECORD_VALUE(value) \
  do { } while (0)
#endif

// Helper macros for tracking label types (bitvec vs string/seq)
// Most ops are bitvec; string ops are seq; And/Or/ICmp propagate from children
#define TRACK_LABEL_BV_ONLY() \
  is_label_bv_.emplace_back(true); \
  is_label_seq_.emplace_back(false)

#define TRACK_LABEL_SEQ_ONLY() \
  is_label_bv_.emplace_back(false); \
  is_label_seq_.emplace_back(true)

#define TRACK_LABEL_PROPAGATE_BOTH() \
  do { \
    bool bv = (info->l1 >= CONST_OFFSET) ? is_label_bv_[info->l1] : false; \
    bool seq = (info->l1 >= CONST_OFFSET) ? is_label_seq_[info->l1] : false; \
    if (info->l2 >= CONST_OFFSET) { \
      bv = bv || is_label_bv_[info->l2]; \
      seq = seq || is_label_seq_[info->l2]; \
    } \
    is_label_bv_.emplace_back(bv); \
    is_label_seq_.emplace_back(seq); \
  } while (0)

    dfsan_label_info *info = get_label_info(l);
    // fprintf(stderr, "%u = (l1:%u, l2:%u, op:%s, size:%u, op1:%lu, op2:%lu)\n",
    //         l, info->l1, info->l2, get_op_name(info->op).c_str(),
    //         info->size, info->op1.i, info->op2.i);
    input_dep_set_t &input_deps = deps_cache_.emplace_back();

    // special ops
    char name[256];
    if (info->op == 0) {
      // input
      uint32_t offset = info->op1.i; // legacy: offset in op1
      uint32_t input = info->op2.i;
      uint64_t val = serialize_input(l, input, offset, info->size / 8, input_deps);
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(val);
      continue;
    } else if (info->op == __dfsan::Load) {
      uint32_t offset = get_label_info(info->l1)->op1.i; // legacy: offset in op1
      uint32_t input = get_label_info(info->l1)->op2.i;
      input_deps.insert(std::make_pair(input, offset));
      uint64_t val = serialize_input(l, input, offset, info->l2, input_deps);
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(val);
      continue;
    } else if (info->op == __dfsan::ZExt) {
      z3::expr base = get_cached_expr(info->l1, input_deps);
      if (base.is_bool()) // dirty hack since llvm lacks bool
        base = z3::ite(base, context_.bv_val(1, 1),
                            context_.bv_val(0, 1));
      uint32_t base_size = base.get_sort().bv_size();
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, z3::zext(base, info->size - base_size));
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(value_cache_[info->l1] & ((1UL << base_size) - 1));
      continue;
    } else if (info->op == __dfsan::SExt) {
      z3::expr base = get_cached_expr(info->l1, input_deps);
      uint32_t base_size = base.get_sort().bv_size();
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, z3::sext(base, info->size - base_size));
      TRACK_LABEL_BV_ONLY();
      // Sign extend: shift left to put sign bit at MSB, then arithmetic shift right
      uint64_t base_val = value_cache_[info->l1] & ((1UL << base_size) - 1);
      RECORD_VALUE(((int64_t)(base_val << (64 - base_size))) >> (64 - base_size));
      continue;
    } else if (info->op == __dfsan::Trunc) {
      z3::expr base = get_cached_expr(info->l1, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, base.extract(info->size - 1, 0));
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(value_cache_[info->l1] & ((1UL << info->size) - 1));
      continue;
    } else if (info->op == __dfsan::IntToPtr) {
      z3::expr e = get_cached_expr(info->l1, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, e);
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(value_cache_[info->l1]);
      continue;
    } else if (info->op == __dfsan::PtrToInt) {
      // PtrToInt converts a pointer to integer
      // If the source is a string op result, convert the index to bitvector
      if (info->l1 >= CONST_OFFSET) {
        dfsan_label_info *src_info = get_label_info(info->l1);
        if (src_info->op >= __dfsan::fstr_op_start && src_info->op < __dfsan::fstr_op_end) {
          // String op result (indexof) is Int sort — keep it as Int
          // instead of int2bv which creates expensive mixed BV+string theory.
          // Downstream Add/Sub/ICmp will detect Int operands and stay in Int domain,
          // converting BV operands to fresh Int variables (intbyte-...) as needed.
          z3::expr idx = get_cached_expr(info->l1, input_deps);
          tsize_cache_.emplace_back(tsize_cache_[info->l1]);
          cache_expr(l, idx);  // keep Int sort
          TRACK_LABEL_SEQ_ONLY();
          RECORD_VALUE(value_cache_[info->l1]);
          continue;
        }
      }
      // For other PtrToInt cases, pass through (shouldn't normally reach here)
      z3::expr e = get_cached_expr(info->l1, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, e);
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(value_cache_[info->l1]);
      continue;
    } //FIXME: other casting ops (BitCast)?
    // symsan-defined
    else if (info->op == __dfsan::Extract) {
      z3::expr base = get_cached_expr(info->l1, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, base.extract((info->op2.i + info->size) - 1, info->op2.i));
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE((value_cache_[info->l1] >> info->op2.i) &
                    ((1UL << info->size) - 1));
      continue;
    } else if (info->op == __dfsan::Not) {
      if (info->l2 == 0 || info->size != 1) {
        throw z3::exception("invalid Not operation");
      }
      z3::expr e = get_cached_expr(info->l2, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l2]);
      if (!e.is_bool()) {
        throw z3::exception("Only LNot should be recorded");
      }
      cache_expr(l, !e);
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(!value_cache_[info->l2]);
      continue;
    } else if (info->op == __dfsan::Neg) {
      if (info->l2 == 0) {
        throw z3::exception("invalid Neg predicate");
      }
      z3::expr e = get_cached_expr(info->l2, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l2]);
      cache_expr(l, -e);
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(-value_cache_[info->l2]);
      continue;
    }
    // higher-order
    else if (info->op == __dfsan::fmemcmp) {
      z3::expr op1 = (info->l1 >= CONST_OFFSET) ?
                     get_cached_expr(info->l1, input_deps) :
                     read_concrete(l, info->size); // memcmp size in bytes
      if (info->l2 < CONST_OFFSET) {
        throw z3::exception("invalid memcmp operand2");
      }
      z3::expr op2 = get_cached_expr(info->l2, input_deps);
      tsize_cache_.emplace_back(1);
      z3::expr e = z3::ite(op1 == op2, context_.bv_val(0, 32),
                                       context_.bv_val(1, 32));
      cache_expr(l, e);
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(0); // memcmp result is always 0 or 1
      continue;
    } else if (info->op == __dfsan::fsize) {
      // file size
      z3::symbol symbol = context_.str_symbol("fsize");
      z3::sort sort = context_.bv_sort(info->size);
      z3::expr base = context_.constant(symbol, sort);
      tsize_cache_.emplace_back(1);
      has_fsize = true; // XXX: set a flag
      // don't cache because of deps
      if (info->op1.i) {
        // minus the offset stored in op1
        z3::expr offset = context_.bv_val((uint64_t)info->op1.i, info->size);
        cache_expr(l, base - offset);
      } else {
        cache_expr(l, base);
      }
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(0); // FIXME: map to input size
      continue;
    } else if (info->op == __dfsan::fatoi) {
      // string to integer conversion
      assert(info->l1 == 0 && info->l2 >= CONST_OFFSET);
      dfsan_label_info *src = get_label_info(info->l2);
      assert(src->op == __dfsan::Load);
      uint32_t offset = get_label_info(src->l1)->op1.i; // legacy: offset in op1
      uint32_t input = get_label_info(src->l1)->op2.i;
      int base = info->op1.i;
      uint64_t orig_len = info->op2.i;
      // FIXME: dependencies?
      tsize_cache_.emplace_back(1);
      // XXX: hacky, avoid string theory
      snprintf(name, sizeof(name), atoi_name_format, input, offset, base, orig_len);
      z3::symbol symbol = context_.str_symbol(name);
      z3::sort sort = context_.bv_sort(info->size);
      cache_expr(l, context_.constant(symbol, sort));
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(0); // FIXME: map to atoi result?
      continue;
    } else if (info->op == __dfsan::fstrlen) {
      // Symbolic string length
      // - l1 = 0 (following fsize/fatoi pattern)
      // - l2 = content label (for input dependencies)
      // - op1 = null_from_input flag (1 if null terminator is from input, 0 if programmatic)
      // - op2 = actual length

      // Extract offset and input_id from content label (l2)
      uint32_t offset = 0;
      uint32_t input_id = 0;
      uint32_t null_from_input = info->op1.i;

      if (info->l2 >= CONST_OFFSET) {
        // Walk the content label to find base input offset
        dfsan_label_info *str_info = get_label_info(info->l2);

        // Handle Concat chain (common for multi-byte strings)
        while (str_info->op == __dfsan::Concat && str_info->l1 >= CONST_OFFSET) {
          str_info = get_label_info(str_info->l1);
        }

        // Base input labels have op=0, offset in op1
        // (created by dfsan_create_label, not dfsan_union)
        if (str_info->op == 0) {
          // Direct input byte - offset stored in op1
          offset = str_info->op1.i;
          input_id = 0; // default input
        } else if (str_info->op == __dfsan::Load) {
          // Load from memory - get offset from pointer label
          dfsan_label_info *ptr_info = get_label_info(str_info->l1);
          offset = ptr_info->op1.i;
          input_id = ptr_info->op2.i;
        }
      }

      tsize_cache_.emplace_back(1);
      // Create symbolic variable: strlen-input-offset-origlen-null_from_input
      snprintf(name, sizeof(name), strlen_name_format, input_id, offset,
               info->op2.i, null_from_input);
      z3::symbol symbol = context_.str_symbol(name);
      z3::sort sort = context_.bv_sort(info->size);
      cache_expr(l, context_.constant(symbol, sort));
      TRACK_LABEL_BV_ONLY();
      RECORD_VALUE(info->op2.i); // actual length for value cache
      continue;
    } else if (info->op == __dfsan::flength) {
      // length(str_var) -> Int sort
      // l1 = content label, l2 = 0, op2 = concrete length
      z3::expr str_var = build_string_from_label(info->l1, input_deps);
      z3::expr len_expr(context_, Z3_mk_seq_length(context_, str_var));
      tsize_cache_.emplace_back(1);
      cache_expr(l, len_expr);  // Int sort
      TRACK_LABEL_SEQ_ONLY();
      RECORD_VALUE(info->op2.i);
      continue;
    } else if (info->op == __dfsan::fstrchr) {
      // strchr/memchr: find character in string
      // l1 = source pointer label (content bytes, fsubstr, or previous strchr for chaining)
      // l2 = c_label (target character - may be symbolic!)
      // op1 = haystack pointer (for concrete content retrieval)
      // op2 = char value
      // size = haystack length if haystack concrete, else 0

      // Build source string from l1 (content label)
      z3::expr haystack_str = context_.string_val("");
      z3::expr start_offset = context_.int_val(0);

      dfsan_label haystack_label = info->l1;
      dfsan_label concrete_label = l;  // Track which label sent the concrete content
      if (haystack_label >= CONST_OFFSET) {
        // Symbolic haystack
        dfsan_label_info *src_info = get_label_info(haystack_label);

        if (is_content_string_op(src_info->op)) {
          // l1 is a fsubstr/strcat - use the cached substr expression directly
          haystack_str = get_cached_expr(haystack_label, input_deps);
        } else if (is_indexof_op(src_info->op)) {
          if (src_info->op == __dfsan::fstr_off) {
            // Chained call via pointer arithmetic: strchr(t1 + N, c)
            // Use build_string_from_label which handles fstr_off specially
            // (creates insertion point if beyond end, or suffix if within bounds)
            haystack_label = src_info->l1;
            // start_offset stays 0 since we're searching from the start of the suffix/insertion point
          } else {
            // Chained call: search starts after previous match
            z3::expr prev_idx = get_cached_expr(info->l1, input_deps);
            start_offset = prev_idx + 1;
            // Walk back to find original haystack content
            haystack_label = info->l1;
            dfsan_label_info *chain_info = src_info;
            while (is_indexof_op(chain_info->op)) {
              concrete_label = haystack_label;  // Save before updating
              haystack_label = chain_info->l1;
              if (haystack_label < CONST_OFFSET) break;
              chain_info = get_label_info(haystack_label);
            }
          }
          // Build string from original haystack label
          if (haystack_label >= CONST_OFFSET) {
              haystack_str = build_string_from_label(haystack_label, input_deps);
          }
        } else {
          // Build string from byte content (Load, Concat, or single byte)
          haystack_str = build_string_from_label(haystack_label, input_deps);
        }
      }

      if (haystack_label < CONST_OFFSET) {
        // Concrete haystack - retrieve from memcmp_cache using concrete_label
        auto it = memcmp_cache_.find(concrete_label);
        if (it != memcmp_cache_.end()) {
          dfsan_label_info *concrete_info = get_label_info(concrete_label);
          std::string haystack(reinterpret_cast<char*>(it->second.get()), concrete_info->size);
          haystack_str = context_.string_val(haystack);
        } else {
          throw z3::exception("cannot find haystack content for strchr");
        }
      }

      // Get target character (concrete or symbolic)
      // Use z3::unit to create single-char string from integer code point
      z3::expr code(context_);
      if (info->l2 == 0) {
        // Concrete character
        uint8_t c = (uint8_t)info->op2.i;
        code = context_.int_val(c);
      } else {
        // Symbolic character - convert bitvector to int
        z3::expr c_expr = get_cached_expr(info->l2, input_deps);
        if (c_expr.get_sort().bv_size() != 8) {
          c_expr = c_expr.extract(7, 0);
        }
        code = z3::bv2int(c_expr, false);
      }
      // Use Z3_mk_string_from_code to convert int to single-char String
      z3::expr target_str(context_, Z3_mk_string_from_code(context_, code));

      z3::expr idx = z3::indexof(haystack_str, target_str, start_offset);

      tsize_cache_.emplace_back(1);
      cache_expr(l, idx);  // cache the index expression (Int sort)
      TRACK_LABEL_SEQ_ONLY();
      RECORD_VALUE(0);  // Placeholder - validation skipped for indexOf ops
      continue;
    } else if (info->op == __dfsan::fstrrchr) {
      // strrchr/memrchr: find LAST occurrence of character
      // l1 = source pointer label (content bytes or fsubstr)
      // l2 = c_label (target character - may be symbolic!)
      // op1 = haystack pointer (for concrete content retrieval)
      // op2 = char value
      // size = haystack length if haystack concrete, else 0

      // Build source string from l1 (content label or fsubstr)
      z3::expr haystack_str = context_.string_val("");
      if (info->l1 >= CONST_OFFSET) {
        // Symbolic haystack
        dfsan_label_info *src_info = get_label_info(info->l1);
        if (is_content_string_op(src_info->op)) {
          // l1 is a fsubstr/strcat - use the cached substr expression directly
          haystack_str = get_cached_expr(info->l1, input_deps);
        } else {
          haystack_str = build_string_from_label(info->l1, input_deps);
        }
      } else {
        // Concrete haystack - retrieve from memcmp_cache
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end()) {
          // Use info->size for haystack length (set in runtime)
          std::string haystack(reinterpret_cast<char*>(it->second.get()), info->size);
          haystack_str = context_.string_val(haystack);
        } else {
          throw z3::exception("cannot find haystack content for strrchr");
        }
      }

      // Get target character (concrete or symbolic)
      // Use z3::unit to create single-char string from integer code point
      z3::expr code(context_);
      if (info->l2 == 0) {
        // Concrete character
        uint8_t c = (uint8_t)info->op2.i;
        code = context_.int_val(c);
      } else {
        // Symbolic character - convert bitvector to int
        z3::expr c_expr = get_cached_expr(info->l2, input_deps);
        if (c_expr.get_sort().bv_size() != 8) {
          c_expr = c_expr.extract(7, 0);
        }
        code = z3::bv2int(c_expr, false);
      }
      // Use Z3_mk_string_from_code to convert int to single-char String
      z3::expr target_str(context_, Z3_mk_string_from_code(context_, code));

      // For reverse search, find the last occurrence
      z3::expr idx = z3::last_indexof(haystack_str, target_str);

      tsize_cache_.emplace_back(1);
      cache_expr(l, idx);
      TRACK_LABEL_SEQ_ONLY();
      RECORD_VALUE(0);  // Placeholder - validation skipped for indexOf ops
      continue;
    } else if (info->op == __dfsan::fstrstr) {
      // strstr: find substring
      // l1 = haystack content label (for chaining or byte content)
      // l2 = needle_label (may be symbolic!)
      // op1 = haystack pointer (for concrete content retrieval)
      // op2 = needle pointer (for concrete content retrieval)
      // size = haystack length if haystack concrete, else needle length if needle concrete, else 0

      // Build haystack string from l1
      z3::expr haystack_str = context_.string_val("");
      z3::expr start_offset = context_.int_val(0);

      dfsan_label haystack_label = info->l1;
      dfsan_label concrete_label = l;  // Track which label sent the concrete content
      if (haystack_label >= CONST_OFFSET) {
        // Symbolic haystack
        dfsan_label_info *src_info = get_label_info(haystack_label);

        if (is_content_string_op(src_info->op)) {
          // l1 is a fsubstr/strcat - use the cached substr expression directly
          haystack_str = get_cached_expr(haystack_label, input_deps);
        } else if (is_indexof_op(src_info->op)) {
          if (src_info->op == __dfsan::fstr_off) {
            // Chained call via pointer arithmetic
            haystack_label = src_info->l1;
          } else {
            // Chained call: search starts after previous match
            z3::expr prev_idx = get_cached_expr(info->l1, input_deps);
            start_offset = prev_idx + 1;
            // Walk back to find original haystack content
            haystack_label = info->l1;
            dfsan_label_info *chain_info = src_info;
            while (is_indexof_op(chain_info->op)) {
              concrete_label = haystack_label;  // Save before updating
              haystack_label = chain_info->l1;
              if (haystack_label < CONST_OFFSET) break;
              chain_info = get_label_info(haystack_label);
            }
          }
          // Build string from original haystack label
          if (haystack_label >= CONST_OFFSET) {
            haystack_str = build_string_from_label(haystack_label, input_deps);
          }
        } else {
          // Build string from byte content
          haystack_str = build_string_from_label(haystack_label, input_deps);
        }
      }

      if (haystack_label < CONST_OFFSET) {
        // Concrete haystack - retrieve from memcmp_cache using concrete_label
        auto it = memcmp_cache_.find(concrete_label);
        if (it != memcmp_cache_.end()) {
          dfsan_label_info *concrete_info = get_label_info(concrete_label);
          std::string haystack(reinterpret_cast<char*>(it->second.get()), concrete_info->size);
          haystack_str = context_.string_val(haystack);
        } else {
          throw z3::exception("cannot find haystack content for strstr");
        }
      }

      // Get needle (concrete or symbolic)
      z3::expr needle_str(context_);
      if (info->l2 == 0) {
        // Concrete needle - get from cache
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end()) {
          // Build string from cached bytes using info->size for length
          std::string needle(reinterpret_cast<char*>(it->second.get()), info->size);
          needle_str = context_.string_val(needle);
        } else {
          throw z3::exception("cannot find concrete needle content");
        }
      } else {
        // Symbolic needle - build string from l2 (Load of tainted buffer)
        needle_str = build_string_from_label(info->l2, input_deps);
      }

      z3::expr idx = z3::indexof(haystack_str, needle_str, start_offset);

      tsize_cache_.emplace_back(1);
      cache_expr(l, idx);
      TRACK_LABEL_SEQ_ONLY();
      RECORD_VALUE(0);  // Placeholder - validation skipped for indexOf ops
      continue;
    } else if (info->op == __dfsan::fstrpbrk) {
      // strpbrk: find first character from accept set
      // l1 = source content label
      // l2 = accept_label (may be symbolic)
      // op1 = haystack pointer (for concrete content retrieval)
      // op2 = accept pointer (for concrete content retrieval)
      // size = haystack length if haystack concrete, else accept length if accept concrete, else 0

      // Build source string from l1
      z3::expr haystack_str = context_.string_val("");
      z3::expr start_offset = context_.int_val(0);

      dfsan_label haystack_label = info->l1;
      dfsan_label concrete_label = l;  // Track which label sent the concrete content
      if (haystack_label >= CONST_OFFSET) {
        // Symbolic haystack
        dfsan_label_info *src_info = get_label_info(haystack_label);

        if (is_content_string_op(src_info->op)) {
          haystack_str = get_cached_expr(haystack_label, input_deps);
        } else if (is_indexof_op(src_info->op)) {
          if (src_info->op == __dfsan::fstr_off) {
            // Chained call via pointer arithmetic
            haystack_label = src_info->l1;
          } else {
            // Chained call
            z3::expr prev_idx = get_cached_expr(info->l1, input_deps);
            start_offset = prev_idx + 1;
            haystack_label = info->l1;
            dfsan_label_info *chain_info = src_info;
            while (is_indexof_op(chain_info->op)) {
              concrete_label = haystack_label;  // Save before updating
              haystack_label = chain_info->l1;
              if (haystack_label < CONST_OFFSET) break;
              chain_info = get_label_info(haystack_label);
            }
          }
          // Build string from original haystack label
          if (haystack_label >= CONST_OFFSET) {
            haystack_str = build_string_from_label(haystack_label, input_deps);
          }
        } else {
          haystack_str = build_string_from_label(haystack_label, input_deps);
        }
      }

      if (haystack_label < CONST_OFFSET) {
        // Concrete haystack - retrieve from memcmp_cache using concrete_label
        auto it = memcmp_cache_.find(concrete_label);
        if (it != memcmp_cache_.end()) {
          dfsan_label_info *concrete_info = get_label_info(concrete_label);
          std::string haystack(reinterpret_cast<char*>(it->second.get()), concrete_info->size);
          haystack_str = context_.string_val(haystack);
        } else {
          throw z3::exception("cannot find haystack content for strpbrk");
        }
      }

      // Get accept character set
      z3::expr idx(context_);
      if (info->l2 == 0) {
        // Concrete accept set - get from cache
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end() && info->size > 0) {
          // Simplified approach: use first character's index as representative
          // and add constraint that any character could be found
          // This works well for NULL checks (if (strpbrk(s, accept)))
          uint8_t first_c = it->second.get()[0];
          z3::expr code = context_.int_val(first_c);
          z3::expr char_str(context_, Z3_mk_string_from_code(context_, code));
          idx = z3::indexof(haystack_str, char_str, start_offset);
        } else {
          throw z3::exception("cannot find concrete accept content");
        }
      } else {
        // Symbolic accept set - build string from label
        z3::expr accept_str = build_string_from_label(info->l2, input_deps);
        // Get the length of accept string
        z3::expr accept_len(context_, Z3_mk_seq_length(context_, accept_str));
        // strpbrk returns NULL if accept is empty, so: if (len > 0) indexOf else -1
        z3::expr first_char_str(context_, Z3_mk_seq_extract(context_, accept_str, context_.int_val(0), context_.int_val(1)));
        z3::expr idx_if_nonempty = z3::indexof(haystack_str, first_char_str, start_offset);
        idx = z3::ite(accept_len > 0, idx_if_nonempty, context_.int_val(-1));
      }

      tsize_cache_.emplace_back(1);
      cache_expr(l, idx.simplify());
      TRACK_LABEL_SEQ_ONLY();
      RECORD_VALUE(0);  // Placeholder - validation skipped for indexOf ops
      continue;
    } else if (info->op == __dfsan::fsubstr) {
      // fsubstr: substring with symbolic position/length
      // l1 = original content label (full haystack from previous string op)
      // l2 = string op label (position or length depending on mode)
      // op1 = concrete length n
      // op2 = 0 for prefix mode (from 0 to l2), 1 for suffix mode (from l2 to end)

      // Build the full string from l1 (the original content)
      z3::expr full_str = context_.string_val("");
      if (info->l1 >= CONST_OFFSET) {
        full_str = build_string_from_label(info->l1, input_deps);
      }

      z3::expr substr_expr(context_);
      bool suffix_mode = (info->op2.i == 1);

      if (suffix_mode) {
        // Suffix mode: substr(str, start_pos, remaining_len)
        // l2 is fstr_off - need to extract the start position
        z3::expr start_pos = context_.int_val(0);
        if (info->l2 >= CONST_OFFSET) {
          dfsan_label_info *l2_info = get_label_info(info->l2);
          if (l2_info->op == __dfsan::fstr_off) {
            // fstr_off: l1 = indexOf op, op2 = byte offset
            // start_pos = indexOf_result + offset
            z3::expr base_idx = get_cached_expr(l2_info->l1, input_deps);
            start_pos = base_idx + context_.int_val((int64_t)l2_info->op2.i);
          } else {
            // Direct indexOf op
            start_pos = get_cached_expr(info->l2, input_deps);
          }
        }
        // Use large length to get "rest of string" - Z3 will clamp to actual length
        z3::expr full_len(context_, Z3_mk_seq_length(context_, full_str));
        z3::expr len_expr = full_len - start_pos;
        substr_expr = z3::expr(context_, Z3_mk_seq_extract(context_,
                                                           full_str,
                                                           start_pos,
                                                           len_expr));
      } else {
        // Prefix mode: substr(str, 0, len)
        z3::expr len_expr = context_.int_val((int64_t)info->op1.i);
        if (info->l2 >= CONST_OFFSET) {
          // l2 is the string op label - its cached value is the index/length
          len_expr = get_cached_expr(info->l2, input_deps);
        }
        substr_expr = z3::expr(context_, Z3_mk_seq_extract(context_,
                                                           full_str,
                                                           context_.int_val(0),
                                                           len_expr));
      }

      tsize_cache_.emplace_back(1);
      cache_expr(l, substr_expr);
      TRACK_LABEL_SEQ_ONLY();
      // The substr itself doesn't have a numeric value, but downstream ops will use it
      RECORD_VALUE(info->op1.i);
      continue;
    } else if (info->op == __dfsan::fstrcat) {
      // strcat: string concatenation
      // l1 = dest string label
      // l2 = src string label
      // op1 = dest pointer (for concrete content access)
      // op2 = src pointer (for concrete content access)
      // size = length of concrete operand (for memcmp_cache), 0 if both symbolic

      z3::expr dest_str = context_.string_val("");
      z3::expr src_str = context_.string_val("");

      // Build dest string from l1
      // Only fsubstr and fstrcat cache String expressions; other string ops cache Int (position)
      if (info->l1 >= CONST_OFFSET) {
        dfsan_label_info *l1_info = get_label_info(info->l1);
        if (is_content_string_op(l1_info->op)) {
          dest_str = get_cached_expr(info->l1, input_deps);
        } else {
          dest_str = build_string_from_label(info->l1, input_deps);
        }
      } else {
        // Concrete dest - get from memcmp_cache
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end()) {
          std::string s(reinterpret_cast<char*>(it->second.get()), info->size);
          dest_str = context_.string_val(s);
        } else {
          throw z3::exception("cannot find strcat content");
        }
      }

      // Build src string from l2
      if (info->l2 >= CONST_OFFSET) {
        dfsan_label_info *l2_info = get_label_info(info->l2);
        if (is_content_string_op(l2_info->op)) {
          src_str = get_cached_expr(info->l2, input_deps);
        } else {
          src_str = build_string_from_label(info->l2, input_deps);
        }
      } else {
        // Concrete src - get from memcmp_cache
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end()) {
          std::string s(reinterpret_cast<char*>(it->second.get()), info->size);
          src_str = context_.string_val(s);
        } else {
          throw z3::exception("cannot find strcat content");
        }
      }

      // Create Z3 string concatenation
      z3::expr concat_result = z3::concat(dest_str, src_str);

      tsize_cache_.emplace_back(1);
      cache_expr(l, concat_result);
      TRACK_LABEL_SEQ_ONLY();
      RECORD_VALUE(0);
      continue;
    } else if (info->op == __dfsan::fstrcmp) {
      // String comparison using Z3 string theory
      // l1 = first string label (may be fsubstr or content)
      // l2 = second string label (may be fsubstr or content)
      // size = comparison length (in bytes, for memcmp_cache lookup)
      // op1 = s1 pointer (for memcmp_cache lookup)
      // op2 = s2 pointer (for memcmp_cache lookup)

      z3::expr str1 = context_.string_val("");
      z3::expr str2 = context_.string_val("");

      // Build first string
      if (info->l1 >= CONST_OFFSET) {
        dfsan_label_info *l1_info = get_label_info(info->l1);
        if (is_content_string_op(l1_info->op)) {
          // fsubstr/fstrcat - get the cached String expression
          str1 = get_cached_expr(info->l1, input_deps);
        } else {
          // Regular content - build string from labels
          str1 = build_string_from_label(info->l1, input_deps);
        }
      } else {
        // Concrete - get from memcmp_cache
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end()) {
          std::string s(reinterpret_cast<char*>(it->second.get()), info->size);
          str1 = context_.string_val(s);
        } else {
          throw z3::exception("cannot find strcmp content");
        }
      }

      // Build second string
      if (info->l2 >= CONST_OFFSET) {
        dfsan_label_info *l2_info = get_label_info(info->l2);
        if (is_content_string_op(l2_info->op)) {
          // fsubstr/fstrcat - get the cached String expression
          str2 = get_cached_expr(info->l2, input_deps);
        } else {
          // Regular content - build string from labels
          str2 = build_string_from_label(info->l2, input_deps);
        }
      } else {
        // Concrete - get from memcmp_cache
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end()) {
          std::string s(reinterpret_cast<char*>(it->second.get()), info->size);
          str2 = context_.string_val(s);
        } else {
          throw z3::exception("cannot find strcmp content");
        }
      }

      // Create equality: strcmp returns 0 when equal, non-zero otherwise
      z3::expr eq = z3::ite(str1 == str2,
                             context_.bv_val(0, 32),
                             context_.bv_val(1, 32));
      tsize_cache_.emplace_back(1);
      cache_expr(l, eq);
      TRACK_LABEL_SEQ_ONLY();
      RECORD_VALUE(0);
      continue;
    } else if (info->op == __dfsan::fprefixof) {
      // prefixof: check if str starts with prefix
      // l1 = string label, l2 = prefix label
      // size = comparison length, op1 = str ptr, op2 = prefix ptr

      z3::expr str = context_.string_val("");
      z3::expr prefix = context_.string_val("");

      // Build first string (str)
      if (info->l1 >= CONST_OFFSET) {
        dfsan_label_info *l1_info = get_label_info(info->l1);
        if (is_content_string_op(l1_info->op)) {
          str = get_cached_expr(info->l1, input_deps);
        } else {
          str = build_string_from_label(info->l1, input_deps);
        }
      } else {
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end()) {
          std::string s(reinterpret_cast<char*>(it->second.get()), info->size);
          str = context_.string_val(s);
        } else {
          throw z3::exception("cannot find prefixof str content");
        }
      }

      // Build second string (prefix)
      if (info->l2 >= CONST_OFFSET) {
        dfsan_label_info *l2_info = get_label_info(info->l2);
        if (is_content_string_op(l2_info->op)) {
          prefix = get_cached_expr(info->l2, input_deps);
        } else {
          prefix = build_string_from_label(info->l2, input_deps);
        }
      } else {
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end()) {
          std::string s(reinterpret_cast<char*>(it->second.get()), info->size);
          prefix = context_.string_val(s);
        } else {
          throw z3::exception("cannot find prefixof prefix content");
        }
      }

      // Use Z3's prefixof: returns 1 if str starts with prefix, else 0
      z3::expr result = z3::ite(z3::prefixof(prefix, str),
                                 context_.bv_val(1, 32),
                                 context_.bv_val(0, 32));
      tsize_cache_.emplace_back(1);
      cache_expr(l, result);
      TRACK_LABEL_SEQ_ONLY();
      RECORD_VALUE(0);
      continue;
    } else if (info->op == __dfsan::fsuffixof) {
      // suffixof: check if str ends with suffix
      // l1 = string label, l2 = suffix label
      // size = comparison length, op1 = str ptr, op2 = suffix ptr

      z3::expr str = context_.string_val("");
      z3::expr suffix = context_.string_val("");

      // Build first string (str) - same pattern as fprefixof
      if (info->l1 >= CONST_OFFSET) {
        dfsan_label_info *l1_info = get_label_info(info->l1);
        if (is_content_string_op(l1_info->op)) {
          str = get_cached_expr(info->l1, input_deps);
        } else {
          str = build_string_from_label(info->l1, input_deps);
        }
      } else {
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end()) {
          std::string s(reinterpret_cast<char*>(it->second.get()), info->size);
          str = context_.string_val(s);
        } else {
          throw z3::exception("cannot find suffixof str content");
        }
      }

      // Build second string (suffix)
      if (info->l2 >= CONST_OFFSET) {
        dfsan_label_info *l2_info = get_label_info(info->l2);
        if (is_content_string_op(l2_info->op)) {
          suffix = get_cached_expr(info->l2, input_deps);
        } else {
          suffix = build_string_from_label(info->l2, input_deps);
        }
      } else {
        auto it = memcmp_cache_.find(l);
        if (it != memcmp_cache_.end()) {
          std::string s(reinterpret_cast<char*>(it->second.get()), info->size);
          suffix = context_.string_val(s);
        } else {
          throw z3::exception("cannot find suffixof suffix content");
        }
      }

      // Use Z3's suffixof: returns 1 if str ends with suffix, else 0
      z3::expr result = z3::ite(z3::suffixof(suffix, str),
                                 context_.bv_val(1, 32),
                                 context_.bv_val(0, 32));
      tsize_cache_.emplace_back(1);
      cache_expr(l, result);
      TRACK_LABEL_SEQ_ONLY();
      RECORD_VALUE(0);
      continue;
    } else if (info->op == __dfsan::fstr_off) {
      // fstr_off: string op pointer + constant offset (from GEP)
      // l1 = string op label (fstrchr result)
      // op2 = byte offset (e.g., 1 for sep + 1)
      // The result is a pointer with the offset recorded for later substr calculation

      if (info->l1 >= CONST_OFFSET) {
        // Get the index expression for the base string op
        z3::expr idx_expr = get_cached_expr(info->l1, input_deps);
        int64_t gep_offset = (int64_t)info->op2.i;

        // The fstr_off result is idx + offset (still an Int for string indexing)
        z3::expr offset_idx = idx_expr + (int)gep_offset;

        tsize_cache_.emplace_back(tsize_cache_[info->l1]);
        cache_expr(l, offset_idx);
        TRACK_LABEL_SEQ_ONLY();
        // Record the concrete position + offset
        RECORD_VALUE(value_cache_[info->l1] + gep_offset);
      } else {
        // No base label, just return zero
        tsize_cache_.emplace_back(0);
        cache_expr(l, context_.int_val(0));
        TRACK_LABEL_SEQ_ONLY();
        RECORD_VALUE(0);
      }
      continue;
    } else if (info->op == __dfsan::Alloca || info->op == __dfsan::Free) {
      // not expression, do nothing
      tsize_cache_.emplace_back(0);
      expr_cache_.emplace_back(nullptr);
      TRACK_LABEL_BV_ONLY();  // placeholder, doesn't matter
      RECORD_VALUE(0);
      continue;
    }

    // common ops
    uint16_t size = info->size;  // Must be uint16_t to handle sizes > 255 bits

    // Early check for ICmp with string functions - handle before creating BVs
    // because string functions use 'size' field for other purposes (e.g., needle length)
    if ((info->op & 0xff) == __dfsan::ICmp) {
      uint16_t l1_op = info->l1 >= CONST_OFFSET ? get_label_info(info->l1)->op : 0;
      uint16_t l2_op = info->l2 >= CONST_OFFSET ? get_label_info(info->l2)->op : 0;
      bool l1_is_strfunc = (l1_op >= __dfsan::fstr_op_start && l1_op < __dfsan::fstr_op_end);
      bool l2_is_strfunc = (l2_op >= __dfsan::fstr_op_start && l2_op < __dfsan::fstr_op_end);
      bool l1_is_flength = (l1_op == __dfsan::flength);
      bool l2_is_flength = (l2_op == __dfsan::flength);

      if (l1_is_flength || l2_is_flength) {
        // Length comparison - produce Int sort comparison
        uint16_t predicate = info->op >> 8;
        z3::expr len_expr = l1_is_flength
            ? get_cached_expr(info->l1, input_deps)
            : get_cached_expr(info->l2, input_deps);
        // Get the other operand as Int
        z3::expr other(context_);
        if (l1_is_flength && info->l2 == 0) {
          other = context_.int_val((uint64_t)info->op2.i);
        } else if (l2_is_flength && info->l1 == 0) {
          other = context_.int_val((uint64_t)info->op1.i);
        } else {
          // Both symbolic - get other operand as Int
          dfsan_label other_l = l1_is_flength ? info->l2 : info->l1;
          other = get_cached_expr(other_l, input_deps);
          if (other.is_bv()) {
            other = z3::expr(context_, Z3_mk_bv2int(context_, other, false));
          }
          // else already Int (from sort coercion), use as-is
        }
        // If flength is on the right side, swap the comparison direction
        if (l2_is_flength && !l1_is_flength) {
          std::swap(len_expr, other);
        }
        z3::expr cmp_expr(context_);
        switch (predicate) {
          case __dfsan::bvuge: cmp_expr = len_expr >= other; break;
          case __dfsan::bvugt: cmp_expr = len_expr > other; break;
          case __dfsan::bvule: cmp_expr = len_expr <= other; break;
          case __dfsan::bvult: cmp_expr = len_expr < other; break;
          case __dfsan::bveq:  cmp_expr = len_expr == other; break;
          case __dfsan::bvneq: cmp_expr = len_expr != other; break;
          case __dfsan::bvsge: cmp_expr = len_expr >= other; break;
          case __dfsan::bvsgt: cmp_expr = len_expr > other; break;
          case __dfsan::bvsle: cmp_expr = len_expr <= other; break;
          case __dfsan::bvslt: cmp_expr = len_expr < other; break;
          default: throw z3::exception("unsupported predicate for flength comparison");
        }
        tsize_cache_.emplace_back(tsize_cache_[info->l1] + tsize_cache_[info->l2]);
        cache_expr(l, cmp_expr);
        TRACK_LABEL_SEQ_ONLY();
        RECORD_VALUE(info->op2.i);
        continue;
      }

      if (l1_is_strfunc || l2_is_strfunc) {
        // String function comparison - convert index to found/not-found
        // strchr returns -1 for not found, >= 0 for found
        z3::expr cmp_expr(context_);
        z3::expr zero = context_.int_val(0);
        int64_t found_pos;
        bool found;
        uint16_t predicate = info->op >> 8;

        if (l1_is_strfunc && info->l2 == 0 && info->op2.i == 0) {
          // Comparing string result with NULL (0)
          z3::expr idx = get_cached_expr(info->l1, input_deps);
          found_pos = (int64_t)value_cache_[info->l1];
          found = found_pos >= 0;
          z3::expr found_expr = idx >= zero;
          if (predicate == __dfsan::bvneq) {
            cmp_expr = found_expr;  // != NULL means found
          } else if (predicate == __dfsan::bveq) {
            cmp_expr = !found_expr; // == NULL means not found
          } else {
            throw z3::exception("unsupported predicate for string search result");
          }
        } else if (l2_is_strfunc && info->l1 == 0 && info->op1.i == 0) {
          // NULL compared with string result
          z3::expr idx = get_cached_expr(info->l2, input_deps);
          found_pos = (int64_t)value_cache_[info->l2];
          found = found_pos >= 0;
          z3::expr found_expr = idx >= zero;
          if (predicate == __dfsan::bvneq) {
            cmp_expr = found_expr;  // != NULL means found
          } else if (predicate == __dfsan::bveq) {
            cmp_expr = !found_expr; // == NULL means not found
          } else {
            throw z3::exception("unsupported predicate for string search result");
          }
        } else {
          throw z3::exception("unsupported string comparison");
        }

        tsize_cache_.emplace_back(tsize_cache_[info->l1] + tsize_cache_[info->l2]);
        cache_expr(l, cmp_expr);
        TRACK_LABEL_SEQ_ONLY();  // string function comparison is purely seq
#if FILTER_WRONG_AST
        // For string ops, calculate value based on found/not-found semantics
        bool cmp_result = (predicate == __dfsan::bvneq) ? found : !found;
        value_cache_.emplace_back(cmp_result ? 1 : 0);
#endif
        continue;
      }
    }

    uint64_t valmask = size < 64 ? (1UL << size) - 1 : ~0UL;
    // size for concat is a bit complicated ...
    if (info->op == __dfsan::Concat && info->l1 == 0) {
      assert(info->l2 >= CONST_OFFSET);
      size = info->size - get_label_info(info->l2)->size;
      valmask = (1UL << size) - 1;
    }
    z3::expr op1 = context_.bv_val((uint64_t)info->op1.i, size);
    uint64_t val1 = info->op1.i & valmask;
    if (info->l1 >= CONST_OFFSET) {
      op1 = get_cached_expr(info->l1, input_deps).simplify();
      if (op1.is_bv() && info->op != __dfsan::Concat) {
        // XXX: fix size mismatch, only for bv and not concat
        uint8_t op_size = op1.get_sort().bv_size();
        if (op_size > size) {
          op1 = op1.extract(size - 1, 0);
        } else if (op_size < size) {
          op1 = z3::zext(op1, size - op_size);
        }
      }
#if FILTER_WRONG_AST
      val1 = value_cache_[info->l1] & valmask;
#endif
    } else if (info->size == 1) {
      op1 = context_.bool_val(info->op1.i == 1);
    }
    // handle op2
    if (info->op == __dfsan::Concat && info->l2 == 0) {
      assert(info->l1 >= CONST_OFFSET);
      size = info->size - get_label_info(info->l1)->size;
      valmask = (1UL << size) - 1;
    }
    z3::expr op2 = context_.bv_val((uint64_t)info->op2.i, size);
    uint64_t val2 = info->op2.i & valmask;
    if (info->l2 >= CONST_OFFSET) {
      op2 = get_cached_expr(info->l2, input_deps).simplify();
      if (op2.is_bv() && info->op != __dfsan::Concat) {
        // XXX: fix size mismatch, only for bv and not concat
        uint8_t op_size = op2.get_sort().bv_size();
        if (op_size > size) {
          op2 = op2.extract(size - 1, 0);
        } else if (op_size < size) {
          op2 = z3::zext(op2, size - op_size);
        }
      }
#if FILTER_WRONG_AST
      val2 = value_cache_[info->l2] & valmask;
#endif
    } else if (info->size == 1) {
      op2 = context_.bool_val(info->op2.i == 1);
    }

    // Sort coercion: when one operand is Int (from string ops via PtrToInt)
    // and the other is BV, convert the BV side to Int to avoid expensive int2bv.
    // Tier 1: direct input bytes get a fresh named Int variable (int-id-offset-bits)
    // Tier 2: complex BV expressions use bv2int (still cheaper than int2bv of indexof)
    bool op1_is_int = op1.get_sort().is_int();
    bool op2_is_int = op2.get_sort().is_int();
    if (op1_is_int != op2_is_int) {
      auto convert_bv_to_int = [&](z3::expr &bv_op, dfsan_label lbl, uint64_t concrete_val) {
        if (lbl < CONST_OFFSET) {
          // Constant — just use int_val
          bv_op = context_.int_val(concrete_val);
        } else {
          dfsan_label_info *lbl_info = get_label_info(lbl);
          if (lbl_info->op == 0) {
            // Direct input byte — create named Int variable with bounds
            char intname[256];
            snprintf(intname, sizeof(intname), int_name_format,
                     lbl_info->op2.i, lbl_info->op1.i, lbl_info->size);
            z3::symbol sym = context_.str_symbol(intname);
            bv_op = context_.constant(sym, context_.int_sort());
            aux_constraints_.push_back(bv_op >= 0);
            if (lbl_info->size < 64) {
              aux_constraints_.push_back(bv_op < context_.int_val((uint64_t)(1ULL << lbl_info->size)));
            }
          } else {
            // Complex BV expression — use bv2int (unsigned)
            bv_op = z3::expr(context_, Z3_mk_bv2int(context_, bv_op, false));
          }
        }
      };
      if (!op1_is_int && op2_is_int) {
        convert_bv_to_int(op1, info->l1, info->op1.i);
      } else {
        convert_bv_to_int(op2, info->l2, info->op2.i);
      }
    }

    // update tree_size
    tsize_cache_.emplace_back(tsize_cache_[info->l1] + tsize_cache_[info->l2]);

    switch((info->op & 0xff)) {
      // llvm doesn't distinguish between logical and bitwise and/or/xor
      case __dfsan::And: {
        cache_expr(l, info->size != 1 ? (op1 & op2) : (op1 && op2));
        TRACK_LABEL_PROPAGATE_BOTH();
        RECORD_VALUE((info->size != 1) ? (val1 & val2) : (val1 && val2));
        break;
      }
      case __dfsan::Or: {
        cache_expr(l, info->size != 1 ? (op1 | op2) : (op1 || op2));
        TRACK_LABEL_PROPAGATE_BOTH();
        RECORD_VALUE((info->size != 1) ? (val1 | val2) : (val1 || val2));
        break;
      }
      case __dfsan::Xor: {
        cache_expr(l, op1 ^ op2);
        TRACK_LABEL_BV_ONLY();
        RECORD_VALUE(val1 ^ val2);
        break;
      }
      case __dfsan::Shl: {
        cache_expr(l, z3::shl(op1, op2));
        TRACK_LABEL_BV_ONLY();
        RECORD_VALUE(val1 << (val2 % size));
        break;
      }
      case __dfsan::LShr: {
        cache_expr(l, z3::lshr(op1, op2));
        TRACK_LABEL_BV_ONLY();
        RECORD_VALUE(val1 >> (val2 % size));
        break;
      }
      case __dfsan::AShr: {
        cache_expr(l, z3::ashr(op1, op2));
        TRACK_LABEL_BV_ONLY();
        RECORD_VALUE((int64_t)val1 >> (val2 % size));
        break;
      }
      case __dfsan::Add: {
        cache_expr(l, op1 + op2);
        if (op1_is_int || op2_is_int) {
          // After sort coercion, result is pure Int - no BV variables remain.
          // SEQ_ONLY prevents spurious linking of string bytes as used_in_bv.
          TRACK_LABEL_SEQ_ONLY();
        } else {
          TRACK_LABEL_BV_ONLY();
        }
        RECORD_VALUE(val1 + val2);
        break;
      }
      case __dfsan::Sub: {
        // Check for pointer arithmetic pattern: (ptr_with_string_op) - base_addr
        // When l1 is PtrToInt of a string op and l2 is constant (untainted base),
        // the result is just the index (since ptr = base + index, so ptr - base = index)
        if (info->l1 >= CONST_OFFSET && info->l2 == 0) {
          dfsan_label_info *l1_info = get_label_info(info->l1);
          if (l1_info->op == __dfsan::PtrToInt && l1_info->l1 >= CONST_OFFSET) {
            dfsan_label_info *src_info = get_label_info(l1_info->l1);
            if (src_info->op >= __dfsan::fstr_op_start &&
                src_info->op < __dfsan::fstr_op_end) {
              // This is (PtrToInt(string_op)) - base_addr = index
              // The expression is just the index (op1 already contains the idx)
              cache_expr(l, op1);
              TRACK_LABEL_SEQ_ONLY();
              // The value is just the index, not idx - base_addr
              RECORD_VALUE(val1);
              break;
            }
          }
        }
        cache_expr(l, op1 - op2);
        if (op1_is_int || op2_is_int) {
          TRACK_LABEL_SEQ_ONLY();
        } else {
          TRACK_LABEL_BV_ONLY();
        }
        RECORD_VALUE(val1 - val2);
        break;
      }
      case __dfsan::Mul: {
        cache_expr(l, op1 * op2);
        TRACK_LABEL_BV_ONLY();
        RECORD_VALUE(val1 * val2);
        break;
      }
      case __dfsan::UDiv: {
        cache_expr(l, z3::udiv(op1, op2));
        TRACK_LABEL_BV_ONLY();
        if (val2 == 0) {
          fprintf(stderr, "WARNING: division by zero for label %u\n", l);
          RECORD_VALUE(0);
        } else
          RECORD_VALUE(val1 / val2);
        break;
      }
      case __dfsan::SDiv: {
        cache_expr(l, op1 / op2);
        TRACK_LABEL_BV_ONLY();
        if (val2 == 0) {
          fprintf(stderr, "WARNING: division by zero for label %u\n", l);
          RECORD_VALUE(0);
        } else
          RECORD_VALUE((int64_t)val1 / (int64_t)val2);
        break;
      }
      case __dfsan::URem: {
        cache_expr(l, z3::urem(op1, op2));
        TRACK_LABEL_BV_ONLY();
        if (val2 == 0) {
          fprintf(stderr, "WARNING: division by zero for label %u\n", l);
          RECORD_VALUE(0);
        } else
          RECORD_VALUE(val1 % val2);
        break;
      }
      case __dfsan::SRem: {
        cache_expr(l, z3::srem(op1, op2));
        TRACK_LABEL_BV_ONLY();
        if (val2 == 0) {
          fprintf(stderr, "WARNING: division by zero for label %u\n", l);
          RECORD_VALUE(0);
        } else
          RECORD_VALUE((int64_t)val1 % (int64_t)val2);
        break;
      }
      // relational
      case __dfsan::ICmp: {
        // Note: string function ICmps are handled early before BV creation
        uint16_t l1_op = info->l1 >= CONST_OFFSET ? get_label_info(info->l1)->op : 0;
        uint16_t l2_op = info->l2 >= CONST_OFFSET ? get_label_info(info->l2)->op : 0;

        // fprintf(stderr, "DEBUG serialize ICmp label %u: l1=%u (op=%u), l2=%u (op=%u), predicate=%u\n",
        //         l, info->l1, l1_op, info->l2, l2_op, info->op >> 8);
        // fprintf(stderr, "DEBUG serialize ICmp: val1=%lu (cached), val2=%lu (cached), op1.i=%lu (runtime), op2.i=%lu (runtime)\n",
        //         val1, val2, (uint64_t)info->op1.i, (uint64_t)info->op2.i);

#if FILTER_WRONG_AST
        // we have both operands recorded for ICmp
        if ((info->op1.i & valmask) != val1 ||
            (info->op2.i & valmask) != val2) {
          fprintf(stderr, "DEBUG serialize ICmp: VALUE MISMATCH detected\n");
          // fprintf(stderr, "WARNING: value mismatch for label %u: "
          //         "expected op1 %lu, got %lu, expected op2 %lu, got %lu\n",
          //         l, info->op1.i, val1, info->op2.i, val2);
          // fprintf(stderr, "cond: %s\n", get_cmd(op1, op2, info->op >> 8).to_string().c_str());
          // dump_value_cache(info->l1);
          // dump_value_cache(info->l2);

          // Special cases where we don't have the actual value cached:
          // - memcmp/atoi/strcmp: fix using runtime value from ICmp
          // - indexOf operations: op1 repurposed for haystack pointer, skip validation
          bool is_special = false;
          if (l1_op == __dfsan::fmemcmp || l1_op == __dfsan::fatoi || l1_op == __dfsan::fstrcmp) {
            fprintf(stderr, "DEBUG serialize ICmp: fixing up value_cache_[%u] from %lu to %lu (op=%u)\n",
                    info->l1, value_cache_[info->l1], (uint64_t)info->op1.i, l1_op);
            value_cache_[info->l1] = val1 = info->op1.i;
            is_special = true;
          }
          if (l2_op == __dfsan::fmemcmp || l2_op == __dfsan::fatoi || l2_op == __dfsan::fstrcmp) {
            fprintf(stderr, "DEBUG serialize ICmp: fixing up value_cache_[%u] from %lu to %lu (op=%u)\n",
                    info->l2, value_cache_[info->l2], (uint64_t)info->op2.i, l2_op);
            value_cache_[info->l2] = val2 = info->op2.i;
            is_special = true;
          }
          // Check if either operand contains indexOf operations
          if ((info->l1 >= CONST_OFFSET && label_contains_indexof(info->l1)) ||
              (info->l2 >= CONST_OFFSET && label_contains_indexof(info->l2))) {
            is_special = true;
          }
          if (!is_special) {
            throw z3::exception("value mismatch for ICmp");
          }
        }
        uint64_t icmp_result = eval_icmp(info->op >> 8, val1, val2, size) ? 1 : 0;
        // fprintf(stderr, "DEBUG serialize ICmp: recording value_cache_[%u] = %lu\n", l, icmp_result);
        value_cache_.emplace_back(icmp_result);
#endif
        // Cache the expression AFTER updating value_cache to maintain consistency
        // if an exception is thrown above
        cache_expr(l, get_cmd(op1, op2, info->op >> 8));
        if (op1_is_int || op2_is_int) {
          // After sort coercion, comparison is pure Int - no BV variables.
          // SEQ_ONLY prevents spurious linking of string bytes.
          TRACK_LABEL_SEQ_ONLY();
        } else {
          TRACK_LABEL_PROPAGATE_BOTH();
        }
        break;
      }
      // concat
      case __dfsan::Concat: {
        // Check if either operand is a String (from fsubstr or string ops)
        // We can't concat String with bitvector
        if (!op1.is_bv() || !op2.is_bv()) {
          // If one operand is String and the other is constant 0 (label 0),
          // just use the String. The constant bytes don't contribute to constraints.
          if (!op1.is_bv() && info->l2 == 0) {
            cache_expr(l, op1);
            TRACK_LABEL_BV_ONLY();
            RECORD_VALUE(val1);
            break;
          }
          if (!op2.is_bv() && info->l1 == 0) {
            cache_expr(l, op2);
            TRACK_LABEL_BV_ONLY();
            RECORD_VALUE(val2);
            break;
          }
          // fprintf(stderr, "DEBUG Concat %u: l1=%u (sort=%s, is_bv=%d), l2=%u (sort=%s, is_bv=%d)\n",
          //         l, info->l1, op1.get_sort().to_string().c_str(), op1.is_bv(),
          //         info->l2, op2.get_sort().to_string().c_str(), op2.is_bv());
          throw z3::exception("concat with non-bitvector operand (string op involved)");
        }
        cache_expr(l, z3::concat(op2, op1)); // little endian
        TRACK_LABEL_BV_ONLY();
        RECORD_VALUE((val2 << op1.get_sort().bv_size()) | (val1));
        break;
      }
      default:
        fprintf(stderr, "WARNING: unsupported operator %u for label %u\n",
                info->op & 0xff, l);
        throw z3::exception("unsupported operator");
        break;
    }
  }

  return get_cached_expr(label, deps);
}

int Z3AstParser::parse_cond(dfsan_label label, bool result, bool add_nested, std::vector<uint64_t> &tasks) {

  if (label < CONST_OFFSET || label == __dfsan::kInitializingLabel || label >= size_) {
    // invalid label
    return -1;
  }

  // allocate a new task
  auto task = std::make_shared<z3_task_t>();
  try {
    // reset has_fsize flag
    has_fsize = false;

    // parse last branch cond
    input_dep_set_t inputs;
    z3::expr cond = serialize(label, inputs);

    // fix cond if it's bv1
    if (cond.is_bv() && cond.get_sort().bv_size() == 1) {
      cond = (cond != context_.bv_val(0, 1));
    }

    // add negated last branch condition
    z3::expr r = context_.bool_val(result);

#if FILTER_WRONG_AST
    // Skip validation for indexOf operations (op1 repurposed for haystack pointer)
    bool contains_indexof = label_contains_indexof(label);

    if (!contains_indexof && value_cache_[label] != result) {
      // recalcuated value must match the recorded value
      fprintf(stderr, "WARNING: value mismatch for label %u: expected %lu, got %d\n",
              label, value_cache_[label], result);
      fprintf(stderr, "cond: %s\n", cond.to_string().c_str());
      dump_value_cache(label);
      return -1;
    }
#endif

    task->push_back((cond != r));

    // mark expression type for linking detection
    mark_expr_type(label, inputs);

    // collect additional input deps
    collect_more_deps(inputs);

    // add nested constraints
    add_nested_constraints(inputs, task.get());

    // save the task
    tasks.push_back(save_task(task));

    // save nested unless it's a fsize constraints
    if (add_nested && !has_fsize) {
      save_constraint(cond == r, inputs);
    }

    return 0; // success
  } catch (z3::exception e) {
    fprintf(stderr, "WARNING: parsing error: %s\n", e.msg());
  } catch (std::exception& e) {
    fprintf(stderr, "WARNING: std::exception in parse_cond: %s\n", e.what());
  } catch (...) {
    fprintf(stderr, "WARNING: unknown exception in parse_cond\n");
  }

  // exception happened, nothing added
  return -1;
}

void Z3AstParser::construct_index_tasks(z3::expr &index, uint64_t curr,
                                        uint64_t lb, uint64_t ub, uint64_t step,
                                        z3_task_t &nested,
                                        std::vector<uint64_t> &tasks) {

  std::shared_ptr<z3_task_t> task = nullptr;

  // enumerate indices
  for (uint64_t i = lb; i < ub; i += step) {
    if (i == curr) continue;
    z3::expr idx = context_.bv_val(i, 64);
    z3::expr e = (index == idx);
    // allocate a new task
    task = std::make_shared<z3_task_t>();
    task->push_back(e);
    // add nested constraints
    task->insert(task->end(), nested.begin(), nested.end());
    // save the task
    tasks.push_back(save_task(task));
  }
}

int Z3AstParser::parse_gep(dfsan_label ptr_label, uptr ptr, dfsan_label index_label, int64_t index,
                           uint64_t num_elems, uint64_t elem_size, int64_t current_offset,
                           bool enum_index, std::vector<uint64_t> &tasks) {

  if (index_label < CONST_OFFSET ||
      index_label == __dfsan::kInitializingLabel || index_label >= size_ ||
      ptr_label == __dfsan::kInitializingLabel || ptr_label >= size_) {
    // invalid label
    return -1;
  }

  // early return if nothing to do
  if (!enum_index || // if we are not enumerating the index
      (num_elems == 0 && // if the GEP type is not an array,
       // and we also don't have a pointer label
       ptr_label == 0)) {
    return 0;
  }

  try {
    // prepare current index
    uint16_t size = get_label_info(index_label)->size;
    z3::expr r = context_.bv_val(index, size);

    input_dep_set_t inputs;
    z3::expr i = serialize(index_label, inputs);

#if FILTER_WRONG_AST
    if (value_cache_[index_label] != index) {
      // recalculated value must match the recorded value
      fprintf(stderr, "WARNING: value mismatch for label %u: expected %ld, got %ld\n",
              index_label, value_cache_[index_label], index);
      return -1;
    }
#endif

    // mark expression type for linking detection
    mark_expr_type(index_label, inputs);

    // collect nested constraints
    collect_more_deps(inputs);

    z3_task_t nested_tasks;
    add_nested_constraints(inputs, &nested_tasks);

    // Normalize index expr to 64-bit bitvector.
    // String-derived constraints may produce Int-sort indices.
    z3::expr idx = i;
    if (idx.is_bool()) {
      // Defensive normalization: bool -> 1-bit BV.
      idx = z3::ite(idx, context_.bv_val(1, 1), context_.bv_val(0, 1));
    }
    if (idx.is_int()) {
      idx = z3::int2bv(64, idx);
    } else if (idx.is_bv()) {
      unsigned idx_bits = idx.get_sort().bv_size();
      if (idx_bits < 64) {
        idx = z3::zext(idx, 64 - idx_bits);
      } else if (idx_bits > 64) {
        idx = idx.extract(63, 0);
      }
    } else {
      throw z3::exception("GEP index has unsupported sort");
    }

    // first, check against fixed array bounds if available
    if (num_elems > 0) {
      construct_index_tasks(idx, index, 0, num_elems, 1, nested_tasks, tasks);
    } else {
      dfsan_label_info *bounds = get_label_info(ptr_label);
      // fprintf(stderr, "GEP bounds: lower=0x%lx, upper=0x%lx)\n",
      //     bounds->op1.i, bounds->op2.i);
      // if the array size is unknow, check bound info
      if (bounds->op == __dfsan::Alloca ||
          // due to async solving, we may have a Free op
          bounds->op == __dfsan::Free) {
        z3::expr es = context_.bv_val(elem_size, 64);
        z3::expr co = context_.bv_val(current_offset, 64);
        if (bounds->l2 == 0) {
          // only perform index enumeration and bound check
          // when the size of the buffer is fixed
          z3::expr p = context_.bv_val(ptr, 64);
          z3::expr np = idx * es + co + p;
          construct_index_tasks(np, index, (uint64_t)bounds->op1.i,
              (uint64_t)bounds->op2.i, elem_size, nested_tasks, tasks);
        }
      }
    }

    // always preserve
    save_constraint(i == r, inputs);

    return 0; // success
  } catch (z3::exception e) {
    // logf("WARNING: solving error: %s\n", e.msg());
  } catch (std::exception& e) {
    fprintf(stderr, "WARNING: std::exception in parse_gep: %s\n", e.what());
  } catch (...) {
    fprintf(stderr, "WARNING: unknown exception in parse_gep\n");
  }

  // exception happened, nothing added
  return -1;
}

int Z3AstParser::add_constraints(dfsan_label label, uint64_t result) {
  if (label < CONST_OFFSET || label == __dfsan::kInitializingLabel || label >= size_) {
    // invalid label
    return -1;
  }

  try {
    input_dep_set_t inputs;
    z3::expr expr = serialize(label, inputs);

    // mark expression type for linking detection
    mark_expr_type(label, inputs);

    collect_more_deps(inputs);

    // prepare result
    uint16_t size = get_label_info(label)->size;
    z3::expr r = context_.bv_val(result, size);
    // add constraint
    if (expr.is_bool()) r = context_.bool_val(result);

#if FILTER_WRONG_AST
    // double check if label is valid
    if (value_cache_[label] != result) {
      // recalculated value must match the recorded value
      fprintf(stderr, "WARNING: value mismatch for label %u: expected %ld, got %ld\n",
              label, value_cache_[label], result);
      return -1;
    }
#endif

    save_constraint(expr == r, inputs);
  } catch (z3::exception e) {
    return -1;
  } catch (std::exception& e) {
    fprintf(stderr, "WARNING: std::exception in add_constraints: %s\n", e.what());
    return -1;
  } catch (...) {
    fprintf(stderr, "WARNING: unknown exception in add_constraints\n");
    return -1;
  }

  return 0;
}

int Z3AstParser::record_minimize(dfsan_label label) {
  if (label < CONST_OFFSET || label == __dfsan::kInitializingLabel || label >= size_) {
    return -1;
  }

  try {
    input_dep_set_t inputs;
    z3::expr expr = serialize(label, inputs);
    if (expr.is_bv() && !inputs.empty()) {
      minimize_hints_.emplace_back(expr, inputs);
    }
  } catch (z3::exception e) {
    fprintf(stderr, "WARNING: z3 exception in record_minimize: %s\n", e.msg());
    return -1;
  } catch (...) {
    return -1;
  }

  return 0;
}

void Z3AstParser::mark_expr_type(dfsan_label label, input_dep_set_t &inputs) {
  bool is_bv = is_label_bv_.at(label);
  bool is_seq = is_label_seq_.at(label);
  // fprintf(stderr, "DEBUG mark_expr_type: label %u is_bv=%d is_seq=%d\n", label, is_bv, is_seq);

  for (auto off : inputs) {
    auto c = get_branch_dep(off);
    if (c == nullptr) {
      throw z3::exception("branch_dep not found for input byte");
    }
    // Update type flags (accumulate, don't overwrite)
    c->used_in_bv |= is_bv;
    c->used_in_seq |= is_seq;
    // fprintf(stderr, "DEBUG mark_expr_type: offset (%u, %u), used_in_bv=%d, used_in_seq=%d\n",
    //         off.first, off.second, c->used_in_bv, c->used_in_seq);
  }
}

void Z3AstParser::save_constraint(z3::expr expr, input_dep_set_t &inputs) {
  for (auto off : inputs) {
    auto c = get_branch_dep(off);
    if (c == nullptr) {
      throw z3::exception("branch_dep not found for input byte");
    }
    c->input_deps.insert(inputs.begin(), inputs.end());
    c->expr_deps.insert(expr);
  }
}

void Z3AstParser::collect_more_deps(input_dep_set_t &inputs) {
  // collect additional input deps
  std::vector<offset_t> worklist;
  worklist.insert(worklist.begin(), inputs.begin(), inputs.end());
  while (!worklist.empty()) {
    auto off = worklist.back();
    worklist.pop_back();

    auto deps = get_branch_dep(off);
    if (deps != nullptr) {
      for (auto &i : deps->input_deps) {
        if (inputs.insert(i).second)
          worklist.push_back(i);
      }
    }
  }
}

size_t Z3AstParser::add_nested_constraints(input_dep_set_t &inputs, z3_task_t *task) {
  expr_set_t added;
  std::vector<offset_t> need_linking;

  for (auto &off : inputs) {
    // fprintf(stderr, "adding offset %d\n", off.second);
    auto deps = get_branch_dep(off);
    if (deps != nullptr) {
      // Check if this offset is used in both constraint types
      if (deps->used_in_bv && deps->used_in_seq) {
        // fprintf(stderr, "DEBUG: need linking for offset (%u, %u)\n", off.first, off.second);
        need_linking.push_back(off);
      }

      for (auto &expr : deps->expr_deps) {
        if (added.insert(expr).second) {
          // fprintf(stderr, "adding expr: %s\n", expr.to_string().c_str());
          task->push_back(expr);
        }
      }
    }
  }

  // Add linking constraints for overlapping offsets
  for (auto &off : need_linking) {
    add_string_bitvec_link(off, task);
  }

  return added.size();
}

void Z3AstParser::add_string_bitvec_link(offset_t off, z3_task_t *task) {
  // Check if input_id is valid
  if (off.first >= string_ranges_.size()) return;

  auto &ranges = string_ranges_[off.first];

  // Use upper_bound with transparent comparator - search with just uint32_t
  // Find first range where start > off.second, then go back one
  auto it = ranges.upper_bound(off.second);

  if (it != ranges.begin()) {
    --it;
    if (off.second >= it->start && off.second < it->end) {
      // Found covering range, use cached exprs directly
      uint32_t pos_in_string = off.second - it->start;

      z3::expr str_var = it->str_expr;  // cached str- expr

      // Get cached input- expr from branch_dependency
      z3::expr input_var = get_branch_dep(off)->input_expr;

      // str_var[pos] as integer == input_var as integer
      // Extract single-char substring, then convert to code point
      z3::expr pos_expr = context_.int_val(pos_in_string);
      z3::expr one = context_.int_val(1);
      z3::expr single_char_str(context_, Z3_mk_seq_extract(context_, str_var, pos_expr, one));
      z3::expr char_code(context_, Z3_mk_string_to_code(context_, single_char_str));
      z3::expr byte_val = z3::bv2int(input_var, false);

      // Add the linking constraint
      task->push_back(char_code == byte_val);

      // fprintf(stderr, "DEBUG: adding link constraint: %s\n",
      //         (char_code == byte_val).to_string().c_str());
    }
  }
}

Z3ParserSolver::solving_status
Z3ParserSolver::solve_task(uint64_t task_id, unsigned timeout, solution_t &solutions) {
  solving_status ret = unknown_error;
  auto task = retrieve_task(task_id);
  if (task == nullptr) {
    return invalid_task;
  }

  try {
    // setup global solver
    // Use default solver to auto-detect theory (needed for string constraints)
    z3::solver solver(context_);
    solver.set("timeout", timeout);
    // add auxiliary constraints (e.g., Int variable bounds from sort coercion)
    for (const auto &ac : aux_constraints_) {
      solver.add(ac);
    }
    // solve the first constraint (optimistic)
    z3::expr e = task->at(0);
    solver.add(e);
    // fprintf(stderr, "DEBUG solve_task[%lu]: checking first constraint: %s\n", task_id, e.to_string().c_str());
    z3::check_result res = solver.check();
    // fprintf(stderr, "DEBUG solve_task[%lu]: result = %d (sat=1, unsat=0, unknown=2)\n", task_id, (int)res);
    if (res == z3::sat) {
      ret = opt_sat;
      // optimistic sat, save a model
      z3::model m = solver.get_model();
      // fprintf(stderr, "DEBUG solve_task[%lu]: optimistic SAT model:\n%s\n", task_id, m.to_string().c_str());
      // check nested, if any
      if (task->size() > 1) {
        solver.push();
        // add nested constraints
        // fprintf(stderr, "DEBUG solve_task[%lu]: adding %zu nested constraints\n", task_id, task->size() - 1);
        for (size_t i = 1; i < task->size(); i++) {
          // fprintf(stderr, "DEBUG solve_task[%lu]: nested[%zu]: %s\n", task_id, i, task->at(i).to_string().c_str());
          solver.add(task->at(i));
        }
        res = solver.check();
        // fprintf(stderr, "DEBUG solve_task[%lu]: nested result = %d (sat=1, unsat=0, unknown=2)\n", task_id, (int)res);
        if (res == z3::sat) {
          ret = nested_sat;
          m = solver.get_model();
          // fprintf(stderr, "DEBUG solve_task[%lu]: nested SAT model:\n%s\n", task_id, m.to_string().c_str());
        } else if (res == z3::unsat) {
          fprintf(stderr, "WARNING: nested unsat for task %lu: %s\n",
              task_id, solver.to_smt2().c_str());
          ret = opt_sat_nested_unsat;
        } else {
          ret = opt_sat_nested_timeout;
        }
      } else {
        ret = nested_sat; // XXX: upgrade to nested_sat?
      }

      // Check if model contains strlen/str symbols and optimize if needed
      std::vector<std::pair<z3::expr, uint64_t>> strlen_vars; // (var, max_len)
      std::vector<z3::expr> str_len_minimize; // str.len(str_var) to minimize
      const uint64_t MAX_STRLEN_EXTEND = 4096; // Reasonable max extension

      // Collect input offsets from the model for minimize hint matching
      std::unordered_set<offset_t, offset_hash> model_inputs;

      for (unsigned i = 0; i < m.num_consts(); ++i) {
        z3::func_decl decl = m.get_const_decl(i);
        if (decl.name().kind() == Z3_STRING_SYMBOL) {
          if (decl.name().str().find("strlen") == 0) {
            uint32_t input, offset, null_from_input;
            uint64_t orig_len;
            if (sscanf(decl.name().str().c_str(), strlen_name_format,
                       &input, &offset, &orig_len, &null_from_input) == 4) {
              z3::expr strlen_var = context_.constant(decl.name(), decl.range());
              uint64_t max_len = orig_len + MAX_STRLEN_EXTEND;
              strlen_vars.emplace_back(strlen_var, max_len);
            }
          } else if (decl.name().str().find("str-") == 0) {
            // Minimize string variable lengths to avoid unnecessarily large strings
            z3::expr str_var = context_.constant(decl.name(), decl.range());
            z3::expr len_expr(context_, Z3_mk_seq_length(context_, str_var));
            str_len_minimize.push_back(len_expr);
          } else if (decl.name().str().find("input") == 0) {
            uint32_t input, offset;
            if (sscanf(decl.name().str().c_str(), input_name_format, &input, &offset) == 2) {
              model_inputs.emplace(input, offset);
            }
          }
        }
      }

      // Find matching minimize hints based on input dep overlap
      std::vector<z3::expr> alloc_minimize;
      for (const auto &hint : minimize_hints_) {
        for (const auto &dep : hint.second) {
          if (model_inputs.count(dep)) {
            alloc_minimize.push_back(hint.first);
            break;
          }
        }
      }

      if (!strlen_vars.empty() || !str_len_minimize.empty() || !alloc_minimize.empty()) {
        // Try optimizer to minimize values (no hard bounds)
        z3::optimize opt(context_);
        z3::params p(context_);
        p.set("timeout", timeout);
        opt.set(p);

        for (const auto &ac : aux_constraints_) {
          opt.add(ac);
        }
        for (const auto &expr : *task) {
          opt.add(expr);
        }
        for (const auto &sv : strlen_vars) {
          opt.minimize(sv.first);
        }
        for (const auto &sl : str_len_minimize) {
          opt.minimize(sl);
        }
        for (const auto &am : alloc_minimize) {
          opt.minimize(am);
        }

        bool use_optimized = false;
        if (opt.check() == z3::sat) {
          z3::model opt_model = opt.get_model();
          // Check if all strlen values are within bounds
          bool all_within_bounds = true;
          for (const auto &sv : strlen_vars) {
            z3::expr val = opt_model.eval(sv.first, true);
            uint64_t strlen_val = val.get_numeral_uint64();
            if (strlen_val > sv.second) {
              all_within_bounds = false;
              break;
            }
          }
          if (all_within_bounds) {
            m = opt_model;
            use_optimized = true;
          }
          // else: optimized model exceeds bounds, fall back to bounded solver
        }

        // Step 2: If optimization failed or exceeded bounds, try solver with bound constraints
        if (!use_optimized) {
          solver.push();
          for (const auto &sv : strlen_vars) {
            solver.add(z3::ule(sv.first, context_.bv_val(sv.second, sv.first.get_sort().bv_size())));
          }
          if (solver.check() == z3::sat) {
            m = solver.get_model();
          } else {
            // Unsolvable within bounds, skip
            solver.pop();
            return ret;
          }
          solver.pop();
        }
      }

      generate_solution(m, solutions);
      // fprintf(stderr, "DEBUG solve_task[%lu]: after generate_solution, solutions.size() = %zu\n", task_id, solutions.size());
    } else if (res == z3::unsat) {
      // fprintf(stderr, "DEBUG solve_task[%lu]: UNSAT\n", task_id);
      ret = opt_unsat;
    } else {
      // fprintf(stderr, "DEBUG solve_task[%lu]: TIMEOUT\n", task_id);
      ret = opt_timeout;
    }
  } catch (z3::exception ze) {
    fprintf(stderr, "WARNING: solve_task[%lu]: EXCEPTION: %s\n", task_id, ze.msg());
    ret = unknown_error;
  }

  // fprintf(stderr, "DEBUG solve_task[%lu]: returning with ret=%d, solutions.size() = %zu\n", task_id, ret, solutions.size());
  return ret;
}

void Z3ParserSolver::generate_solution(z3::model &m, solution_t &solutions) {
  // from qsym
  unsigned num_constants = m.num_consts();
  // fprintf(stderr, "DEBUG generate_solution: model has %u constants\n", num_constants);
  for (unsigned i = 0; i < num_constants; i++) {
    z3::func_decl decl = m.get_const_decl(i);
    z3::expr e = m.get_const_interp(decl);
    z3::symbol name = decl.name();

    if (name.kind() == Z3_STRING_SYMBOL) {
      // fprintf(stderr, "DEBUG generate_solution: processing symbol '%s' = %s\n",
      //         name.str().c_str(), e.to_string().c_str());
      if (name.str().find("input") == 0) {
        uint32_t input;
        uint32_t offset;
        sscanf(name.str().c_str(), input_name_format, &input, &offset);
        uint8_t value = (uint8_t)e.get_numeral_int();
        // fprintf(stderr, "DEBUG input-%u-%u: SET offset %u = 0x%02x (individual byte)\n",
        //         input, offset, offset, value);
        solutions.emplace_back(input, offset, value);
      } else if (!name.str().compare("fsize")) {
        // FIXME:
        // off_t size = (off_t)e.get_numeral_int64();
        // if (size > input_size) { // grow
        //   lseek(fd, size, SEEK_SET);
        //   uint8_t dummy = 0;
        //   write(fd, &dummy, sizeof(dummy));
        // } else {
        //   AOUT("truncate file to %ld\n", size);
        //   ftruncate(fd, size);
        // }
        throw z3::exception("skip fsize constraints");
      } else if (name.str().find("atoi") == 0) {
        uint32_t input;
        uint32_t offset;
        int base;
        uint64_t orig_len;
        char buf[64];
        int parsed = sscanf(name.str().c_str(), atoi_name_format, &input, &offset, &base, &orig_len);
        if (parsed != 4) {
          continue;
        }
        const char *format = NULL;
        switch (base) {
          case 2: format = "%lb"; break;
          case 8: format = "%lo"; break;
          case 10: format = "%ld"; break;
          case 16: format = "%lx"; break;
          default: throw z3::exception("unsupported base");
        }
        // XXX: assumed signed
        int new_len = snprintf(buf, 64, format, (int)e.get_numeral_int());

        if ((uint64_t)new_len > orig_len) {
          // Extending: insert extra digits
          std::vector<uint8_t> insert_bytes(buf + orig_len, buf + new_len);
          solutions.emplace_back(input, offset + (uint32_t)orig_len, std::move(insert_bytes));
          // Set the common prefix
          for (uint64_t i = 0; i < orig_len; ++i) {
            solutions.emplace_back(input, offset + (uint32_t)i, (uint8_t)buf[i]);
          }
        } else if ((uint64_t)new_len < orig_len) {
          // Shrinking: delete extra bytes
          solutions.emplace_back(solution_op_t::DELETE, input,
                                 offset + (uint32_t)new_len,
                                 (uint32_t)(orig_len - new_len));
          // Set the new digits
          for (int i = 0; i < new_len; ++i) {
            solutions.emplace_back(input, offset + i, (uint8_t)buf[i]);
          }
        } else {
          // Same length: just set the digits
          for (int i = 0; i < new_len; ++i) {
            solutions.emplace_back(input, offset + i, (uint8_t)buf[i]);
          }
        }
        // Set null terminator at the new end
        solutions.emplace_back(input, offset + new_len, (uint8_t)0);
      } else if (name.str().find("strlen") == 0) {
        uint32_t input;
        uint32_t offset;
        uint64_t orig_len;
        uint32_t null_from_input;
        if (sscanf(name.str().c_str(), strlen_name_format,
                   &input, &offset, &orig_len, &null_from_input) != 4) {
          throw z3::exception("malformed strlen symbol name");
        }

        uint64_t target_len = e.get_numeral_uint64();
        // fprintf(stderr, "DEBUG generate_solution: strlen-%u-%u: orig=%lu, target=%lu, null_from_input=%u\n",
        //         input, offset, orig_len, target_len, null_from_input);

        if (target_len > orig_len) {
          // Extending: insert bytes to make the string longer
          uint64_t extend_by = target_len - orig_len;
          std::vector<uint8_t> fill_bytes(extend_by, 'A');
          solutions.emplace_back(input, offset + (uint32_t)orig_len, std::move(fill_bytes));
          // For plain strings (null_from_input=1), add null terminator at new end
          // For structured formats (null_from_input=0), delimiter handles termination
          if (null_from_input) {
            solutions.emplace_back(input, offset + (uint32_t)target_len, (uint8_t)0);
          }
        } else if (target_len < orig_len) {
          // Shrinking: delete bytes to make the string shorter
          uint64_t shrink_by = orig_len - target_len;
          solutions.emplace_back(solution_op_t::DELETE, input,
                                 offset + (uint32_t)target_len,
                                 (uint32_t)shrink_by);
        }
        // target_len == orig_len: no change needed
      } else if (name.str().find("str-") == 0) {
        // String variable from strchr/strstr: str-input-offset-len
        // Extract byte values from the string and generate solutions
        // Handle length changes with INSERT/DELETE like strlen does
        uint32_t input;
        uint32_t offset;
        uint32_t orig_len;
        if (sscanf(name.str().c_str(), str_name_format, &input, &offset, &orig_len) != 3) {
          continue;  // Skip malformed string variable
        }

        // Get the string value from Z3 and decode escape sequences
        if (e.is_string_value()) {
          std::string raw_str = e.get_string();
          std::vector<uint8_t> bytes = decode_z3_string(raw_str);
          uint32_t new_len = bytes.size();
          fprintf(stderr, "DEBUG generate_solution: str-%u-%u-%u: orig=%u, new=%u, raw='%s'\n",
                  input, offset, orig_len, orig_len, new_len, raw_str.c_str());

          if (new_len > orig_len) {
            // Extending: set common prefix, then insert extra bytes
            for (uint32_t j = 0; j < orig_len; j++) {
              solutions.emplace_back(input, offset + j, bytes[j]);
            }
            // Insert the extra bytes after the original range
            std::vector<uint8_t> insert_bytes(bytes.begin() + orig_len, bytes.end());
            solutions.emplace_back(input, offset + orig_len, std::move(insert_bytes));
          } else if (new_len < orig_len) {
            // Shrinking: set new content, then delete extra bytes
            for (uint32_t j = 0; j < new_len; j++) {
              solutions.emplace_back(input, offset + j, bytes[j]);
            }
            // Delete the bytes we no longer need
            solutions.emplace_back(solution_op_t::DELETE, input,
                                   offset + new_len,
                                   orig_len - new_len);
          } else {
            // Same length: just set all bytes
            for (uint32_t j = 0; j < new_len; j++) {
              solutions.emplace_back(input, offset + j, bytes[j]);
            }
          }
        }
      } else if (name.str().find("int-") == 0) {
        // Int variable from BV-to-Int sort coercion (int-input-offset-bits)
        // Maps back to input byte(s)
        uint32_t input, offset, bits;
        if (sscanf(name.str().c_str(), int_name_format,
                   &input, &offset, &bits) != 3) {
          continue;
        }
        uint64_t value = e.get_numeral_uint64();
        uint32_t bytes = bits / 8;
        if (bytes == 0) bytes = 1;
        // Emit byte-level solutions (little-endian)
        for (uint32_t i = 0; i < bytes; i++) {
          solutions.emplace_back(input, offset + i, (uint8_t)(value & 0xff));
          value >>= 8;
        }
      } else if (name.str().find("strrchr_idx_") == 0 ||
                 name.str().find("strchr_idx_") == 0) {
        // Index variables from strchr/strrchr - skip, they're intermediate
        continue;
      } else {
        // Skip unknown symbols - Z3 string theory creates internal variables
        continue;
      }
    }
  }

  // Post-process solutions: replace null bytes (0x00) with non-null placeholder ('A')
  // for bytes within string ranges. Z3 doesn't model C null-termination so may put
  // nulls before the target character position.

  // // Debug: print string ranges
  // fprintf(stderr, "DEBUG generate_solution: string_ranges_ has %zu entries\n", string_ranges_.size());
  // for (const auto &entry : string_ranges_) {
  //   fprintf(stderr, "DEBUG generate_solution: input %u has %zu ranges\n", entry.first, entry.second.size());
  //   for (const auto &range : entry.second) {
  //     fprintf(stderr, "DEBUG generate_solution:   range [%u, %u)\n", range.first, range.second);
  //   }
  // }

  // Replace null bytes within string ranges (tracked in string_ranges_)
  for (auto &sol : solutions) {
    if (sol.op == solution_op_t::SET && sol.val == 0x00) {
      if (sol.id < string_ranges_.size()) {
        auto &ranges = string_ranges_[sol.id];
        for (const auto &range : ranges) {
          // If this offset is within a string range (but not at the end), replace null
          if (sol.offset >= range.start && sol.offset < range.end) {
            // fprintf(stderr, "DEBUG generate_solution: replacing null at offset %u (in range [%u,%u))\n",
            //         sol.offset, range.start, range.end);
            sol.val = 'A';  // Replace null with 'A'
            break;
          }
        }
      }
    }
  }

  // fprintf(stderr, "DEBUG generate_solution: finished with %zu solutions\n", solutions.size());
}

int Z3ParserSolver::export_task_smt2(uint64_t task_id, int fd) {
  // Use tasks_.find() to peek without removing
  auto it = tasks_.find(task_id);
  if (it == tasks_.end()) {
    return -1;
  }
  auto task = it->second;

  try {
    // Create solver and add all constraints
    z3::solver solver(context_);
    for (const auto &ac : aux_constraints_) {
      solver.add(ac);
    }
    for (const auto &expr : *task) {
      solver.add(expr);
    }

    // Export as SMT2
    std::string smt2 = solver.to_smt2();
    ssize_t written = write(fd, smt2.c_str(), smt2.size());
    if (written < 0 || (size_t)written != smt2.size()) {
      return -1;
    }
    return 0;
  } catch (z3::exception &e) {
    fprintf(stderr, "WARNING: export_task_smt2[%lu]: %s\n", task_id, e.msg());
    return -1;
  }
}

// Build Z3 string from a content label (Load or Concat of bytes)
// Creates a symbolic string variable with naming convention: str-input-offset-len
z3::expr Z3AstParser::build_string_from_label(dfsan_label label, input_dep_set_t &deps) {
  if (label < CONST_OFFSET) {
    throw z3::exception("Invalid string label");  // No tainted content
  }

  dfsan_label_info *info = get_label_info(label);

  // Handle Load: multi-byte load from input - create a single symbolic string
  if (info->op == __dfsan::Load) {
    uint32_t offset = get_label_info(info->l1)->op1.i;
    uint32_t input = get_label_info(info->l1)->op2.i;
    uint32_t len = info->l2;  // number of bytes loaded

    // Add dependencies for all bytes in the range
    for (uint32_t i = 0; i < len; i++) {
      deps.insert(std::make_pair(input, offset + i));
    }

    // Create a single symbolic string variable: str-input-offset-len
    char name[256];
    snprintf(name, sizeof(name), str_name_format, input, offset, len);
    z3::symbol symbol = context_.str_symbol(name);
    z3::expr str_var = context_.constant(symbol, context_.string_sort());

    // Track string range for null-byte post-processing and linking constraints
    if (input < string_ranges_.size()) {
      string_ranges_[input].emplace(offset, offset + len, str_var);
    }

    // Cache string info for this label
    string_info_cache_[label] = {input, offset, len};

    return str_var;
  }

  // Handle fsubstr and fstrcat: these ops cache String expressions
  if (is_content_string_op(info->op)) {
    // Should be cached from earlier processing
    return get_cached_expr(label, deps);
  }

  // Handle fstr_off: string op pointer + constant offset (from GEP)
  // l1 = string op label (fstrchr, etc.), op2 = byte offset
  if (info->op == __dfsan::fstr_off) {
    if (info->l1 == 0) {
      throw z3::exception("fstr_off with constant l1");
    }
    dfsan_label_info *str_op_info = get_label_info(info->l1);

    // The string op's l1 is the base string content
    if (str_op_info->l1 >= CONST_OFFSET) {
      int64_t gep_offset = (int64_t)info->op2.i;

      // Get concrete values to check if we're beyond the end
      // Bounds check: value_cache_ is indexed by label
      if (info->l1 >= value_cache_.size()) {
        throw z3::exception("fstr_off label out of value cache bounds");
      }
      int64_t str_op_pos = (int64_t)value_cache_[info->l1];  // position of found char
      int64_t concrete_start = str_op_pos + gep_offset;

      // Build haystack string FIRST - this populates string_info_cache_
      dfsan_label content_label = str_op_info->l1;
      z3::expr haystack = build_string_from_label(content_label, deps);

      // Get string info directly from cache (populated by build_string_from_label)
      auto it = string_info_cache_.find(content_label);
      if (it == string_info_cache_.end()) {
        throw z3::exception("string info not found in cache for fstr_off");
      }
      uint32_t input_id = it->second.input_id;
      uint32_t base_offset = it->second.offset;
      uint32_t haystack_len = it->second.length;

      // fprintf(stderr, "DEBUG build_string_from_label fstr_off: content_label=%u, haystack_len=%u, input_id=%u, base_offset=%u, concrete_start=%ld\n",
      //         content_label, haystack_len, input_id, base_offset, concrete_start);

      // Check if start is beyond the end of the haystack
      if (concrete_start >= (int64_t)(base_offset + haystack_len)) {
        // Beyond end: create a new insertion point variable
        // str-<input>-<offset>-0 means "string at offset with no original content"
        // fprintf(stderr, "DEBUG build_string_from_label: fstr_off beyond end, creating insertion point %s\
           -n", name);
        char name[256];
        snprintf(name, sizeof(name), "str-%u-%ld-0", input_id, concrete_start);
        z3::symbol symbol = context_.str_symbol(name);
        z3::expr str_var = context_.constant(symbol, context_.string_sort());

        // Don't add dependency for insertion point - it's beyond file bounds
        return str_var;
      }

      // Within bounds: use original suffix extraction
      z3::expr idx_expr = get_cached_expr(info->l1, deps);
      z3::expr suffix_start = idx_expr + (int)gep_offset;
      z3::expr haystack_len_expr(context_, Z3_mk_seq_length(context_, haystack));
      z3::expr suffix_len = haystack_len_expr - idx_expr - (int)gep_offset;

      return z3::to_expr(context_, Z3_mk_seq_extract(context_,
                                                     haystack,
                                                     suffix_start,
                                                     suffix_len));
    }
    throw z3::exception("invalid str_op for fstr_off");
  }

  // Handle string search ops (fstrchr, fstrrchr, fstrstr, fstrpbrk):
  // These labels represent pointer results. When used as content directly
  // (without GEP offset), we build content at the found position.
  if (is_indexof_op(info->op)) {
    if (info->l1 >= CONST_OFFSET) {
      // Get the index expression for this string op (if already cached)
      z3::expr idx_expr = get_cached_expr(label, deps);

      // Build the full haystack string
      z3::expr haystack = build_string_from_label(info->l1, deps);

      // Create suffix starting at the found position (no offset)
      // substr(haystack, idx, len-idx) - content from found position to end
      z3::expr haystack_len(context_, Z3_mk_seq_length(context_, haystack));
      z3::expr suffix_len = haystack_len - idx_expr;

      return z3::to_expr(context_, Z3_mk_seq_extract(context_,
                                                      haystack,
                                                      idx_expr,
                                                      suffix_len));
    }
    throw z3::exception("invalid l1 for fstr_op");
  }

  // Handle Concat: check if it's a chain of consecutive input bytes
  // If so, create a single string variable for the whole range
  if (info->op == __dfsan::Concat) {
    // Try to find the range of consecutive input bytes
    uint32_t min_offset = UINT32_MAX;
    uint32_t max_offset = 0;
    uint32_t input_id = UINT32_MAX;
    bool is_consecutive = true;
    std::vector<uint32_t> offsets;

    // Helper lambda to collect offsets from a label
    std::function<void(dfsan_label)> collect_offsets = [&](dfsan_label label) {
      if (!is_consecutive) return;
      if (label < CONST_OFFSET) {
        // Concrete byte in the chain - mark as non-consecutive
        is_consecutive = false;
        return;
      }
      dfsan_label_info *linfo = get_label_info(label);
      if (linfo->op == 0) {
        // Single input byte
        uint32_t off = linfo->op1.i;
        uint32_t inp = linfo->op2.i;
        if (input_id == UINT32_MAX) input_id = inp;
        else if (input_id != inp) { is_consecutive = false; return; }
        offsets.push_back(off);
        if (off < min_offset) min_offset = off;
        if (off > max_offset) max_offset = off;
      } else if (linfo->op == __dfsan::Concat) {
        collect_offsets(linfo->l1);
        collect_offsets(linfo->l2);
      } else {
        // Other operation - not a simple byte chain
        is_consecutive = false;
      }
    };

    collect_offsets(label);

    // Check if offsets are truly consecutive
    if (is_consecutive && !offsets.empty() && input_id != UINT32_MAX) {
      std::sort(offsets.begin(), offsets.end());
      for (size_t i = 1; i < offsets.size(); i++) {
        if (offsets[i] != offsets[i-1] + 1) {
          is_consecutive = false;
          break;
        }
      }
    }

    if (is_consecutive && !offsets.empty()) {
      // Create a single string variable for the whole range
      uint32_t len = offsets.size();
      uint32_t start_offset = offsets[0];

      // Add dependencies for all bytes
      for (uint32_t off : offsets) {
        deps.insert(std::make_pair(input_id, off));
      }

      // Create single symbolic string variable
      char name[256];
      snprintf(name, sizeof(name), str_name_format, input_id, start_offset, len);
      z3::symbol symbol = context_.str_symbol(name);
      z3::expr str_var = context_.constant(symbol, context_.string_sort());

      // Track string range for null-byte post-processing and linking constraints
      if (input_id < string_ranges_.size()) {
        string_ranges_[input_id].emplace(start_offset, start_offset + len, str_var);
      }

      // Cache string info for this label
      string_info_cache_[label] = {input_id, start_offset, len};

      return str_var;
    }

    // Fall back to recursive concatenation if not consecutive
    z3::expr left(context_);
    z3::expr right(context_);

    if (info->l1 >= CONST_OFFSET) {
      left = build_string_from_label(info->l1, deps);
    } else {
      char c = (char)(info->op1.i & 0xff);
      left = context_.string_val(std::string(1, c));
    }

    if (info->l2 >= CONST_OFFSET) {
      right = build_string_from_label(info->l2, deps);
    } else {
      char c = (char)(info->op2.i & 0xff);
      right = context_.string_val(std::string(1, c));
    }

    // Try to cache combined string info from children for downstream lookups
    // Use left child's info as base (it comes first in the concat)
    if (info->l1 >= CONST_OFFSET) {
      auto it = string_info_cache_.find(info->l1);
      if (it != string_info_cache_.end()) {
        uint32_t combined_len = it->second.length;
        // Add right child's length if available
        if (info->l2 >= CONST_OFFSET) {
          auto it2 = string_info_cache_.find(info->l2);
          if (it2 != string_info_cache_.end()) {
            combined_len += it2->second.length;
          }
        } else {
          combined_len += 1; // concrete byte
        }
        string_info_cache_[label] = {it->second.input_id, it->second.offset, combined_len};
      }
    }

    return z3::concat(left, right);
  }

  // Handle single input byte (op == 0)
  if (info->op == 0) {
    uint32_t offset = info->op1.i;
    uint32_t input = info->op2.i;

    deps.insert(std::make_pair(input, offset));

    // Create a single-char symbolic string
    char name[256];
    snprintf(name, sizeof(name), str_name_format, input, offset, 1);
    z3::symbol symbol = context_.str_symbol(name);
    z3::expr str_var = context_.constant(symbol, context_.string_sort());

    // Track string range for null-byte post-processing and linking constraints
    if (input < string_ranges_.size()) {
      string_ranges_[input].emplace(offset, offset + 1, str_var);
    }

    // Cache string info for this label
    string_info_cache_[label] = {input, offset, 1};

    return str_var;
  }

  // Last resort: empty string
  return context_.string_val("");
}

// Get byte expression for a specific input offset
z3::expr Z3AstParser::get_byte_expr(uint32_t input, uint32_t offset, input_dep_set_t &deps) {
  deps.insert(std::make_pair(input, offset));
  char name[256];
  snprintf(name, sizeof(name), input_name_format, input, offset);
  z3::symbol symbol = context_.str_symbol(name);
  return context_.constant(symbol, context_.bv_sort(8));
}
