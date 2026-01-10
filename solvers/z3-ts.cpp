#include "dfsan/dfsan.h"

#include "parse-z3.h"

#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

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
};

static std::string get_op_name(uint32_t op) {
  auto itr = OP_MAP.find(op);
  if (itr != OP_MAP.end()) {
    return itr->second;
  }
  return std::to_string(op);
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
  }

int Z3AstParser::restart(std::vector<input_t> &inputs) {

  // reset caches
  memcmp_cache_.clear();
  string_ranges_.clear();
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
  branch_deps_.clear();
  branch_deps_.resize(inputs.size());

  for (size_t i = 0; i < inputs.size(); i++) {
    auto &input = inputs[i];
#if FILTER_WRONG_AST
    inputs_cache_.emplace_back(input.first, input.second);
#endif
    // resize branch_deps_
    branch_deps_[i].resize(input.second);
  }

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
  switch (predicate) {
    case __dfsan::bveq:  return lhs == rhs;
    case __dfsan::bvneq: return lhs != rhs;
    case __dfsan::bvugt: return z3::ugt(lhs, rhs);
    case __dfsan::bvuge: return z3::uge(lhs, rhs);
    case __dfsan::bvult: return z3::ult(lhs, rhs);
    case __dfsan::bvule: return z3::ule(lhs, rhs);
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
  }

  for (dfsan_label l = last_label + 1; l <= label; l++) {

#if FILTER_WRONG_AST
#define RECORD_VALUE(value) \
  value_cache_.emplace_back((uint64_t)(value))
#else
#define RECORD_VALUE(value) \
  do { } while (0)
#endif

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
      snprintf(name, sizeof(name), input_name_format, input, offset);
      z3::symbol symbol = context_.str_symbol(name);
      z3::sort sort = context_.bv_sort(8);
      tsize_cache_.emplace_back(1);
      input_deps.insert(std::make_pair(input, offset));
      // caching is not super helpful
      cache_expr(l, context_.constant(symbol, sort));
      RECORD_VALUE(inputs_cache_[input].first[offset]);
      continue;
    } else if (info->op == __dfsan::Load) {
      uint32_t offset = get_label_info(info->l1)->op1.i; // legacy: offset in op1
      uint32_t input = get_label_info(info->l1)->op2.i;
      snprintf(name, sizeof(name), input_name_format, input, offset);
      z3::symbol symbol = context_.str_symbol(name);
      z3::sort sort = context_.bv_sort(8);
      z3::expr out = context_.constant(symbol, sort);
      input_deps.insert(std::make_pair(input, offset));
#if FILTER_WRONG_AST
      uint64_t val = inputs_cache_[input].first[offset];
#endif
      for (uint32_t i = 1; i < info->l2; i++) {
        snprintf(name, sizeof(name), input_name_format, input, offset + i);
        symbol = context_.str_symbol(name);
        out = z3::concat(context_.constant(symbol, sort), out);
        input_deps.insert(std::make_pair(input, offset + i));
#if FILTER_WRONG_AST
        val |= (uint64_t)inputs_cache_[input].first[offset + i] << (i * 8);
#endif
      }
      tsize_cache_.emplace_back(1);
      cache_expr(l, out);
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
      RECORD_VALUE(value_cache_[info->l1] & ((1UL << base_size) - 1));
      continue;
    } else if (info->op == __dfsan::SExt) {
      z3::expr base = get_cached_expr(info->l1, input_deps);
      uint32_t base_size = base.get_sort().bv_size();
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, z3::sext(base, info->size - base_size));
      RECORD_VALUE((int64_t)(value_cache_[info->l1] & ((1UL << base_size) - 1)));
      continue;
    } else if (info->op == __dfsan::Trunc) {
      z3::expr base = get_cached_expr(info->l1, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, base.extract(info->size - 1, 0));
      RECORD_VALUE(value_cache_[info->l1] & ((1UL << info->size) - 1));
      continue;
    } else if (info->op == __dfsan::IntToPtr) {
      z3::expr e = get_cached_expr(info->l1, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, e);
      RECORD_VALUE(value_cache_[info->l1]);
      continue;
    } else if (info->op == __dfsan::PtrToInt) {
      // PtrToInt converts a pointer to integer
      // If the source is a string op result, convert the index to bitvector
      if (info->l1 >= CONST_OFFSET) {
        dfsan_label_info *src_info = get_label_info(info->l1);
        if (src_info->op >= __dfsan::fstr_op_start && src_info->op < __dfsan::fstr_op_end) {
          // String op result - the "pointer" is semantically the index
          // Convert the Int expression to a bitvector for downstream ops
          z3::expr idx = get_cached_expr(info->l1, input_deps);
          z3::expr bv_idx = z3::int2bv(info->size, idx);
          tsize_cache_.emplace_back(tsize_cache_[info->l1]);
          cache_expr(l, bv_idx);
          RECORD_VALUE(value_cache_[info->l1]);
          continue;
        }
      }
      // For other PtrToInt cases, pass through (shouldn't normally reach here)
      z3::expr e = get_cached_expr(info->l1, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, e);
      RECORD_VALUE(value_cache_[info->l1]);
      continue;
    } //FIXME: other casting ops (BitCast)?
    // symsan-defined
    else if (info->op == __dfsan::Extract) {
      z3::expr base = get_cached_expr(info->l1, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l1]);
      cache_expr(l, base.extract((info->op2.i + info->size) - 1, info->op2.i));
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
      RECORD_VALUE(!value_cache_[info->l2]);
      continue;
    } else if (info->op == __dfsan::Neg) {
      if (info->l2 == 0) {
        throw z3::exception("invalid Neg predicate");
      }
      z3::expr e = get_cached_expr(info->l2, input_deps);
      tsize_cache_.emplace_back(tsize_cache_[info->l2]);
      cache_expr(l, -e);
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
      RECORD_VALUE(info->op2.i); // actual length for value cache
      continue;
    } else if (info->op == __dfsan::fstrchr) {
      // strchr/memchr: find character in string
      // l1 = source pointer label (content bytes, fsubstr, or previous strchr for chaining)
      // l2 = c_label (target character - may be symbolic!)
      // op1 = concrete c value
      // op2 = found position (runtime)

      int64_t found_pos = (int64_t)info->op2.i;

      // Build source string from l1 (content label)
      z3::expr haystack_str = context_.string_val("");
      z3::expr start_offset = context_.int_val(0);

      if (info->l1 >= CONST_OFFSET) {
        dfsan_label_info *src_info = get_label_info(info->l1);

        if (src_info->op == __dfsan::fsubstr) {
          // l1 is a fsubstr - use the cached substr expression directly
          haystack_str = get_cached_expr(info->l1, input_deps);
        } else if (src_info->op >= __dfsan::fstr_op_start && src_info->op < __dfsan::fstr_op_end) {
          // Chained call: search starts after previous match
          z3::expr prev_idx = get_cached_expr(info->l1, input_deps);
          start_offset = prev_idx + 1;
          // Walk back to find original haystack content
          dfsan_label content_label = info->l1;
          dfsan_label_info *chain_info = src_info;
          while (chain_info->op >= __dfsan::fstr_op_start &&
                 chain_info->op < __dfsan::fstr_op_end) {
            content_label = chain_info->l1;
            if (content_label < CONST_OFFSET) break;
            chain_info = get_label_info(content_label);
          }
          if (content_label >= CONST_OFFSET) {
            haystack_str = build_string_from_label(content_label, input_deps);
          }
        } else {
          // Build string from byte content (Load, Concat, or single byte)
          haystack_str = build_string_from_label(info->l1, input_deps);
        }
      }

      // Get target character (concrete or symbolic)
      // Use z3::unit to create single-char string from integer code point
      z3::expr code(context_);
      if (info->l2 == 0) {
        // Concrete character
        uint8_t c = (uint8_t)info->op1.i;
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
      RECORD_VALUE(found_pos);
      continue;
    } else if (info->op == __dfsan::fstrrchr) {
      // strrchr/memrchr: find LAST occurrence of character
      // l1 = source pointer label (content bytes or fsubstr)
      // l2 = c_label (target character - may be symbolic!)
      // op1 = concrete c value
      // op2 = found position (runtime)

      int64_t found_pos = (int64_t)info->op2.i;

      // Build source string from l1 (content label or fsubstr)
      z3::expr haystack_str = context_.string_val("");
      if (info->l1 >= CONST_OFFSET) {
        dfsan_label_info *src_info = get_label_info(info->l1);
        if (src_info->op == __dfsan::fsubstr) {
          // l1 is a fsubstr - use the cached substr expression directly
          haystack_str = get_cached_expr(info->l1, input_deps);
        } else {
          haystack_str = build_string_from_label(info->l1, input_deps);
        }
      }

      // Get target character (concrete or symbolic)
      // Use z3::unit to create single-char string from integer code point
      z3::expr code(context_);
      if (info->l2 == 0) {
        // Concrete character
        uint8_t c = (uint8_t)info->op1.i;
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
      RECORD_VALUE(found_pos);
      continue;
    } else if (info->op == __dfsan::fstrstr) {
      // strstr: find substring
      // l1 = haystack content label (for chaining or byte content)
      // l2 = needle_label (may be symbolic!)
      // size = needle length
      // op1 = needle pointer (for caching if concrete)
      // op2 = found position

      int64_t found_pos = (int64_t)info->op2.i;

      // Build haystack string from l1
      z3::expr haystack_str = context_.string_val("");
      z3::expr start_offset = context_.int_val(0);

      if (info->l1 >= CONST_OFFSET) {
        dfsan_label_info *src_info = get_label_info(info->l1);

        if (src_info->op >= __dfsan::fstr_op_start && src_info->op < __dfsan::fstr_op_end) {
          // Chained call: search starts after previous match
          z3::expr prev_idx = get_cached_expr(info->l1, input_deps);
          start_offset = prev_idx + 1;
          // Walk back to find original haystack content
          dfsan_label content_label = info->l1;
          dfsan_label_info *chain_info = src_info;
          while (chain_info->op >= __dfsan::fstr_op_start &&
                 chain_info->op < __dfsan::fstr_op_end) {
            content_label = chain_info->l1;
            if (content_label < CONST_OFFSET) break;
            chain_info = get_label_info(content_label);
          }
          if (content_label >= CONST_OFFSET) {
            haystack_str = build_string_from_label(content_label, input_deps);
          }
        } else {
          // Build string from byte content
          haystack_str = build_string_from_label(info->l1, input_deps);
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
          needle_str = context_.string_val("");
        }
      } else {
        // Symbolic needle - build string from l2 (Load of tainted buffer)
        needle_str = build_string_from_label(info->l2, input_deps);
      }

      z3::expr idx = z3::indexof(haystack_str, needle_str, start_offset);

      tsize_cache_.emplace_back(1);
      cache_expr(l, idx);
      RECORD_VALUE(found_pos);
      continue;
    } else if (info->op == __dfsan::fsubstr) {
      // fsubstr: substring with length from a previous string op result
      // l1 = original content label (full haystack from previous string op)
      // l2 = string op label (whose cached index becomes the length)
      // op1 = concrete length n

      // Build the full string from l1 (the original content)
      z3::expr full_str = context_.string_val("");
      if (info->l1 >= CONST_OFFSET) {
        full_str = build_string_from_label(info->l1, input_deps);
      }

      // Get the length from l2 (the string op's result index)
      z3::expr len_expr = context_.int_val((int64_t)info->op1.i);
      if (info->l2 >= CONST_OFFSET) {
        // l2 is the string op label - its cached value is the index
        len_expr = get_cached_expr(info->l2, input_deps);
      }

      // Generate substr(full_str, 0, len)
      z3::expr substr_expr = full_str.extract(context_.int_val(0), len_expr);

      tsize_cache_.emplace_back(1);
      cache_expr(l, substr_expr);
      // The substr itself doesn't have a numeric value, but downstream ops will use it
      RECORD_VALUE(info->op1.i);
      continue;
    } else if (info->op == __dfsan::Alloca || info->op == __dfsan::Free) {
      // not expression, do nothing
      tsize_cache_.emplace_back(0);
      expr_cache_.emplace_back(nullptr);
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
      bool l1_is_strfunc = (l1_op == __dfsan::fstrchr || l1_op == __dfsan::fstrrchr ||
                            l1_op == __dfsan::fstrstr);
      bool l2_is_strfunc = (l2_op == __dfsan::fstrchr || l2_op == __dfsan::fstrrchr ||
                            l2_op == __dfsan::fstrstr);

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
    // update tree_size
    tsize_cache_.emplace_back(tsize_cache_[info->l1] + tsize_cache_[info->l2]);

    switch((info->op & 0xff)) {
      // llvm doesn't distinguish between logical and bitwise and/or/xor
      case __dfsan::And: {
        cache_expr(l, info->size != 1 ? (op1 & op2) : (op1 && op2));
        RECORD_VALUE((info->size != 1) ? (val1 & val2) : (val1 && val2));
        break;
      }
      case __dfsan::Or: {
        cache_expr(l, info->size != 1 ? (op1 | op2) : (op1 || op2));
        RECORD_VALUE((info->size != 1) ? (val1 | val2) : (val1 || val2));
        break;
      }
      case __dfsan::Xor: {
        cache_expr(l, op1 ^ op2);
        RECORD_VALUE(val1 ^ val2);
        break;
      }
      case __dfsan::Shl: {
        cache_expr(l, z3::shl(op1, op2));
        RECORD_VALUE(val1 << (val2 % size));
        break;
      }
      case __dfsan::LShr: {
        cache_expr(l, z3::lshr(op1, op2));
        RECORD_VALUE(val1 >> (val2 % size));
        break;
      }
      case __dfsan::AShr: {
        cache_expr(l, z3::ashr(op1, op2));
        RECORD_VALUE((int64_t)val1 >> (val2 % size));
        break;
      }
      case __dfsan::Add: {
        cache_expr(l, op1 + op2);
        RECORD_VALUE(val1 + val2);
        break;
      }
      case __dfsan::Sub: {
        cache_expr(l, op1 - op2);
        RECORD_VALUE(val1 - val2);
        break;
      }
      case __dfsan::Mul: {
        cache_expr(l, op1 * op2);
        RECORD_VALUE(val1 * val2);
        break;
      }
      case __dfsan::UDiv: {
        cache_expr(l, z3::udiv(op1, op2));
        if (val2 == 0) {
          fprintf(stderr, "WARNING: division by zero for label %u\n", l);
          RECORD_VALUE(0);
        } else
          RECORD_VALUE(val1 / val2);
        break;
      }
      case __dfsan::SDiv: {
        cache_expr(l, op1 / op2);
        if (val2 == 0) {
          fprintf(stderr, "WARNING: division by zero for label %u\n", l);
          RECORD_VALUE(0);
        } else
          RECORD_VALUE((int64_t)val1 / (int64_t)val2);
        break;
      }
      case __dfsan::URem: {
        cache_expr(l, z3::urem(op1, op2));
        if (val2 == 0) {
          fprintf(stderr, "WARNING: division by zero for label %u\n", l);
          RECORD_VALUE(0);
        } else
          RECORD_VALUE(val1 % val2);
        break;
      }
      case __dfsan::SRem: {
        cache_expr(l, z3::srem(op1, op2));
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

        cache_expr(l, get_cmd(op1, op2, info->op >> 8));
#if FILTER_WRONG_AST
        // we have both operands recorded for ICmp
        if ((info->op1.i & valmask) != val1 ||
            (info->op2.i & valmask) != val2) {
          // fprintf(stderr, "WARNING: value mismatch for label %u:"
          //         "expected op1 %lu, got %lu, expected op2 %lu, got %lu\n",
          //         l, info->op1.i, val1, info->op2.i, val2);
          // fprintf(stderr, "cond: %s\n", get_cmd(op1, op2, info->op >> 8).to_string().c_str());
          // dump_value_cache(info->l1);
          // dump_value_cache(info->l2);

          // memcmp and atoi are special cases where we don't have the actual
          // value cached, so we fix it using the runtime value from ICmp
          bool is_special = false;
          if (l1_op == __dfsan::fmemcmp || l1_op == __dfsan::fatoi) {
            value_cache_[info->l1] = val1 = info->op1.i;
            is_special = true;
          }
          if (l2_op == __dfsan::fmemcmp || l2_op == __dfsan::fatoi) {
            value_cache_[info->l2] = val2 = info->op2.i;
            is_special = true;
          }
          if (!is_special)
            throw z3::exception("value mismatch for ICmp");
        }
        value_cache_.emplace_back(
            eval_icmp(info->op >> 8, val1, val2, size) ? 1 : 0);
#endif
        break;
      }
      // concat
      case __dfsan::Concat: {
        cache_expr(l, z3::concat(op2, op1)); // little endian
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

    // add negated last branch condition
    z3::expr r = context_.bool_val(result);

#if FILTER_WRONG_AST
    if (value_cache_[label] != result) {
      // recalcuated value must match the recorded value
      fprintf(stderr, "WARNING: value mismatch for label %u: expected %lu, got %d\n",
              label, value_cache_[label], result);
      fprintf(stderr, "cond: %s\n", cond.to_string().c_str());
      dump_value_cache(label);
      return -1;
    }
#endif

    task->push_back((cond != r));

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

    // collect nested constraints
    collect_more_deps(inputs);
    z3_task_t nested_tasks;
    add_nested_constraints(inputs, &nested_tasks);

    // first, check against fixed array bounds if available
    z3::expr idx = z3::zext(i, 64 - size);
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
  }

  return 0;
}

void Z3AstParser::save_constraint(z3::expr expr, input_dep_set_t &inputs) {
  for (auto off : inputs) {
    auto c = get_branch_dep(off);
    if (c == nullptr) {
      auto nc = std::make_unique<struct branch_dependency>();
      c = nc.get();
      set_branch_dep(off, std::move(nc));
    }
    if (c == nullptr) {
      throw z3::exception("out of memory");
    } else {
      c->input_deps.insert(inputs.begin(), inputs.end());
      c->expr_deps.insert(expr);
    }
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
  for (auto &off : inputs) {
    // fprintf(stderr, "adding offset %d\n", off.second);
    auto deps = get_branch_dep(off);
    if (deps != nullptr) {
      for (auto &expr : deps->expr_deps) {
        if (added.insert(expr).second) {
          // fprintf(stderr, "adding expr: %s\n", expr.to_string().c_str());
          task->push_back(expr);
        }
      }
    }
  }
  return added.size();
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
    // solve the first constraint (optimistic)
    z3::expr e = task->at(0);
    solver.add(e);
    fprintf(stderr, "DEBUG solve_task: checking constraint: %s\n", e.to_string().c_str());
    z3::check_result res = solver.check();
    // fprintf(stderr, "DEBUG solve_task: result = %d (sat=1, unsat=0, unknown=2)\n", (int)res);
    if (res == z3::sat) {
      ret = opt_sat;
      // optimistic sat, save a model
      z3::model m = solver.get_model();
      // check nested, if any
      if (task->size() > 1) {
        solver.push();
        // add nested constraints
        for (size_t i = 1; i < task->size(); i++) {
          solver.add(task->at(i));
        }
        res = solver.check();
        if (res == z3::sat) {
          ret = nested_sat;
          m = solver.get_model();
        } else if (res == z3::unsat) {
          // fprintf(stderr, "WARNING: nested unsat for task %lu: %s\n",
          //     task_id, solver.to_smt2().data());
          ret = opt_sat_nested_unsat;
        } else {
          ret = opt_sat_nested_timeout;
        }
      } else {
        ret = nested_sat; // XXX: upgrade to nested_sat?
      }

      // Check if model contains strlen symbols and optimize if needed
      std::vector<std::pair<z3::expr, uint64_t>> strlen_vars; // (var, max_len)
      const uint64_t MAX_STRLEN_EXTEND = 4096; // Reasonable max extension

      for (unsigned i = 0; i < m.num_consts(); ++i) {
        z3::func_decl decl = m.get_const_decl(i);
        if (decl.name().kind() == Z3_STRING_SYMBOL &&
            decl.name().str().find("strlen") == 0) {
          uint32_t input, offset, null_from_input;
          uint64_t orig_len;
          if (sscanf(decl.name().str().c_str(), strlen_name_format,
                     &input, &offset, &orig_len, &null_from_input) == 4) {
            z3::expr strlen_var = context_.constant(decl.name(), decl.range());
            uint64_t max_len = orig_len + MAX_STRLEN_EXTEND;
            strlen_vars.emplace_back(strlen_var, max_len);
          }
        }
      }

      if (!strlen_vars.empty()) {
        // Step 1: Try optimizer to minimize strlen values (no hard bounds)
        z3::optimize opt(context_);
        z3::params p(context_);
        p.set("timeout", timeout);
        opt.set(p);

        for (const auto &expr : *task) {
          opt.add(expr);
        }
        for (const auto &sv : strlen_vars) {
          opt.minimize(sv.first);
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
            // Step 3: Unsolvable within bounds, skip
            solver.pop();
            return ret;
          }
          solver.pop();
        }
      }

      generate_solution(m, solutions);
      // fprintf(stderr, "DEBUG solve_task: after generate_solution, solutions.size() = %zu\n", solutions.size());
    } else if (res == z3::unsat) {
      ret = opt_unsat;
      //AOUT("\n%s\n", __z3_solver.to_smt2().c_str());
      //AOUT("  tree_size = %d", __dfsan_label_info[label].tree_size);
    } else {
      ret = opt_timeout;
    }
  } catch (z3::exception ze) {
    // fprintf(stderr, "DEBUG solve_task: EXCEPTION caught: %s\n", ze.msg());
    ret = unknown_error;
  }

  // fprintf(stderr, "DEBUG solve_task: returning with solutions.size() = %zu\n", solutions.size());
  return ret;
}

void Z3ParserSolver::generate_solution(z3::model &m, solution_t &solutions) {
  // from qsym
  unsigned num_constants = m.num_consts();
  // fprintf(stderr, "DEBUG generate_solution: num_constants = %u\n", num_constants);
  for (unsigned i = 0; i < num_constants; i++) {
    z3::func_decl decl = m.get_const_decl(i);
    z3::expr e = m.get_const_interp(decl);
    z3::symbol name = decl.name();

    // all values should be string symbols
    // fprintf(stderr, "DEBUG generate_solution: var[%u] = %s (kind=%d)\n", i,
    //         name.kind() == Z3_STRING_SYMBOL ? name.str().c_str() : "(int)", name.kind());
    if (name.kind() == Z3_STRING_SYMBOL) {
      if (name.str().find("input") == 0) {
        uint32_t input;
        uint32_t offset;
        sscanf(name.str().c_str(), input_name_format, &input, &offset);
        uint8_t value = (uint8_t)e.get_numeral_int();
        // fprintf(stderr, "DEBUG generate_solution: found input-%u-%u = %u\n", input, offset, value);
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
        uint32_t input;
        uint32_t offset;
        uint32_t len;
        if (sscanf(name.str().c_str(), "str-%u-%u-%u", &input, &offset, &len) != 3) {
          continue;  // Skip malformed string variable
        }

        // Get the string value from Z3
        if (e.is_string_value()) {
          std::string str_val = e.get_string();
          // Generate solutions for each byte
          for (uint32_t j = 0; j < len && j < str_val.size(); j++) {
            solutions.emplace_back(input, offset + j, (uint8_t)str_val[j]);
          }
        }
      } else if (name.str().find("strrchr_idx_") == 0 ||
                 name.str().find("strchr_idx_") == 0) {
        // Index variables from strchr/strrchr - skip, they're intermediate
        continue;
      } else {
        // fprintf(stderr, "DEBUG generate_solution: UNKNOWN symbol '%s', skipping\n", name.str().c_str());
        // Skip unknown symbols instead of throwing - Z3 string theory creates internal variables
        continue;
      }
    }
  }

  // Post-process solutions: replace null bytes (0x00) with non-null placeholder ('A')
  // for bytes within string ranges. Z3 doesn't model C null-termination so may put
  // nulls before the target character position.

  // Debug: print string ranges
  // fprintf(stderr, "DEBUG: string_ranges_ has %zu entries\n", string_ranges_.size());
  // for (const auto &entry : string_ranges_) {
  //   fprintf(stderr, "DEBUG: input %u has %zu ranges\n", entry.first, entry.second.size());
  //   for (const auto &range : entry.second) {
  //     fprintf(stderr, "DEBUG:   range [%u, %u)\n", range.first, range.second);
  //   }
  // }

  // Replace null bytes within string ranges (tracked in string_ranges_)
  for (auto &sol : solutions) {
    if (sol.op == solution_op_t::SET && sol.val == 0x00) {
      auto it = string_ranges_.find(sol.id);
      if (it != string_ranges_.end()) {
        for (const auto &range : it->second) {
          // If this offset is within a string range (but not at the end), replace null
          if (sol.offset >= range.first && sol.offset < range.second) {
            // fprintf(stderr, "DEBUG: replacing null at offset %u (in range [%u,%u))\n",
            //         sol.offset, range.first, range.second);
            sol.val = 'A';  // Replace null with 'A'
            break;
          }
        }
      }
    }
  }

  // fprintf(stderr, "DEBUG generate_solution: finished with %zu solutions\n", solutions.size());
}

// Build Z3 string from a content label (Load or Concat of bytes)
// Converts byte bitvectors to strings using Z3_mk_string_from_code
z3::expr Z3AstParser::build_string_from_label(dfsan_label content_label, input_dep_set_t &deps) {
  if (content_label < CONST_OFFSET) {
    return context_.string_val("");  // No tainted content
  }

  dfsan_label_info *info = get_label_info(content_label);

  // Handle Load: multi-byte load from input
  if (info->op == __dfsan::Load) {
    uint32_t offset = get_label_info(info->l1)->op1.i;
    uint32_t input = get_label_info(info->l1)->op2.i;
    uint32_t len = info->l2;  // number of bytes loaded

    // Track string range for null-byte post-processing
    string_ranges_[input].emplace_back(offset, offset + len);

    // Build string by concatenating str.from_code for each byte
    z3::expr result = context_.string_val("");
    for (uint32_t i = 0; i < len; i++) {
      z3::expr byte = get_byte_expr(input, offset + i, deps);
      z3::expr code = z3::bv2int(byte, false);
      z3::expr char_str(context_, Z3_mk_string_from_code(context_, code));
      result = z3::concat(result, char_str);
    }
    return result;
  }

  // Handle Concat: concatenation of byte expressions
  if (info->op == __dfsan::Concat) {
    z3::expr left = build_string_from_label(info->l1, deps);
    z3::expr right = build_string_from_label(info->l2, deps);
    return z3::concat(left, right);
  }

  // Handle single input byte (op == 0)
  if (info->op == 0) {
    uint32_t offset = info->op1.i;
    uint32_t input = info->op2.i;

    // Track string range for null-byte post-processing (single byte)
    string_ranges_[input].emplace_back(offset, offset + 1);

    z3::expr byte = get_byte_expr(input, offset, deps);
    z3::expr code = z3::bv2int(byte, false);
    return z3::expr(context_, Z3_mk_string_from_code(context_, code));
  }

  // Fallback: try to serialize the label and convert to string
  z3::expr byte_expr = get_cached_expr(content_label, deps);
  if (byte_expr.is_bv() && byte_expr.get_sort().bv_size() == 8) {
    z3::expr code = z3::bv2int(byte_expr, false);
    return z3::expr(context_, Z3_mk_string_from_code(context_, code));
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
