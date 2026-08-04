#pragma once

#include "parse.h"

#include <z3++.h>
#include <set>

namespace symsan {

using z3_task_t = std::vector<z3::expr>;
class Z3AstParser : public ASTParser<z3_task_t> {
public:
  Z3AstParser() = delete;
  Z3AstParser(void *base, size_t size, z3::context &context);
  ~Z3AstParser() {
    for (Z3_ast ast : expr_cache_) {
      if (ast != nullptr) {
        Z3_dec_ref(context_, ast); // decrement reference count
      }
    }
  }

  int restart(std::vector<input_t> &inputs, bool copy_input = false) override;
  /// @brief Update input cache without clearing deps
  int update_input(std::vector<input_t> &inputs, bool copy_input = false);
  int parse_cond(dfsan_label label, bool result, bool add_nested,
                 std::vector<uint64_t> &tasks) override;
  int parse_gep(dfsan_label ptr_label, uptr ptr,
                dfsan_label index_label, int64_t index,
                uint64_t num_elems, uint64_t elem_size,
                int64_t current_offset, bool enum_index,
                std::vector<uint64_t> &tasks) override;

  int add_constraints(dfsan_label label, uint64_t result) override;
  int record_minimize(dfsan_label label, bool allow_zero = true) override;

protected:
  z3::context &context_;
  const char* input_name_format;
  const char* atoi_name_format;
  const char* strlen_name_format;
  const char* str_name_format;
  const char* int_name_format;

  // Auxiliary constraints generated during serialization (e.g., Int variable bounds)
  std::vector<z3::expr> aux_constraints_;

  // Expressions to minimize during solving (e.g., malloc sizes)
  // Each entry: (expr to minimize, set of input offsets it depends on)
  struct minimize_hint_t {
    z3::expr expr;
    bool allow_zero;  // whether to allow zero as a valid solution
    std::unordered_set<offset_t, offset_hash> deps;
  };
  std::vector<minimize_hint_t> minimize_hints_;

  // String range entry with cached str- expr for linking constraints
  struct string_range_t {
    uint32_t start;
    uint32_t end;
    z3::expr str_expr;  // cached str-X-Y-Z expr (z3::expr handles refcount)

    string_range_t(uint32_t s, uint32_t e, z3::expr expr)
        : start(s), end(e), str_expr(expr) {}
  };

  // Transparent comparator: order by (start, end) so ranges with the same
  // start but different lengths coexist.  Heterogeneous lookup by uint32_t
  // still works for upper_bound (compares against start only).
  struct string_range_cmp {
    using is_transparent = void;  // Enable heterogeneous lookup

    bool operator()(const string_range_t &a, const string_range_t &b) const {
      if (a.start != b.start) return a.start < b.start;
      return a.end < b.end;
    }
    bool operator()(const string_range_t &a, uint32_t offset) const {
      return a.start < offset;
    }
    bool operator()(uint32_t offset, const string_range_t &b) const {
      return offset < b.start;
    }
  };

  // String ranges for null-byte post-processing and linking constraints
  // vector indexed by input_id, each contains a sorted set of ranges
  std::vector<std::set<string_range_t, string_range_cmp>> string_ranges_;

  // String info cache: label -> (input_id, offset, length)
  struct string_info_t {
    uint32_t input_id;
    uint32_t offset;
    uint32_t length;
  };
  std::unordered_map<dfsan_label, string_info_t> string_info_cache_;

private:
  // Original input cache (stores pointers to input data)
  std::vector<input_t> inputs_cache_;

  // Copied input data (when copy_input=true, owns the data)
  std::vector<std::vector<uint8_t>> inputs_copy_;

  // fsize flag
  bool has_fsize;

  // input deps
  using input_dep_set_t = std::unordered_set<offset_t, offset_hash>;

  // caches
  std::vector<uint32_t> tsize_cache_;
  std::vector<input_dep_set_t> deps_cache_;
  std::vector<Z3_ast> expr_cache_;
  std::vector<uint64_t> value_cache_;
  // parallel to value_cache_: this label's concrete value did not fit in 64
  // bits (or descends from one that did not), so the cached value is only a low
  // half and every FILTER_WRONG_AST consistency check must skip it
  std::vector<uint8_t> value_unknown_;
  // true when value_cache_[l] is only a low half and must not be checked
  bool value_is_unknown(uint32_t l) const {
    return l < value_unknown_.size() && value_unknown_[l];
  }
  static const size_t SIZE_INCREMENT = 2048;

  // Label-level tracking: what type of variables does each expression involve?
  std::vector<bool> is_label_bv_;   // involves bitvec variables (input-X-Y)
  std::vector<bool> is_label_seq_;  // involves string/seq variables (str-X-Y-Z)

  // dependencies
  //
  // Keyed on the z3 AST id, with the expr carried as the value.  This used to be
  // an unordered_set<z3::expr> hashing on expr.hash() and comparing on
  // lhs.id() == rhs.id(), which is the same identity -- but it re-fetched both
  // over the C API on every probe.  Each of those calls opens with a LOCK'd
  // exchange on z3's g_z3_log_enabled (the logging guard, paid whether or not
  // logging is on: it *is* the enabled check, see z3's z3_log_ctx), and
  // add_nested_constraints probes once per expr per input offset.  On the
  // 811-seed libpng corpus Z3_get_ast_hash/Z3_get_ast_id and the
  // Z3_get_error_code shadowing each of them were two thirds of the parser's
  // whole runtime.  The id is computed once, where the expr is saved.
  using expr_set_t = std::unordered_map<unsigned, z3::expr>;
  // Comparison info stored for Int mirroring of BV nested constraints
  struct cmp_info_t {
    dfsan_label l1;      // left operand label
    dfsan_label l2;      // right operand label
    uint16_t predicate;  // comparison predicate (e.g., bvsle)
    bool result;         // concrete result (true/false)
  };

  struct branch_dependency_t {
    expr_set_t expr_deps;
    input_dep_set_t input_deps;
    bool used_in_bv = false;   // any saved constraint involves bitvec
    bool used_in_seq = false;  // any saved constraint involves string/seq
    z3::expr input_expr;  // cached input-X-Y expr (z3::expr handles refcount)
    std::vector<cmp_info_t> cmp_deps;  // ICmp constraints for Int mirroring

    // Only constructor: must have input_expr (linear scan guarantees this)
    branch_dependency_t(z3::expr e) : input_expr(e) {}
  };

  // Cache of int-* variables: label -> Int z3 expr
  // Populated when int-* variables are created in convert_bv_to_int or fsubstr handler
  std::unordered_map<dfsan_label, z3::expr> int_var_cache_;
  using branch_dep_t = std::unique_ptr<struct branch_dependency_t>;
  using offset_dep_t = std::vector<branch_dep_t>;
  std::vector<offset_dep_t> branch_deps_;
  // Separate storage for negative offsets (container_of pattern).
  // Negative offset -N (encoded as uint32_t > INT32_MAX) maps to index N-1.
  std::vector<offset_dep_t> neg_branch_deps_;

  static inline bool is_negative_offset(uint32_t off) {
    return (int32_t)off < 0;
  }

  static inline uint32_t neg_index(uint32_t off) {
    return (uint32_t)(-(int32_t)off) - 1;
  }

  inline struct branch_dependency_t* get_branch_dep(offset_t off) {
    if (is_negative_offset(off.second)) {
      if (off.first >= neg_branch_deps_.size()) {
        return nullptr;
      }
      auto &deps = neg_branch_deps_.at(off.first);
      if (neg_index(off.second) >= deps.size()) {
        return nullptr;
      }
      return deps.at(neg_index(off.second)).get();
    }
    if (off.first >= branch_deps_.size()) {
      return nullptr;
    }
    auto &offset_deps = branch_deps_.at(off.first);
    if (off.second >= offset_deps.size()) {
      return nullptr;
    }
    return offset_deps.at(off.second).get();
  }

  inline void set_branch_dep(offset_t off, branch_dep_t dep) {
    if (is_negative_offset(off.second)) {
      if (off.first >= neg_branch_deps_.size())
        neg_branch_deps_.resize(off.first + 1);
      auto &deps = neg_branch_deps_[off.first];
      uint32_t idx = neg_index(off.second);
      if (idx >= deps.size())
        deps.resize(idx + 1);
      deps[idx] = std::move(dep);
      return;
    }
    auto &offset_deps = branch_deps_.at(off.first);
    if (off.second >= offset_deps.size()) {
      offset_deps.resize(off.second + 1);
    }
    offset_deps[off.second] = std::move(dep);
  }

  inline void cache_expr(dfsan_label label, z3::expr const &e) {
    if (label != expr_cache_.size()) {
      // fprintf(stderr, "expected label %zu, got %u\n",
      //         expr_cache_.size(), label);
      throw z3::exception("missing or adding too many expressions");
    }
    Z3_ast ast = e;
    Z3_inc_ref(context_, ast); // increment reference count
    expr_cache_.emplace_back(ast);
  }

  inline z3::expr get_cached_expr(dfsan_label label, input_dep_set_t &deps) {
    if (label >= expr_cache_.size()) {
      throw z3::exception("invalid label");
    }
    Z3_ast ast = expr_cache_[label];
    if (ast == nullptr) {
      // A label serialize() gave up on -- see poison_label -- or one that was
      // never filled.  Report the original cause where we have it: "cannot find
      // cached expression" is the symptom, and says nothing about which
      // construct the parser could not model.
      auto it = poison_reason_.find(label);
      if (it != poison_reason_.end()) {
        throw z3::exception(it->second.c_str());
      }
      // Alloca/Free carry concrete allocation bounds and nothing else, so
      // serialize() caches a null for them on purpose rather than failing.
      // Asking one for an expression means a condition compared the *pointer*
      // -- `if (p != NULL)` on a heap object is the common shape -- which is
      // not solvable and should not be, but it is a different thing from a
      // label the parser could not build, and it is not worth an entry in
      // poison_reason_ (one per allocation) to say so.
      dfsan_label_info *info = nullptr;
      try { info = this->get_label_info(label); } catch (...) {}
      if (info != nullptr &&
          (info->op == __dfsan::Alloca || info->op == __dfsan::Free)) {
        throw z3::exception("pointer compared against allocation bounds");
      }
      throw z3::exception("cannot find cached expression");
    }
    deps.insert(deps_cache_[label].begin(), deps_cache_[label].end());
    return z3::expr(context_, ast);
  }

  /// @brief Give up on one label without giving up on the rest of the trace
  ///
  /// serialize() is a linear fill: it resumes at expr_cache_.size() and walks
  /// forward, so a label that throws part-way through leaves the caches short,
  /// and every later call restarts on that same label and throws again.  One
  /// unmodelable label therefore used to cost the whole remainder of the trace
  /// -- measured on a libpng corpus seed, 9159 of the 9167 rejected branches
  /// were a single label re-hit, and the caches that do grow before the throw
  /// (deps_cache_, tsize_cache_) ended up 9159 entries ahead of the rest, so
  /// every subsequent deps_cache_[l] answered for a different label.
  ///
  /// Write a placeholder instead: a null expression, which get_cached_expr
  /// already treats as unusable, and a neutral entry in every parallel cache.
  /// Labels that depend on this one still fail -- correctly, the parser cannot
  /// model them either -- and labels that do not are unaffected.
  void poison_label(dfsan_label l, const char *reason);

  /// Why each poisoned label was abandoned, so that a dependent's failure can
  /// name the original cause rather than the missing entry.  Expected to stay
  /// small: it holds one entry per label the parser could not build, not per
  /// label.
  std::unordered_map<dfsan_label, std::string> poison_reason_;

  inline void dump_value_cache(dfsan_label label);

  z3::expr read_concrete(dfsan_label label, uint16_t size);
  z3::expr serialize(dfsan_label label, input_dep_set_t &deps);
  uint64_t serialize_input(dfsan_label label, uint32_t input, uint32_t offset,
                           uint32_t bytes, input_dep_set_t &input_deps);
  inline void collect_more_deps(input_dep_set_t &deps);
  inline void mark_expr_type(dfsan_label label, input_dep_set_t &inputs);
  inline size_t add_nested_constraints(input_dep_set_t &deps, z3_task_t *task);
  inline void save_constraint(z3::expr expr, input_dep_set_t &inputs);
  void construct_index_tasks(z3::expr &index, uint64_t curr,
                             uint64_t lb, uint64_t ub, uint64_t step,
                             z3_task_t &nested, std::vector<uint64_t> &tasks);

  // String theory helpers for strchr/strstr
  z3::expr build_string_from_label(dfsan_label content_label, input_dep_set_t &deps);
  z3::expr get_byte_expr(uint32_t input, uint32_t offset, input_dep_set_t &deps);
  bool label_contains_indexof(dfsan_label label);

  // Helper for linking bitvec and string constraints on shared offsets
  void add_string_bitvec_link(offset_t off, z3_task_t *task);

  // Register a string range and add linking constraints for overlapping ranges
  void register_string_range(uint32_t input, uint32_t start, uint32_t end,
                             z3::expr str_var);

  // Constrain a (UC) string-search haystack base pointer to be non-null. The
  // pointer label is carried in the high bits of a string op's op2. No-op for
  // concrete/bounds (Alloca/Free) pointers. Pulls the pointer bytes into deps.
  void add_haystack_ptr_nonnull(dfsan_label ptr_label, input_dep_set_t &deps);
};

class Z3ParserSolver : public Z3AstParser {
public:
  Z3ParserSolver() = delete;
  Z3ParserSolver(void *base, size_t size, z3::context &context)
      : Z3AstParser(base, size, context) {}
  ~Z3ParserSolver() {}

  // Solution operation types
  enum class solution_op_t : uint8_t {
    SET,     // Set byte at offset to val
    INSERT,  // Insert bytes at offset (shifts following bytes right)
    DELETE   // Delete len bytes starting at offset (shifts following bytes left)
  };

  struct solution_val {
    solution_op_t op;
    uint32_t id;       // input id
    int32_t offset;    // position in file (signed for container_of negative offsets)
    union {
      uint8_t val;     // for SET: the byte value
      uint32_t len;    // for DELETE: number of bytes to delete
    };
    std::vector<uint8_t> data; // for INSERT: bytes to insert

    // Constructors for convenience
    // SET: set single byte at offset
    solution_val(uint32_t id, int32_t offset, uint8_t val)
        : op(solution_op_t::SET), id(id), offset(offset), val(val) {}

    // INSERT: insert bytes at offset
    solution_val(uint32_t id, int32_t offset, std::vector<uint8_t> data)
        : op(solution_op_t::INSERT), id(id), offset(offset), data(std::move(data)) {}

    // DELETE: delete len bytes at offset
    solution_val(solution_op_t op, uint32_t id, int32_t offset, uint32_t len)
        : op(op), id(id), offset(offset), len(len) {}
  };

  enum solving_status {
    invalid_task = 1,
    opt_sat = 2,
    opt_unsat = 3,
    opt_timeout = 4,
    nested_sat = 5,
    opt_sat_nested_unsat = 6,
    opt_sat_nested_timeout = 7,
    unknown_error,
  };

  using solution_t = std::vector<struct solution_val>;
  solving_status solve_task(uint64_t task_id, unsigned timeout, solution_t &solutions);

  /// @brief Export task constraints to SMT2 format
  /// @param task_id the task to export
  /// @param fd file descriptor to write to
  /// @return 0 on success, -1 on failure
  int export_task_smt2(uint64_t task_id, int fd);

private:
  void generate_solution(z3::model &m, solution_t &solutions);

};

};