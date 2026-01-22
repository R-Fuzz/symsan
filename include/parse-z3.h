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

  int restart(std::vector<input_t> &inputs) override;
  int parse_cond(dfsan_label label, bool result, bool add_nested,
                 std::vector<uint64_t> &tasks) override;
  int parse_gep(dfsan_label ptr_label, uptr ptr,
                dfsan_label index_label, int64_t index,
                uint64_t num_elems, uint64_t elem_size,
                int64_t current_offset, bool enum_index,
                std::vector<uint64_t> &tasks) override;

  int add_constraints(dfsan_label label, uint64_t result) override;

protected:
  z3::context &context_;
  const char* input_name_format;
  const char* atoi_name_format;
  const char* strlen_name_format;

  // String range entry with cached str- expr for linking constraints
  struct string_range_t {
    uint32_t start;
    uint32_t end;
    z3::expr str_expr;  // cached str-X-Y-Z expr (z3::expr handles refcount)

    string_range_t(uint32_t s, uint32_t e, z3::expr expr)
        : start(s), end(e), str_expr(expr) {}
  };

  // Transparent comparator for O(log n) lookup with just uint32_t
  struct string_range_cmp {
    using is_transparent = void;  // Enable heterogeneous lookup

    bool operator()(const string_range_t &a, const string_range_t &b) const {
      return a.start < b.start;
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
  // Original input cache
  std::vector<input_t> inputs_cache_;

  // fsize flag
  bool has_fsize;

  // input deps
  using input_dep_set_t = std::unordered_set<offset_t, offset_hash>;

  // caches
  std::vector<uint32_t> tsize_cache_;
  std::vector<input_dep_set_t> deps_cache_;
  std::vector<Z3_ast> expr_cache_;
  std::vector<uint64_t> value_cache_;
  static const size_t SIZE_INCREMENT = 2048;

  // Label-level tracking: what type of variables does each expression involve?
  std::vector<bool> is_label_bv_;   // involves bitvec variables (input-X-Y)
  std::vector<bool> is_label_seq_;  // involves string/seq variables (str-X-Y-Z)

  // dependencies
  struct expr_hash {
    std::size_t operator()(const z3::expr &expr) const {
      return expr.hash();
    }
  };
  struct expr_equal {
    bool operator()(const z3::expr &lhs, const z3::expr &rhs) const {
      return lhs.id() == rhs.id();
    }
  };
  using expr_set_t = std::unordered_set<z3::expr, expr_hash, expr_equal>;
  struct branch_dependency_t {
    expr_set_t expr_deps;
    input_dep_set_t input_deps;
    bool used_in_bv = false;   // any saved constraint involves bitvec
    bool used_in_seq = false;  // any saved constraint involves string/seq
    z3::expr input_expr;  // cached input-X-Y expr (z3::expr handles refcount)

    // Only constructor: must have input_expr (linear scan guarantees this)
    branch_dependency_t(z3::expr e) : input_expr(e) {}
  };
  using branch_dep_t = std::unique_ptr<struct branch_dependency_t>;
  using offset_dep_t = std::vector<branch_dep_t>;
  std::vector<offset_dep_t> branch_deps_;

  inline struct branch_dependency_t* get_branch_dep(offset_t off) {
    auto &offset_deps = branch_deps_.at(off.first);
    return offset_deps.at(off.second).get();
  }

  inline void set_branch_dep(offset_t off, branch_dep_t dep) {
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
      throw z3::exception("cannot find cached expression");
    }
    deps.insert(deps_cache_[label].begin(), deps_cache_[label].end());
    return z3::expr(context_, ast);
  }

  inline void dump_value_cache(dfsan_label label);

  z3::expr read_concrete(dfsan_label label, uint16_t size);
  z3::expr serialize(dfsan_label label, input_dep_set_t &deps);
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
    uint32_t offset;   // position in file
    union {
      uint8_t val;     // for SET: the byte value
      uint32_t len;    // for DELETE: number of bytes to delete
    };
    std::vector<uint8_t> data; // for INSERT: bytes to insert

    // Constructors for convenience
    // SET: set single byte at offset
    solution_val(uint32_t id, uint32_t offset, uint8_t val)
        : op(solution_op_t::SET), id(id), offset(offset), val(val) {}

    // INSERT: insert bytes at offset
    solution_val(uint32_t id, uint32_t offset, std::vector<uint8_t> data)
        : op(solution_op_t::INSERT), id(id), offset(offset), data(std::move(data)) {}

    // DELETE: delete len bytes at offset
    solution_val(solution_op_t op, uint32_t id, uint32_t offset, uint32_t len)
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