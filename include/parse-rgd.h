#pragma once

#include "parse.h"

#include "task.h"
#include "union_find.h"

#include "boost/dynamic_bitset.hpp"

namespace rgd {

class RGDAstParser : public symsan::ASTParser<SearchTask> {
public:
  RGDAstParser() = delete;
  /// @param strict_clauses  what to do when one conjunct of a DNF clause will
  ///   not parse.  Default (false) keeps the rest of the clause and builds a
  ///   task from it: that task is *weaker* than the clause, so a solution to it
  ///   need not flip the branch, which for hybrid fuzzing costs one execution
  ///   and buys a chance at coverage.  True drops the whole clause instead,
  ///   which is exact -- the surviving disjuncts still flip the branch -- and is
  ///   what a consumer that must trust a task wants.  See construct_task().
  RGDAstParser(void *base, size_t size, bool solve_nested = false, size_t max_ast_size = 200,
               bool strict_clauses = false)
    : symsan::ASTParser<SearchTask>(base, size),
      solve_nested_(solve_nested), max_ast_size_(max_ast_size),
      strict_clauses_(strict_clauses) {}
  ~RGDAstParser() {}

  /// Clauses handed out with a conjunct missing (lenient mode only).  Counted
  /// rather than only warned because stderr is /dev/null in a campaign, and a
  /// task that cannot flip its branch is worth knowing the rate of.
  uint64_t weakened_clauses() const { return weakened_clauses_; }

  int restart(std::vector<symsan::input_t> &inputs, bool copy_input = false) override;
  int parse_cond(dfsan_label label, bool result, bool add_nested,
                 std::vector<uint64_t> &tasks) override;
  int parse_gep(dfsan_label ptr_label, uptr ptr,
                dfsan_label index_label, int64_t index,
                uint64_t num_elems, uint64_t elem_size,
                int64_t current_offset, bool enum_index,
                std::vector<uint64_t> &tasks) override;

  int add_constraints(dfsan_label label, uint64_t result) override;

  // --- dependency queries ----------------------------------------------------
  // The parser already computes which input offsets each label reads, and which
  // offsets are coupled by data flow, as a side effect of parsing.  These expose
  // that to a caller that wants to know which bytes are still worth mutating,
  // without making it reach into the caches.

  /// Set of input offsets, flattened across all inputs -- bit i is the offset
  /// input_to_dep_idx() maps <input_id, offset> to.
  using input_dep_t = boost::dynamic_bitset<>;

  /// OR the input offsets @p label depends on into @p acc, growing @p acc to the
  /// traced input's size if needed.
  ///
  /// Cheap enough to call for every branch, solved or not: scan_labels() fills
  /// the cache linearly up to @p label, so a label the cache already reaches
  /// costs nothing and the total across a trace is one pass over the labels.
  ///
  /// @return false if @p label is out of range or the union table held an
  ///         invalid entry, in which case @p acc is untouched
  [[nodiscard]] bool note_deps(dfsan_label label, input_dep_t &acc);

  /// The data-flow group @p offset belongs to, named by a representative offset.
  /// Offsets no task has coupled to anything are their own group.
  size_t dep_group(size_t offset) { return data_flow_deps.find(offset); }

  /// Every offset in @p offset's data-flow group, itself included.
  /// @return the group size, or UnionFind::INVALID if @p offset is out of range
  size_t dep_members(size_t offset, std::unordered_set<size_t> &out) {
    return data_flow_deps.get_set(offset, out);
  }

protected:
  const bool solve_nested_;
  const size_t max_ast_size_;
  const bool strict_clauses_;
  uint64_t weakened_clauses_ = 0;

private:
  enum ast_node_t {
    NONE_CMP_NODE = 0,
    CMP_NODE = 1,
    INVALID_NODE = 2,
    CONCRETIZE_NODE = 4,
  };

  using expr_t = std::shared_ptr<rgd::AstNode>;
  using constraint_t = std::shared_ptr<rgd::Constraint>;
  using clause_t = std::vector<const rgd::AstNode*>;
  using formula_t = std::vector<clause_t>;

  // caches
  std::vector<symsan::input_t> inputs_cache; // input cache
  std::unordered_map<dfsan_label, expr_t> root_expr_cache; // label -> root expr
  std::unordered_map<dfsan_label, constraint_t> constraint_cache; // label -> constraint
  std::vector<uint32_t> ast_size_cache; // label -> size of the AST
  std::vector<uint32_t> arg_size_cache; // label -> upper bound on input_args slots
  std::vector<uint8_t> nested_cmp_cache; // label -> nested comparison
  std::unordered_map<dfsan_label, uint8_t> concretize_node; // label -> concretize node

  // dependencies tracking
  size_t input_size_; // record the whole input size
  std::vector<input_dep_t> branch_to_inputs; // label -> flattened input dependencies
  // <input_id, offset> will be flattened to bit \sigma_{i=0}^{input_id}{size_of(input_i)} + offset
  inline size_t input_to_dep_idx(uint32_t input_id, uint32_t offset) {
    size_t idx = 0;
    for (uint32_t i = 0; i < input_id; ++i) {
      idx += inputs_cache[i].second;
    }
    return idx + offset;
  }
  UnionFind data_flow_deps;
  std::vector<std::vector<expr_t> > input_to_branches;

  [[nodiscard]] expr_t get_root_expr(dfsan_label label);
  [[nodiscard]] bool scan_labels(dfsan_label label);
  [[nodiscard]] int find_roots(dfsan_label label, AstNode *ret,
                               std::unordered_set<dfsan_label> &subroots);
  inline dfsan_label strip_zext(dfsan_label label);
  [[nodiscard]] int to_nnf(bool expected_r, rgd::AstNode *node);
  [[nodiscard]] int expand_bool_xor(bool expected_r, rgd::AstNode *node);
  void to_dnf(const rgd::AstNode *node, formula_t &formula);
  [[nodiscard]] task_t construct_task(const clause_t &clause);
  [[nodiscard]] constraint_t parse_constraint(dfsan_label label);
  [[nodiscard]] bool do_uta_rel(dfsan_label label, rgd::AstNode *ret,
                                constraint_t constraint,
                                std::unordered_set<dfsan_label> &visited);
  uint32_t map_arg(uint32_t input_id, uint32_t offset, uint32_t length,
                   constraint_t constraint);
  [[nodiscard]] bool pack_const_bytes(const uint8_t *content, uint32_t size,
                                      rgd::AstNode *node, constraint_t constraint);
  [[nodiscard]] bool add_str_operand(dfsan_label label, dfsan_label operand,
                                     uint32_t content_size, rgd::AstNode *child,
                                     constraint_t constraint,
                                     std::unordered_set<dfsan_label> &visited);
  [[nodiscard]] bool do_uta_str(dfsan_label label, dfsan_label_info *info,
                                uint16_t kind, rgd::AstNode *ret,
                                constraint_t constraint,
                                std::unordered_set<dfsan_label> &visited);

  bool save_constraint(expr_t expr, bool result);
  inline void add_nested_constraint(task_t task, const clause_t &nested_caluse);
};

}; // namespace rgd
