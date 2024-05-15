#pragma once

#include "parse.h"

#include "task.h"
#include "union_find.h"

#include "boost/dynamic_bitset.hpp"

namespace rgd {

class RGDAstParser : public symsan::ASTParser<SearchTask> {
public:
  RGDAstParser() = delete;
  RGDAstParser(void *base, size_t size, bool solve_nested = false, size_t max_ast_size = 200)
    : symsan::ASTParser<SearchTask>(base, size),
      solve_nested_(solve_nested), max_ast_size_(max_ast_size) {}
  ~RGDAstParser() {}

  int restart(std::vector<symsan::input_t> &inputs) override;
  int parse_cond(dfsan_label label, bool result, bool add_nested,
                 std::vector<uint64_t> &tasks) override;
  int parse_gep(dfsan_label ptr_label, uptr ptr,
                dfsan_label index_label, int64_t index,
                uint64_t num_elems, uint64_t elem_size,
                int64_t current_offset,
                std::vector<uint64_t> &tasks) override;

  int add_constraints(dfsan_label label, uint64_t result) override;

protected:
  const bool solve_nested_;
  const size_t max_ast_size_;

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
  std::vector<uint8_t> nested_cmp_cache; // label -> nested comparison
  std::unordered_map<dfsan_label, uint8_t> concretize_node; // label -> concretize node

  // dependencies tracking
  size_t input_size_; // record the whole input size
  using input_dep_t = boost::dynamic_bitset<>;
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
  void to_dnf(const rgd::AstNode *node, formula_t &formula);
  [[nodiscard]] task_t construct_task(const clause_t &clause);
  [[nodiscard]] constraint_t parse_constraint(dfsan_label label);
  [[nodiscard]] bool do_uta_rel(dfsan_label label, rgd::AstNode *ret,
                                constraint_t constraint,
                                std::unordered_set<dfsan_label> &visited);
  uint32_t map_arg(uint32_t input_id, uint32_t offset, uint32_t length,
                   constraint_t constraint);

  bool save_constraint(expr_t expr, bool result);
};

}; // namespace rgd
