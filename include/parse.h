#pragma once

//#include "task.h"

#include "dfsan/dfsan.h"

#include <stdint.h>
#include <string.h>

#include <z3++.h>

#include <memory>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace symsan {

using input_t = std::pair<uint8_t*, size_t>;

template <class T>
class ASTParser {
public:
  ASTParser() = delete;
  ASTParser(void *base, size_t size)
    : base_(static_cast<dfsan_label_info*>(base)),
      size_(size / sizeof(dfsan_label_info)),
      prev_task_id_(0) {}
  virtual ~ASTParser() {}

  virtual int restart(std::vector<input_t> &inputs) = 0;
  /// @brief Parse a conditional branch
  /// @param label the label of the condition
  /// @param result the result of the condition
  /// @param add_nested whether to add nested constraints
  /// @param tasks the tasks to be added
  /// @return 0 on success, -1 on failure
  virtual int parse_cond(dfsan_label label, bool result, bool add_nested,
                         std::vector<uint64_t> &tasks) = 0;
  /// @brief Parse a GEP instruction with symbolic index
  /// @param ptr_label symbol label of the pointer (e.g., bounds info)
  /// @param ptr actual pointer value
  /// @param index_label symbolic label of the index
  /// @param index actual index value
  /// @param num_elems number of elements if ptr is an array
  /// @param elem_size size of each element
  /// @param current_offset current offset from previous GEP
  /// @param tasks tasks to be added
  /// @return 0 on success, -1 on failure
  virtual int parse_gep(dfsan_label ptr_label, uptr ptr,
                        dfsan_label index_label, int64_t index,
                        uint64_t num_elems, uint64_t elem_size,
                        int64_t current_offset,
                        std::vector<uint64_t> &tasks) = 0;

  virtual int record_memcmp(dfsan_label label, uint8_t* buf, size_t size) {
    auto content = std::make_unique<uint8_t[]>(size);
    memcpy(content.get(), buf, size);
    memcmp_cache_.insert({label, std::move(content)});
    return 0;
  };

  // use unique_ptr to auto-free task
  virtual std::unique_ptr<T> retrieve_task(uint64_t id) {
    auto it = tasks_.find(id);
    if (it == tasks_.end()) {
      return nullptr;
    }
    auto tmp = std::move(it->second);
    tasks_.erase(it);
    return tmp;
  }

protected:
  inline dfsan_label_info* get_label_info(dfsan_label label) {
    if (label >= size_) {
      throw std::out_of_range("label too large " + std::to_string(label));
    }
    return &base_[label];
  }

  dfsan_label_info *base_;
  size_t size_;
  uint64_t prev_task_id_;
  std::unordered_map<uint64_t, std::unique_ptr<T>> tasks_;
  std::unordered_map<dfsan_label, std::unique_ptr<uint8_t[]>> memcmp_cache_;
};


using z3_task_t = std::vector<z3::expr>;
class Z3AstParser : public ASTParser<z3_task_t> {
public:
  Z3AstParser() = delete;
  Z3AstParser(void *base, size_t size, z3::context &context);
  ~Z3AstParser() {}

  int restart(std::vector<input_t> &inputs) override;
  int parse_cond(dfsan_label label, bool result, bool add_nested,
                 std::vector<uint64_t> &tasks) override;
  int parse_gep(dfsan_label ptr_label, uptr ptr,
                dfsan_label index_label, int64_t index,
                uint64_t num_elems, uint64_t elem_size,
                int64_t current_offset,
                std::vector<uint64_t> &tasks) override;

  /// @return 0 on success, -1 on failure
  int add_constraints(dfsan_label label, uint64_t result);

private:
  z3::context &context_;

  // input deps
  using offset_t = std::pair<uint32_t, uint32_t>;
  struct offset_hash {
    std::size_t operator()(const offset_t &off) const {
      uint64_t key = off.first;
      key <<= 32;
      key |= off.second;
      return std::hash<uint64_t>{}(key);
    }
  };
  using input_dep_set_t = std::unordered_set<offset_t, offset_hash>;

  // caches
  std::unordered_map<dfsan_label, uint32_t> tsize_cache_;
  std::unordered_map<dfsan_label, input_dep_set_t> deps_cache_;
  std::unordered_map<dfsan_label, z3::expr> expr_cache_;

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
  using branch_dep_t = struct {
    expr_set_t expr_deps;
    input_dep_set_t input_deps;
  };
  using offset_dep_t = std::vector<std::unique_ptr<branch_dep_t>>;
  std::vector<offset_dep_t> branch_deps_;

  inline branch_dep_t* get_branch_dep(offset_t off) {
    auto &offset_deps = branch_deps_.at(off.first);
    return offset_deps.at(off.second).get();
  }

  inline void set_branch_dep(offset_t off, std::unique_ptr<branch_dep_t> dep) {
    auto &offset_deps = branch_deps_.at(off.first);
    if (off.second >= offset_deps.size()) {
      offset_deps.resize(off.second + 1);
    }
    offset_deps[off.second] = std::move(dep);
  }

  inline z3::expr cache_expr(dfsan_label label, z3::expr const &e, input_dep_set_t &deps) {
    expr_cache_.insert({label, e});
    deps_cache_.insert({label, deps});
    return e;
  }

  z3::expr read_concrete(dfsan_label label, uint16_t size);
  z3::expr serialize(dfsan_label label, input_dep_set_t &deps);
  inline void collect_more_deps(input_dep_set_t &deps);
  inline size_t add_nested_constraints(input_dep_set_t &deps, z3_task_t *task);
  inline void save_constraint(z3::expr expr, input_dep_set_t &inputs);
  inline uint64_t save_task(std::unique_ptr<z3_task_t> task) {
    uint64_t tid = prev_task_id_++;
    tasks_.insert({tid, std::move(task)});
    return tid;
  }
  void construct_index_tasks(z3::expr &index, uint64_t curr,
                             uint64_t lb, uint64_t ub, uint64_t step,
                             z3_task_t &nested, std::vector<uint64_t> &tasks);
};


// class RGDAstParser : public ASTParser<rgd::SearchTask>;

}; // namespace symsan