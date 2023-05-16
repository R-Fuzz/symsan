#pragma once

#include "task.h"

#include <stdint.h>
#include <z3++.h>

#include <vector>
#include <unordered_map>
#include <utility>
#include <memory>

namespace rgd {

enum solver_result_t {
  SOLVER_ERROR,
  SOLVER_SAT,
  SOLVER_UNSAT,
  SOLVER_TIMEOUT,
};

class Solver {
public:
  virtual ~Solver() {};
  virtual int stages() = 0;
  virtual solver_result_t solve(int stage, std::shared_ptr<SearchTask> task,
                                const uint8_t *in_buf, size_t in_size,
                                uint8_t *out_buf, size_t &out_size) = 0;
};

class Z3Solver : public Solver {
public:
  Z3Solver();
  int stages() override;
  solver_result_t solve(int stage, std::shared_ptr<SearchTask> task,
                        const uint8_t *in_buf, size_t in_size,
                        uint8_t *out_buf, size_t &out_size) override;
private:
  z3::expr serialize_rel(uint32_t comparison,
                         const AstNode* node,
                         const std::vector<std::pair<bool, uint64_t>> &input_args,
                         std::unordered_map<uint32_t,z3::expr> &expr_cache);

  z3::expr serialize(const AstNode* node,
                     const std::vector<std::pair<bool, uint64_t>> &input_args,
                     std::unordered_map<uint32_t,z3::expr> &expr_cache);

  z3::context &context_;
  z3::solver solver_;
};

class JITSolver : public Solver {
};


}; // namespace rgd