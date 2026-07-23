#pragma once

#include "task.h"

#include <stdint.h>
#include <z3++.h>

#include <vector>
#include <unordered_map>
#include <utility>
#include <memory>
#include <atomic>

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
  virtual solver_result_t solve(std::shared_ptr<SearchTask> task,
                                const uint8_t *in_buf, size_t in_size,
                                uint8_t *out_buf, size_t &out_size) = 0;
  virtual void print_stats(int fd) = 0;
};

class Z3Solver : public Solver {
public:
  Z3Solver();
  solver_result_t solve(std::shared_ptr<SearchTask> task,
                        const uint8_t *in_buf, size_t in_size,
                        uint8_t *out_buf, size_t &out_size) override;
  void print_stats(int fd) override {} ;
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
  // auxiliary range constraints emitted while serializing partial FP casts
  // (fpa.to_sbv/to_ubv); collected during serialize() and added before check().
  std::vector<z3::expr> aux_constraints_;
};

class JITSolver : public Solver {
public:
  JITSolver();
  solver_result_t solve(std::shared_ptr<SearchTask> task,
                        const uint8_t *in_buf, size_t in_size,
                        uint8_t *out_buf, size_t &out_size) override;
  void print_stats(int fd) override;
private:
  std::atomic_ulong uuid;
  std::atomic_ulong cache_hits;
  std::atomic_ulong cache_misses;
  std::atomic_ulong num_timeout;
  std::atomic_ulong num_solved;
  std::atomic_ulong process_time;
  std::atomic_ulong jit_time;
  std::atomic_ulong solving_time;
};

class I2SSolver : public Solver {
public:
  I2SSolver();
  solver_result_t solve(std::shared_ptr<SearchTask> task,
                        const uint8_t *in_buf, size_t in_size,
                        uint8_t *out_buf, size_t &out_size) override;
  void print_stats(int fd) override {};
private:
  uint64_t matches;
  uint64_t mismatches;
  std::bitset<rgd::LastOp> binop_mask;
  // bits for the FP op kinds that input-to-state cannot invert (all FP
  // arithmetic, casts, and intrinsics/libcalls -- i.e. every FP op EXCEPT the
  // top-level FP comparisons).  A constraint touching any of these is rejected
  // and falls back to z3.  A "direct" FCmp (input bytes -> FCmp against a
  // constant) sets no bit here and is handled by solve_fcmp.
  std::bitset<rgd::LastOp> fp_ops_mask;

  solver_result_t solve_icmp(std::shared_ptr<const Constraint> const& c,
                             std::unique_ptr<ConsMeta> const& cm,
                             uint32_t comparison,
                             const uint8_t *in_buf, size_t in_size,
                             uint8_t *out_buf, size_t &out_size);
  solver_result_t solve_fcmp(std::shared_ptr<const Constraint> const& c,
                             std::unique_ptr<ConsMeta> const& cm,
                             uint32_t comparison,
                             const uint8_t *in_buf, size_t in_size,
                             uint8_t *out_buf, size_t &out_size);
  solver_result_t solve_memcmp(std::shared_ptr<const Constraint> const& c,
                               std::unique_ptr<ConsMeta> const& cm,
                               const uint8_t *in_buf, size_t in_size,
                               uint8_t *out_buf, size_t &out_size);
};

}; // namespace rgd
