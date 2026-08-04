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
  // out_buf belongs to the caller and out_size is the length written, which is
  // not necessarily in_size: an answer may be shorter than the input (a strlen
  // satisfied by deleting bytes) or longer (inserting them, or an atoi answered
  // with more digits).  Same shape as AFL++'s custom-mutator afl_custom_fuzz,
  // which is what driver/aflpp/symsan.cpp forwards this to -- whoever owns the
  // buffer sizes it for a grown answer.
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
  // JIT every constraint in @p task that does not already carry a compiled
  // function, consulting (and filling) the AST-keyed function cache.  solve()
  // does this before searching; it is exposed so a driver that only wants to
  // exercise the cache -- driver/rgdreplay.cpp -- can stop here rather than
  // paying for a gradient-descent run it will not look at.  Returns false if
  // codegen rejected a constraint, which fails the whole task.
  bool jit_constraints(std::shared_ptr<SearchTask> task);
  // timing accessors (microseconds), cumulative across solve() calls:
  //   codegen  = AST -> LLVM IR (addFunction)
  //   jit      = LLVM IR -> native code (performJit)
  //   solving  = gradient-descent search (gd_entry)
  uint64_t get_codegen_time() const { return process_time.load(); }
  uint64_t get_jit_time() const { return jit_time.load(); }
  uint64_t get_solving_time() const { return solving_time.load(); }
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
  // bits for the FP op kinds that input-to-state cannot invert (FRem, FNeg, and
  // all FP casts and intrinsics/libcalls).  A constraint touching any of these
  // is rejected and falls back to z3.  A "direct" FCmp (input bytes -> FCmp
  // against a constant) sets no bit here and is handled by solve_fcmp.
  std::bitset<rgd::LastOp> fp_ops_mask;
  // bits for the invertible FP binops (FAdd/FSub/FMul/FDiv, plus FpPow) that
  // solve_fcmp can reverse against a constant operand (x + C <cmp> K -> write
  // K-C into input).  These are deliberately NOT in fp_ops_mask so such a
  // constraint reaches solve_fcmp instead of being rejected.
  std::bitset<rgd::LastOp> fp_arith_mask;
  // bits for the invertible unary FP transcendentals (exp/exp2/log/log2/log10/
  // log1p) that solve_fcmp reverses via the numeric libm inverse (log for exp,
  // ...) and verifies.  Also kept out of fp_ops_mask so they reach solve_fcmp.
  std::bitset<rgd::LastOp> fp_trans_mask;
  // bits for every string-theory kind.  Unlike jigsaw and the two z3 backends,
  // which reject an unknown kind through a default: case while walking the
  // tree, i2s works off the *enclosing* comparison's traced operand values and
  // its i2s_candidates -- so it can emit a byte assignment without ever
  // visiting the string subtree, and silence here would be an unsound SAT
  // rather than a decline.  Nothing solves these yet; see the string kinds in
  // include/ast.h.
  std::bitset<rgd::LastOp> string_op_mask;

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
  // x86_fp80, kept apart from solve_fcmp rather than folded into it.  The
  // instrumentation admits fp80 for comparisons only, so there is no arith or
  // transcendental node to invert and none of that machinery applies; and every
  // value here is a `long double` rather than a uint64 bit pattern, which is
  // what makes the format tractable at all.  See the header comment on
  // fp80_decode in i2s-solver.cpp.
  solver_result_t solve_fcmp80(std::shared_ptr<const Constraint> const& c,
                               std::unique_ptr<ConsMeta> const& cm,
                               uint32_t comparison,
                               const uint8_t *in_buf, size_t in_size,
                               uint8_t *out_buf, size_t &out_size);
  solver_result_t solve_memcmp(std::shared_ptr<const Constraint> const& c,
                               std::unique_ptr<ConsMeta> const& cm,
                               const uint8_t *in_buf, size_t in_size,
                               uint8_t *out_buf, size_t &out_size);
  // AST-guided fallbacks, tried only where the value-based matching above has
  // already given up.  They walk the constraint's AST instead of looking for
  // the compared value in the input, which is the only way to reach a table
  // lookup (whose output never appears in the input) or nested arithmetic with
  // more than one operation.  Every candidate they produce is verified by
  // re-evaluating the constraint before it is returned.
  solver_result_t solve_ast(std::shared_ptr<const Constraint> const& c,
                            uint32_t comparison,
                            const uint8_t *in_buf, size_t in_size,
                            uint8_t *out_buf, size_t &out_size);
  solver_result_t solve_memcmp_ast(std::shared_ptr<const Constraint> const& c,
                                   const uint8_t *in_buf, size_t in_size,
                                   uint8_t *out_buf, size_t &out_size);
  // The only path allowed to touch a constraint that string_op_mask matched.
  // It works entirely off the AST -- the string content is in there, byte by
  // byte -- and takes no ConsMeta: i2s_candidates records where a *compared
  // value* appears in the input, and the value compared here is a match
  // position or a length, which is not in the input at all.  Every answer is
  // checked by re-running the string operation over the rewritten bytes, so a
  // shape this does not really understand declines instead of guessing.
  solver_result_t solve_string(std::shared_ptr<const Constraint> const& c,
                               uint32_t comparison,
                               const uint8_t *in_buf, size_t in_size,
                               uint8_t *out_buf, size_t &out_size);
};

}; // namespace rgd
