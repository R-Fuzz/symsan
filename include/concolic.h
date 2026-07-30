/*
  rgd::ConcolicSession -- the RGD concolic-execution driver policy.

  This is the logic that used to live inline in driver/aflpp/symsan.cpp: take an
  input, trace it, turn the branches into solving tasks, and walk the solver
  ladder (i2s -> jigsaw -> z3) to produce mutated inputs.  Nothing here is
  specific to AFL++, so a LibAFL stage or a Python driver gets the same
  behaviour by construction rather than by copying it.

  The division of labour is: this class owns *mechanism* -- tracing, parsing,
  task ordering, solving -- while the front-end owns *policy* about which inputs
  are worth tracing and whether a produced solution turned out to be
  interesting.  The front-end tells us the latter through report_result().

  (c) 2023 - 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#pragma once

#include "session.h"

#include "branch_map.h"
#include "cov.h"
#include "parse-rgd.h"
#include "solver.h"
#include "task.h"
#include "task_mgr.h"

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace rgd {

/// Everything a ConcolicSession needs to know up front.  from_env() fills this
/// in from the SYMSAN_* environment variables, so that every front-end honours
/// the same knobs without each parsing getenv() itself.
struct ConcolicConfig {
  /// path to the symsan-instrumented binary (SYMSAN_TARGET)
  std::string symsan_bin;
  /// where solved inputs are saved when save_solved is set (SYMSAN_OUTPUT_DIR)
  std::string output_dir;
  /// file the session stages each traced input into.  The front-end must also
  /// substitute this path into args wherever the target expects its input file.
  std::string input_file;
  /// argv for the target; argv[0] is conventionally the target path
  std::vector<std::string> args;
  /// whether the target reads its input from stdin rather than input_file
  bool use_stdin = true;

  // --- solver ladder -------------------------------------------------------
  /// the i2s solver is always enabled; these add to it, in this order
  bool use_jigsaw = false;   // SYMSAN_USE_JIGSAW
  bool use_z3 = false;       // SYMSAN_USE_Z3
  bool nested_solving = false; // SYMSAN_USE_NESTED

  // --- tracing -------------------------------------------------------------
  bool trace_bounds = false;      // SYMSAN_TRACE_BOUNDS
  bool solve_ub = false;          // SYMSAN_SOLVE_UB (implies trace_bounds)
  bool exit_on_memerror = true;   // cleared by SYMSAN_DONT_EXIT_ON_MEMERROR
  bool force_stdin = false;       // SYMSAN_FORCE_STDIN
  bool save_solved = false;       // SYMSAN_SAVE_SOLVED
  bool debug = false;
  /// keep one instance of the target alive and fork it per input, instead of
  /// exec'ing it again every run (SYMSAN_FORKSRV).  Only takes effect for file
  /// input against a backend that has a fork server; otherwise it is a no-op.
  bool forkserver = false;        // SYMSAN_FORKSRV
  /// AFL++ AFL_LLVM_DOCUMENT_IDS output for the *fuzzer's* build of the same
  /// target (SYMSAN_BRANCH_MAP).  Setting it lets the session skip branches the
  /// fuzzer has already covered; see include/branch_map.h.  Empty means "no
  /// map", and the session then only knows what it has seen itself.
  std::string branch_map;
  /// Record which branch directions each trace takes, so that check_coverage()
  /// can hold the branch map against ground truth (SYMSAN_VALIDATE_COV).  Off
  /// by default: it costs a hash insert per branch and is a diagnostic, not
  /// something a fuzzing run needs.
  bool validate_coverage = false; // SYMSAN_VALIDATE_COV
  /// per-run timeout in milliseconds; also arms the deadloop guard
  unsigned timeout_ms = 50;       // MIN_TIMEOUT in driver/aflpp/symsan.cpp

  // --- limits --------------------------------------------------------------
  /// ASTs larger than this are not turned into tasks
  size_t max_ast_size = 200;              // MAX_AST_SIZE
  /// how many times one branch id may be traced within a single input
  uint8_t max_local_branch_counter = 128; // MAX_LOCAL_BRANCH_COUNTER
  /// largest input the session will trace or emit
  size_t max_input_size = 1 * 1024 * 1024; // AFL++'s MAX_FILE

  /// Populate from the SYMSAN_* environment variables.  Fields not covered by
  /// an environment variable (input_file, args, use_stdin) are left untouched.
  /// @return 0 on success, -1 if SYMSAN_TARGET is not set
  int from_env();
};

/// Counters matching the ones driver/aflpp/symsan.cpp printed under PRINT_STATS.
struct ConcolicStats {
  uint64_t total_branches = 0;
  uint64_t branches_to_solve = 0;
  uint64_t total_tasks = 0;
  uint64_t solved_tasks = 0;
  uint64_t solved_branches = 0;
  /// Branch directions the BranchMap could and could not resolve to fuzzer edge
  /// ids.  Both stay 0 without a map; with one, the ratio is the diagnostic for
  /// whether the two builds actually agree on branch names.
  uint64_t mapped_branches = 0;
  uint64_t unmapped_branches = 0;
};

class ConcolicSession : public symsan::EventHandler {
public:
  ConcolicSession();
  ~ConcolicSession() override;

  ConcolicSession(const ConcolicSession &) = delete;
  ConcolicSession &operator=(const ConcolicSession &) = delete;

  /// Map the union table, build the parser and the solver ladder, open the
  /// input file.  Must be called exactly once, and only once per process (see
  /// symsan::TraceSession for why).
  /// @return 0 on success, non-zero on failure
  int init(const ConcolicConfig &config);

  /// Stage @p buf into the input file, run the target on it, and turn the
  /// resulting trace into solving tasks.  Discards any tasks left over from a
  /// previous input.
  /// @return the number of tasks queued, or -1 on error
  int trace(const uint8_t *buf, size_t buf_size);

  /// Produce the next solved input for the tasks queued by trace().
  ///
  /// Walks (task, solver) pairs until one of them is satisfiable, so a caller
  /// can simply loop until this returns nullptr:
  ///
  ///     while (const uint8_t *sol = s.next_solution(&len)) {
  ///       bool interesting = run_and_evaluate(sol, len);
  ///       s.report_result(interesting);
  ///     }
  ///
  /// @param size  set to the length of the returned buffer
  /// @return a pointer to session-owned memory, valid until the next call to
  ///         next_solution() or trace(); nullptr when no tasks remain
  const uint8_t *next_solution(size_t *size);

  /// Tell the session whether the last solution from next_solution() turned out
  /// to be interesting (new coverage).  If it was, the underlying branch is
  /// considered solved and no further solver is tried for it.
  ///
  /// This replaces the guess driver/aflpp/symsan.cpp had to make by comparing
  /// queue-entry filenames: a front-end that can observe its own execution
  /// result (a LibAFL stage sees ExecuteInputResult directly) reports the truth.
  void report_result(bool interesting);

  /// Hand the session a snapshot of the fuzzer's coverage map, so that a branch
  /// the fuzzer already covered is not solved again.  Only has an effect when a
  /// branch map was loaded; without one there is no way to tell which entry of
  /// @p map corresponds to which branch, and the call is silently ignored.
  ///
  /// The snapshot is copied, so @p map need not outlive the call.  Call it
  /// before trace(); passing nullptr forgets the previous snapshot.
  /// @return 0 on success, -1 if no branch map is in use
  int set_coverage(const uint8_t *map, size_t len);

  /// Check the branch map against ground truth for the input just traced.
  ///
  /// @p covered is the set of AFL++ edge ids the *fuzzer's* build of the same
  /// target recorded for the same bytes -- from a corpus entry's tracked
  /// indices, or from afl-showmap.  Every direction this trace took should map
  /// to an edge in there; anything else means the map names the wrong edge, or
  /// the two builds took different paths.
  ///
  /// Needs both a branch map and ConcolicConfig::validate_coverage.
  /// @return 0 on success, -1 otherwise
  int check_coverage(const uint32_t *covered, size_t n, JoinReport *out) const;

  const ConcolicStats &stats() const { return stats_; }
  /// Write the counters and each solver's own stats to @p fd.
  void print_stats(int fd) const;

  /// Number of tasks still queued.
  size_t num_pending_tasks() const { return task_mgr_->get_num_tasks(); }
  /// Length of the solver ladder; trace() times this is the largest number of
  /// next_solution() calls that can return a buffer.
  size_t num_solvers() const { return solvers_.size(); }

  /// The file trace() stages inputs into, so the front-end can wire it into argv.
  const std::string &input_file() const { return config_.input_file; }

  // --- symsan::EventHandler ------------------------------------------------
  void on_cond(const symsan::pipe_msg &msg) override;
  void on_gep(const symsan::pipe_msg &msg, const symsan::gep_msg &gmsg) override;
  void on_memcmp(const symsan::pipe_msg &msg, const uint8_t *content, size_t size) override;
  void on_memerr(const symsan::pipe_msg &msg) override;

private:
  /// tracks whether the solution we last handed out has been judged yet; the
  /// same three-state machine driver/aflpp/symsan.cpp used
  enum mutation_state_t {
    MUTATION_INVALID,       // no solution outstanding
    MUTATION_IN_VALIDATION, // a solution is out with the front-end
    MUTATION_VALIDATED,     // the front-end said it was interesting
  };

  void save_solved_input(const uint8_t *buf, size_t size);

  ConcolicConfig config_;
  symsan::TraceSession session_;
  std::unique_ptr<RGDAstParser> parser_;
  std::unique_ptr<TaskManager> task_mgr_;
  std::unique_ptr<CovManager> cov_mgr_;
  std::unique_ptr<BranchMap> branch_map_;
  /// cov_mgr_ again when it is a SharedMapCovManager, so that set_coverage()
  /// and the join-rate counters do not have to go through a dynamic_cast on
  /// every branch.  Owned by cov_mgr_; null when no map was loaded.
  SharedMapCovManager *shared_cov_ = nullptr;
  std::vector<std::shared_ptr<Solver>> solvers_;

  /// the input trace() was last called with; the solvers mutate a copy of it
  std::vector<uint8_t> input_;
  std::vector<uint8_t> output_buf_;
  int input_fd_;
  bool initialized_;

  // solving state, carried across next_solution() calls
  task_t cur_task_;
  size_t cur_solver_index_;
  int mutation_state_;

  // per-input filters, cleared by trace()
  std::unordered_map<uint32_t, uint8_t> local_counter_;
  std::unordered_set<uint32_t> local_index_filter_;

  ConcolicStats stats_;
  std::map<uint64_t, uint64_t> task_size_dist_;
};

}; // namespace rgd
