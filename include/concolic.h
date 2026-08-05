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
  /// which solvers to run, in this order.  i2s is on by default -- it is the
  /// cheap one and the others assume it has already been tried -- but it is
  /// still a knob, so that a measurement can attribute solves to one solver.
  bool use_i2s = true;       // cleared by SYMSAN_NO_I2S
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
  /// TaintPass's -taint-branch-map output for this build of the target
  /// (SYMSAN_BRANCH_MAP).  Setting it lets the session skip branches the fuzzer
  /// has already covered; see include/branch_map.h.  Empty means "no map", and
  /// the session then only knows what it has seen itself.
  std::string branch_map;
  /// Record which branch directions each trace takes, so that check_coverage()
  /// can hold the branch map against ground truth (SYMSAN_VALIDATE_COV).  Off
  /// by default: it costs a hash insert per branch and is a diagnostic, not
  /// something a fuzzing run needs.
  bool validate_coverage = false; // SYMSAN_VALIDATE_COV
  /// Record which input offsets each branch reads, so that input_taint() can
  /// tell the front-end which bytes are still worth mutating (SYMSAN_EXPORT_TAINT).
  /// Off by default: it makes every branch pay for its dependency scan, even
  /// the ones that are never solved, and only a front-end running its own
  /// input-to-state pass has any use for the answer.
  bool export_taint = false;      // SYMSAN_EXPORT_TAINT
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

  /// Which branch the last next_solution() was solving for, and the edge that
  /// would light up in the fuzzer's map if it flipped.
  ///
  /// The point of this is that "interesting" is not "flipped".  A solution is
  /// run on the *coverage* build, and new coverage anywhere is enough to make
  /// it interesting -- including coverage the mutation reached by accident,
  /// nowhere near the branch it was solved for.  That distinction is invisible
  /// to report_result() and to anything downstream of it, so a target whose
  /// AST is wrong (bytes an uninstrumented library wrote, where the shadow
  /// still holds the previous occupant's labels) can look like a steady stream
  /// of successful solves.  Comparing @p dest against the coverage of the run
  /// is what tells the two apart.
  ///
  /// @param cid  the branch's id, which under the two-stage build is also the
  ///             AFL++ edge id
  /// @param direction  the direction the solution asked for, i.e. the one the
  ///             traced input did not take
  /// @param dest  the edge id reaching that side records, BranchMap::kPruned
  ///             when AFL++ numbered no edge for it (the side is implied by
  ///             other coverage, so nothing will ever light up), or 0 when the
  ///             branch map has never heard of this branch
  /// @return 0 on success; -1 when no solution is outstanding, or when the
  ///         task carries no branch -- which is also the case for every task
  ///         when export_taint is off, since that is what records them
  int current_target(uint32_t *cid, bool *direction, uint32_t *dest) const;

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

  /// Which bytes of the input just traced are still worth mutating.
  ///
  /// Writes one byte per input offset into @p out:
  ///
  ///   0 untainted -- no branch on this path read it
  ///   1 open      -- some branch target that depends on it is still unflipped
  ///   2 settled   -- a branch read it, and every target depending on it has
  ///                  been reached, so there is nothing left to find there
  ///
  /// The point is a fuzzer that also runs its own input-to-state pass: it can
  /// hold the settled bytes still and spend the pass on the open ones.  The
  /// classification is per data-flow group, not per byte, so bytes a constraint
  /// couples together are always classified the same way.
  ///
  /// Needs ConcolicConfig::export_taint, and is only meaningful once the caller
  /// has drained next_solution() -- a branch counts as flipped only after
  /// report_result() says its solution was interesting.
  ///
  /// @return the traced input size (which may be larger than @p len, in which
  ///         case only the first @p len offsets were written), or -1
  int input_taint(uint8_t *out, size_t len);

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
  void on_table(const symsan::pipe_msg &msg, const symsan::table_msg &tmsg,
                const uint8_t *content, size_t size) override;
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

  /// One branch target this trace could have flipped but did not take.
  ///
  /// Recorded for *every* branch, including the ones that never became a task
  /// -- whether a task was built is a solving decision, while the question
  /// input_taint() asks is a coverage one.
  struct TracedBranch {
    dfsan_label label;
    void *addr;
    uint32_t id;        ///< the branch's cid, for the re-ask in input_taint()
    bool neg_direction; ///< the direction we did *not* take
    bool flipped;       ///< a solution for it came back interesting
  };
  /// Record @p label and the direction not taken, for input_taint().  No-op
  /// unless export_taint is set.  @return the index, or SIZE_MAX
  size_t note_branch(dfsan_label label, void *addr, uint32_t id,
                     bool neg_direction);

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

  // per-input taint export state, cleared by trace(); only touched when
  // config_.export_taint is set
  std::vector<TracedBranch> traced_branches_;
  /// which TracedBranch a task came from.  The link has to live here because
  /// FIFOTaskManager drops the context it is handed.
  std::unordered_map<const SearchTask *, size_t> task_branch_;
  /// every offset any branch on the path read
  RGDAstParser::input_dep_t traced_taint_;

  ConcolicStats stats_;
  std::map<uint64_t, uint64_t> task_size_dist_;
};

}; // namespace rgd
