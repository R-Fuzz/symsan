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
#include "tokens.h"

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
  /// Collect the concrete bytes the target compares its input against, as
  /// fuzzer dictionary tokens (SYMSAN_TOKENS).  Off by default: it costs a
  /// walk of every condition's boolean skeleton, and only a front-end with a
  /// token mutator has anywhere to put the answer.  See take_tokens().
  bool collect_tokens = false;    // SYMSAN_TOKENS
  /// per-run timeout in milliseconds; also arms the deadloop guard
  unsigned timeout_ms = 50;       // MIN_TIMEOUT in driver/aflpp/symsan.cpp

  // --- limits --------------------------------------------------------------
  /// ASTs larger than this are not turned into tasks
  size_t max_ast_size = 200;              // MAX_AST_SIZE
  /// how many times one branch id may be traced within a single input
  uint8_t max_local_branch_counter = 128; // MAX_LOCAL_BRANCH_COUNTER
  /// largest input the session will trace or emit
  size_t max_input_size = 1 * 1024 * 1024; // AFL++'s MAX_FILE
  /// how many distinct dictionary tokens the session will keep.  A dictionary
  /// is diluted by size, not slowed by it -- a token mutator picks one at
  /// random, so every junk entry costs a draw -- which is why this is small.
  size_t max_tokens = 4096;
  /// how many tasks the queue may hold before it starts throwing work away; 0
  /// leaves it unbounded, which is what it has always been.  The queue outlives
  /// the trace that filled it, so under a budget it is the whole campaign's
  /// backlog and grows without one (see #168).
  size_t max_queue_tasks = 0;             // SYMSAN_MAX_TASKS
  /// Drain the queue best-first rather than in arrival order, ranking each task
  /// by how new its destination is (enum TargetNovelty).  Off by default: with
  /// no bound and a queue drained to exhaustion the order is only latency, and
  /// this is the arm of an A/B, not a default anyone has earned yet.
  bool priority_tasks = false;            // SYMSAN_TASK_PRIORITY
  /// On an attempt that produced nothing the fuzzer kept, put the task back in
  /// the queue with its ladder position advanced instead of running the next
  /// solver on it right away.
  ///
  /// The ladder is a portfolio: i2s is fastest and least capable, z3 slowest
  /// and most capable, and all three can be asked the same task.  Walking it
  /// inline makes "when does the expensive solver run" a property of the loop
  /// -- immediately, always, for whatever task happens to be in hand.  Handing
  /// the task back makes it a property of the queue, which is the thing that
  /// already knows what else is waiting: the second attempt competes with every
  /// unattempted task, and under a bound it loses to them, so a saturated queue
  /// spends its budget on breadth and an idle one escalates.
  ///
  /// There is no give-up threshold to tune, because eviction is the give-up:
  /// a task nothing else outranks comes back, one everything outranks does not.
  ///
  /// Off by default and independent of priority_tasks so all four cells are
  /// reachable -- with a FIFO this defers escalation to the back of the whole
  /// queue, which is a different policy again and worth being able to measure.
  bool requeue_tasks = false;             // SYMSAN_REQUEUE_TASKS

  /// Climb the ladder after a solution the front-end did not keep, as well as
  /// after a rung that produced no solution at all.  This was the old
  /// unconditional behaviour; it is now off, and this exists to A/B it.
  ///
  /// The default is that a rung which *answered* is finished with the task,
  /// whatever became of the answer, and only a decline or a timeout escalates.
  /// The next rung would be handed the same constraint set, so if a satisfying
  /// assignment did not flip the branch, a second satisfying assignment to the
  /// same system is not going to either -- the constraints are stale or
  /// incomplete, the path changes under the new bytes, or the direction is
  /// infeasible.  Measured on libxml2: escalations after a kept-nothing SAT are
  /// 71.8% of all escalations and retire at 0.06% (#174).
  ///
  /// This is also the hybrid-fuzzing reading of a solution.  An input that did
  /// not flip its branch is not a failure to be retried; it went to the fuzzer,
  /// which is free to make something of it.  Not every input has to flip.
  bool escalate_unkept_solutions = false; // SYMSAN_ESCALATE_UNKEPT

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
  /// Tasks dropped unsolved because their target had been covered by the time
  /// a solver would have run -- usually by one of this batch's own earlier
  /// answers.  The parse-time filter cannot see those; see next_pending_task().
  uint64_t stale_tasks = 0;
  /// Tasks the queue refused or discarded to stay under max_queue_tasks.  Stays
  /// 0 without a bound; with one it is the measurement that says whether the
  /// bound is costing solvable work or only trimming a backlog nothing would
  /// have reached.
  uint64_t evicted_tasks = 0;
  /// Tasks offered to the queue, by how new their destination was (indexed by
  /// enum TargetNovelty).  All 0 unless the queue is the ranking one, which is
  /// the only one that scores.  This is what says whether the ranking has
  /// anything to rank: a run whose tasks all land in one bucket is one where
  /// best-first and oldest-first are the same queue.
  uint64_t queued_novelty[3] = {0, 0, 0};
  /// Per-solver accounting, indexed by position in the ladder -- position j is
  /// whatever ConcolicSession::solver_name(j) says, since which solvers are
  /// enabled is a config question.  Kept here rather than inside each Solver
  /// because two of the three keep no counters at all (Z3Solver and I2SSolver
  /// have empty print_stats), and because what a scheduler needs is the cost of
  /// *a call to rung j*, measured at the one place every call goes through.
  ///
  /// `usecs / calls` is the cost term: what it costs, on average, to ask rung j
  /// about a task.  The outcome split is what says whether that cost bought
  /// anything -- a rung with a large `usecs` and a `declined` count close to its
  /// `calls` is spending its time deciding it has nothing to say, which is a
  /// different problem from one that searches and fails.
  static constexpr size_t kMaxSolvers = 3;
  uint64_t solver_calls[kMaxSolvers] = {};
  uint64_t solver_usecs[kMaxSolvers] = {};
  uint64_t solver_sat[kMaxSolvers] = {};
  /// SOLVER_DECLINE: the rung did not search.  Everything else that is neither
  /// SAT, UNSAT nor a decline -- a search that ran its budget out, or an error
  /// -- is calls - sat - unsat - declined.
  uint64_t solver_declined[kMaxSolvers] = {};
  /// SOLVER_UNSAT: the rung says no assignment exists, which retires the task
  /// for every rung above it too.  Counted apart from the timeouts it used to
  /// share a residual with because the two are opposite outcomes -- an UNSAT is
  /// a complete answer and is usually the *cheapest* thing a rung can return
  /// (jigsaw's nested-task early exit is one, and never reaches the JIT), a
  /// timeout is the most expensive thing it can return.  Lumping them made
  /// "expensive failures went up" and "cheap answers went up" the same number.
  uint64_t solver_unsat[kMaxSolvers] = {};
  /// Tasks rung j RETIRED: it returned SAT and report_result() promoted the
  /// answer, i.e. the fuzzer kept the input or the target was reached.  This is
  /// the only counter that says a rung accomplished something; solver_sat says
  /// only that it answered.  The gap between them is the whole question, because
  /// a SAT that does not retire the task escalates, and next_pending_task() has
  /// already established the target is still uncovered by anybody -- so the
  /// assignment satisfied the recorded constraints and did not do what they
  /// claimed.  Without this, `sat` on the last rung cannot be checked at all:
  /// every other rung's retirements are recoverable as calls[j] - calls[j+1],
  /// and the top rung has no j+1 to difference against.
  uint64_t solver_retired[kMaxSolvers] = {};
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

  /// Whether the last solution actually took the branch it was solved for, as
  /// distinct from whether the fuzzer found it interesting.  See
  /// report_result().
  enum class TargetOutcome {
    /// No way to tell: the direction is pruned or unmapped, there is no branch
    /// map, or the front-end simply does not check.  The conservative answer.
    Unknown = 0,
    /// The run took the solved-for direction, or had already covered the edge
    /// so that taking it again would have gone unremarked.  Either way there is
    /// no evidence this solver failed.
    Reached,
    /// The run did not take it, and would have been noticed if it had.  The
    /// solver returned SAT on an AST that does not describe the program.
    NotReached,
  };

  /// Tell the session whether the last solution from next_solution() turned out
  /// to be interesting (new coverage).  If it was, the underlying branch is
  /// considered solved and no further solver is tried for it.
  ///
  /// This replaces the guess driver/aflpp/symsan.cpp had to make by comparing
  /// queue-entry filenames: a front-end that can observe its own execution
  /// result (a LibAFL stage sees ExecuteInputResult directly) reports the truth.
  ///
  /// @p outcome is what makes the *un*interesting case actionable, and it is
  /// worth the second parameter because that case is the bulk of the traffic.
  /// "Not interesting" was read as "try the next solver on this task", which
  /// conflates two situations: the branch did not flip -- another solver's
  /// assignment might, so escalating is right -- and the branch flipped onto
  /// ground that turned out to be boring, where every remaining solver will
  /// flip the same branch to the same edge and be boring in exactly the same
  /// way.  Measured on libxml2, the ladder returned 1.70 answers per task, and
  /// every answer costs the front-end a full execution.  So escalation now
  /// wants evidence of failure rather than absence of success.
  ///
  /// Unknown keeps the old behaviour, which is what a front-end that cannot
  /// check should get.
  void report_result(bool interesting,
                     TargetOutcome outcome = TargetOutcome::Unknown);

  /// Hand the session a snapshot of the fuzzer's coverage map, so that a branch
  /// the fuzzer already covered is not solved again.  Only has an effect when a
  /// branch map was loaded; without one there is no way to tell which entry of
  /// @p map corresponds to which branch, and the call is silently ignored.
  ///
  /// The snapshot is copied, so @p map need not outlive the call.  Call it
  /// before trace(); passing nullptr forgets the previous snapshot.
  /// @return 0 on success, -1 if no branch map is in use
  int set_coverage(const uint8_t *map, size_t len);

  /// set_coverage() without the copy: the session reads @p map in place.
  ///
  /// Prefer this from a front-end that owns the fuzzer's history map, because
  /// it makes the answer live.  The fuzzer runs each solved input as
  /// next_solution() hands it over, which updates that map -- so a copy taken
  /// before trace() has the session re-solving targets its own earlier answers
  /// already covered.
  ///
  /// @p map must stay valid and stay put until the next call.  Re-publish if
  /// it can be reallocated (LibAFL's MapFeedbackMetadata::history_map is a Vec
  /// and grows once, on the first is_interesting); pass nullptr to forget it.
  /// @return 0 on success, -1 if no branch map is in use
  int set_coverage_shared(const uint8_t *map, size_t len);

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

  /// A concrete byte string the target compared its input against.
  using Token = symsan::TokenCollector::Token;

  /// Drain the dictionary tokens found since the last call.
  ///
  /// Two sources, both of them things the trace already carries and throws
  /// away: the concrete side of a memcmp/strcmp (which the runtime ships
  /// verbatim, so nothing has to be reconstructed), and the constant operand of
  /// an integer comparison on the condition's boolean skeleton.
  ///
  /// What this is *for* is the half AFL++'s LTO autodict cannot reach.  That
  /// pass reads the constants in the binary, so it already has every
  /// compile-time literal; what it cannot have is a comparand computed at run
  /// time -- a name interned while parsing an earlier part of the input, a
  /// table entry, a length derived from a header field.  Those are most of what
  /// a real parser compares against, and they only exist during a trace.
  ///
  /// The second reason is the branches we fail on.  A comparand is worth
  /// handing to a token mutator precisely when the solver could not use it, and
  /// this is collected independently of parse_cond() so that a condition the
  /// parser refuses -- over max_ast_size, an op it has no node for -- still
  /// gives up its constants.
  ///
  /// Tokens are interned and never evicted, so each returned pointer stays
  /// valid for the life of the session and a token is only ever reported once.
  /// Needs ConcolicConfig::collect_tokens.
  ///
  /// @param out  where to write up to @p max tokens
  /// @param max  capacity of @p out; anything past it is kept for the next call
  /// @return how many tokens were written
  size_t take_tokens(Token *out, size_t max) {
    return config_.collect_tokens ? tokens_.take(out, max) : 0;
  }
  /// How many distinct tokens the session has interned so far.
  size_t num_tokens() const { return tokens_.size(); }

  const ConcolicStats &stats() const { return stats_; }
  /// Write the counters and each solver's own stats to @p fd.
  void print_stats(int fd) const;

  /// Number of tasks still queued.
  size_t num_pending_tasks() const { return task_mgr_->get_num_tasks(); }
  /// Length of the solver ladder; trace() times this is the largest number of
  /// next_solution() calls that can return a buffer.
  size_t num_solvers() const { return solvers_.size(); }
  /// Name of the solver at ladder position @p index, or nullptr past the end.
  /// The per-position counters in ConcolicStats are unreadable without this:
  /// position 0 is i2s in a default run and jigsaw in one started with
  /// --symsan-no-i2s.
  const char *solver_name(size_t index) const {
    return index < solvers_.size() ? solvers_[index]->name() : nullptr;
  }

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
  /// same three-state machine driver/aflpp/symsan.cpp used, plus a fourth that
  /// separates "this rung produced nothing" from "this rung produced something
  /// the front-end did not keep" -- the ladder now turns on that distinction.
  enum mutation_state_t {
    MUTATION_INVALID,       // no solution outstanding
    MUTATION_IN_VALIDATION, // a solution is out with the front-end
    MUTATION_VALIDATED,     // the front-end said it was interesting
    MUTATION_UNSOLVED,      // the rung declined or timed out; nothing was sent
  };

  void save_solved_input(const uint8_t *buf, size_t size);

  /// One branch target this trace could have flipped but did not take.
  ///
  /// Recorded for *every* branch, including the ones that never became a task
  /// -- whether a task was built is a solving decision, while the question
  /// input_taint() asks is a coverage one.
  ///
  /// `target` is the same object the tasks built for this branch hold, so
  /// `target->flipped` here and on the task are the same bit -- but it is null
  /// for the great majority of branches, which never get as far as a task.  The
  /// scalars above it are what input_taint() needs for one of those, and are
  /// why they are still here rather than being read off the target.
  ///
  /// Deliberately lazy: the local counter in on_cond() drops 84% (nvdcve_0.xml)
  /// to 98% (docbook_0.xml) of a libxml2 trace's conditions, measured, and a
  /// control block each for those is over a million allocations per trace on
  /// the hottest path in the session.  A target is built where the old negated
  /// context was, past the counter, so the allocation count is unchanged.
  struct TracedBranch {
    dfsan_label label;
    void *addr;
    uint32_t id;        ///< the branch's cid, for the re-ask in input_taint()
    bool neg_direction; ///< the direction we did *not* take
    std::shared_ptr<TaskTarget> target;
  };
  /// Record @p label and the direction not taken, for input_taint() and for
  /// next_pending_task().  @return the index, or SIZE_MAX
  ///
  /// The index is a within-trace one, read only by the caller a few lines later
  /// to hang a target off the record.  It is not how a task finds its target --
  /// that is SearchTask::target, which is why a task can now outlive the trace
  /// that built it.
  size_t note_branch(dfsan_label label, void *addr, uint32_t id,
                     bool neg_direction);

  /// The target for the branch on_cond()/on_gep() is currently handling, hung
  /// off @p branch_idx if note_branch() recorded one.
  ///
  /// Every task built for the branch gets this same object, which is what makes
  /// report_result() marking one of them retire the siblings still queued
  /// behind it.  Never null, even when @p branch_idx is SIZE_MAX: a task that
  /// reaches the queue with no target at all is one next_pending_task() will
  /// solve without asking, and a dependency scan failing says nothing about
  /// whether the branch is worth solving.
  std::shared_ptr<TaskTarget> make_target(size_t branch_idx, void *addr,
                                          uint32_t id, bool neg_direction,
                                          uint32_t context);

  /// The next queued task whose target is still worth solving, or null.
  ///
  /// Re-asks the coverage manager about each task before returning it, which
  /// is not the same question is_branch_interesting() answered when the task
  /// was built: that ran while the trace was still arriving, before any of this
  /// batch's own answers existed.  See the definition.
  task_t next_pending_task();

  ConcolicConfig config_;
  symsan::TraceSession session_;
  std::unique_ptr<RGDAstParser> parser_;
  /// Before task_mgr_ on purpose: PriorityTaskManager borrows the coverage
  /// manager to score with, and members are destroyed in reverse declaration
  /// order, so the borrower must outlive nothing -- it must die first.
  std::unique_ptr<CovManager> cov_mgr_;
  std::unique_ptr<TaskManager> task_mgr_;
  /// Tasks add_task() accepted, over the life of the session.  trace() reports
  /// the difference across a run, which the queue's own size no longer answers:
  /// a bounded manager can evict more than the trace queued, so the size can
  /// fall over a trace that produced plenty of work.
  uint64_t queued_ = 0;
  std::unique_ptr<BranchMap> branch_map_;
  /// cov_mgr_ again when it is a SharedMapCovManager, so that set_coverage()
  /// and the join-rate counters do not have to go through a dynamic_cast on
  /// every branch.  Owned by cov_mgr_; null when no map was loaded.
  SharedMapCovManager *shared_cov_ = nullptr;
  std::vector<std::shared_ptr<Solver>> solvers_;

  /// the input trace() was last called with; the solvers mutate a copy of it
  ///
  /// Held by shared_ptr and replaced -- not overwritten -- on every trace,
  /// because every task built from a trace keeps a reference to the bytes it
  /// was traced against (SearchTask::input).  Solving a task against some later
  /// trace's seed is not a worse answer, it is an answer to a different
  /// question: the task's Reads are offsets into *these* bytes.  The cost of
  /// that guarantee is that a corpus entry's bytes stay resident while any of
  /// its tasks is still queued, which is the same lifetime the tasks have.
  /// Never null: input_taint() and the like may be asked before the first
  /// trace, and an empty buffer is the answer they used to get.
  std::shared_ptr<std::vector<uint8_t>> input_ =
      std::make_shared<std::vector<uint8_t>>();
  std::vector<uint8_t> output_buf_;
  int input_fd_;
  bool initialized_;

  // solving state, carried across next_solution() calls.  The ladder position
  // is not here: it is SearchTask::solver_index, because with requeue_tasks a
  // task can go back into the queue between two of its own attempts, and a
  // position kept on the session would then belong to whatever came next.
  task_t cur_task_;
  int mutation_state_;

  // per-input filters, cleared by trace()
  std::unordered_map<uint32_t, uint8_t> local_counter_;
  std::unordered_set<uint32_t> local_index_filter_;

  // per-input taint export state, cleared by trace(); only touched when
  // config_.export_taint is set
  //
  // This is the list of *this trace's* branches, which is what input_taint()
  // wants, and clearing it per trace is correct for that.  A task's own link to
  // its target is no longer an index into here -- it is a shared_ptr on the task
  // (SearchTask::target), so it survives the clear and a task can be solved
  // after the trace that built it has gone.  The two point at the same objects.
  std::vector<TracedBranch> traced_branches_;
  /// every offset any branch on the path read
  RGDAstParser::input_dep_t traced_taint_;

  /// dictionary tokens, only touched when config_.collect_tokens is set
  symsan::TokenCollector tokens_;

  ConcolicStats stats_;
  std::map<uint64_t, uint64_t> task_size_dist_;
};

}; // namespace rgd
