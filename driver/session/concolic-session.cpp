/*
  rgd::ConcolicSession -- the RGD concolic-execution driver policy.

  Lifted from driver/aflpp/symsan.cpp so that every front-end shares one copy.
  The behaviour is intended to be identical to what the AFL++ mutator did; the
  places where it deliberately is not are marked NOTE.

  (c) 2023 - 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#include "concolic.h"

#include "branch_id.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>

using namespace __dfsan;

#define SYMSAN_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define SYMSAN_LIKELY(x) __builtin_expect(!!(x), 1)

namespace {

void warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void warn(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  fprintf(stderr, "[symsan] ");
  vfprintf(stderr, fmt, args);
  va_end(args);
}

// Microseconds, monotonic enough for a difference taken across one solve()
// call.  Same shape as jit-solver.cpp's getTimeStamp(), which is file-static
// there; not worth a shared header for four lines.
uint64_t solve_timestamp_us() {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

} // namespace

namespace rgd {

int ConcolicConfig::from_env() {
  const char *target = getenv("SYMSAN_TARGET");
  if (!target) {
    warn("SYMSAN_TARGET not defined, this should point to the full path of "
         "the symsan compiled binary\n");
    return -1;
  }
  symsan_bin = target;

  const char *dir = getenv("SYMSAN_OUTPUT_DIR");
  if (dir) output_dir = dir;

  // i2s is the one that is on unless asked otherwise, so its knob is negative
  if (getenv("SYMSAN_NO_I2S")) use_i2s = false;
  if (getenv("SYMSAN_USE_JIGSAW")) use_jigsaw = true;
  if (getenv("SYMSAN_USE_Z3")) use_z3 = true;
  // make nested solving optional too
  if (getenv("SYMSAN_USE_NESTED")) nested_solving = true;
  // enable trace bounds?
  if (getenv("SYMSAN_TRACE_BOUNDS")) trace_bounds = true;
  // disable exit on memory error
  if (getenv("SYMSAN_DONT_EXIT_ON_MEMERROR")) exit_on_memerror = false;
  if (getenv("SYMSAN_SOLVE_UB")) {
    trace_bounds = true; // solve undefined depends on trace bounds
    solve_ub = true;
  }
  // XXX: force stdin? ugly hack for aixcc
  if (getenv("SYMSAN_FORCE_STDIN")) force_stdin = true;
  // enable saving solved tasks
  if (getenv("SYMSAN_SAVE_SOLVED")) save_solved = true;
  // amortize process setup across runs instead of exec'ing every time
  if (getenv("SYMSAN_FORKSRV")) forkserver = true;
  // share the branch namespace with the fuzzer?
  const char *bmap = getenv("SYMSAN_BRANCH_MAP");
  if (bmap) branch_map = bmap;
  // check that shared branch namespace against ground truth?
  if (getenv("SYMSAN_VALIDATE_COV")) validate_coverage = true;
  // tell the front-end which input bytes are still worth mutating?
  if (getenv("SYMSAN_EXPORT_TAINT")) export_taint = true;
  // hand the front-end the concrete bytes the target compared against?
  if (getenv("SYMSAN_TOKENS")) collect_tokens = true;
  // bound the task backlog, and order it by how new each destination is
  const char *max_tasks = getenv("SYMSAN_MAX_TASKS");
  if (max_tasks) max_queue_tasks = (size_t)strtoull(max_tasks, nullptr, 10);
  if (getenv("SYMSAN_TASK_PRIORITY")) priority_tasks = true;
  // let the queue decide when the next rung of the solver ladder runs
  if (getenv("SYMSAN_REQUEUE_TASKS")) requeue_tasks = true;

  return 0;
}

ConcolicSession::ConcolicSession()
    : input_fd_(-1), initialized_(false), cur_task_(nullptr),
      mutation_state_(MUTATION_INVALID) {}

ConcolicSession::~ConcolicSession() {
  if (input_fd_ >= 0) close(input_fd_);
}

int ConcolicSession::init(const ConcolicConfig &config) {
  if (initialized_) {
    warn("ConcolicSession::init called twice\n");
    return -1;
  }
  if (config.symsan_bin.empty()) {
    warn("ConcolicSession::init needs a symsan_bin\n");
    return -1;
  }
  if (config.input_file.empty()) {
    warn("ConcolicSession::init needs an input_file\n");
    return -1;
  }
  config_ = config;

  // the input file doubles as the fd we hand the launcher, so it has to be
  // readable as well as writable
  input_fd_ = open(config_.input_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (input_fd_ < 0) {
    warn("failed to create input file %s: %s\n", config_.input_file.c_str(),
         strerror(errno));
    return -1;
  }

  // setup symsan launcher and map the union table
  void *shm_base = session_.init(config_.symsan_bin.c_str(), uniontable_size);
  if (!shm_base) {
    return -1;
  }

  // A branch map lets us ask what the *fuzzer* has covered instead of only what
  // this process has seen.  A map that fails to load is not fatal -- the point
  // of it is to skip redundant work, and the fallback is doing that work.
  //
  // Before configure() rather than after, because its `edges=` header is how
  // big the target's coverage map has to be and configure() is where that gets
  // said.
  if (!config_.branch_map.empty()) {
    std::unique_ptr<BranchMap> bm(new BranchMap());
    int n = bm->load(config_.branch_map);
    if (n <= 0) {
      warn("branch map %s unusable, falling back to local coverage only\n",
           config_.branch_map.c_str());
    } else {
      if (config_.debug) {
        warn("branch map %s: %d branch directions over %u edges, %zu lines "
             "unparsed, %zu out of range\n", config_.branch_map.c_str(), n,
             bm->edges(), bm->skipped(), bm->dropped());
      }
      branch_map_.reset(bm.release());
    }
  }

  symsan::TraceConfig tc;
  tc.input = config_.use_stdin ? "stdin" : config_.input_file;
  tc.args = config_.args;
  tc.timeout_ms = config_.timeout_ms;
  tc.debug = config_.debug;
  tc.bounds_check = config_.trace_bounds;
  tc.solve_ub = config_.solve_ub;
  tc.exit_on_memerror = config_.exit_on_memerror;
  tc.force_stdin = config_.force_stdin;
  tc.forkserver = config_.forkserver;
  tc.cov_map_size = branch_map_ ? branch_map_->edges() : 0;
  if (session_.configure(tc) != 0) {
    warn("failed to configure the trace session\n");
    return -1;
  }

  // setup the parser
  parser_.reset(new RGDAstParser(shm_base, uniontable_size,
                                 config_.nested_solving, config_.max_ast_size));
  // The token collector walks the same table, but deliberately not through the
  // parser: a condition the parser refuses is exactly the one whose constants
  // are worth handing to a mutator.  See include/tokens.h.
  tokens_.init(shm_base, uniontable_size, config_.max_tokens);

  if (branch_map_) {
    auto *shared = new SharedMapCovManager(branch_map_.get());
    shared->set_validating(config_.validate_coverage);
    shared_cov_ = shared;
    cov_mgr_.reset(shared);
  } else {
    cov_mgr_.reset(new EdgeCovManager());
  }

  // After the coverage manager, which the priority queue scores against and
  // therefore borrows.  Both are owned here and destroyed in reverse
  // declaration order, so the borrow is safe as long as task_mgr_ is declared
  // after cov_mgr_ (it is; see include/concolic.h).
  if (config_.priority_tasks) {
    task_mgr_.reset(
        new PriorityTaskManager(cov_mgr_.get(), config_.max_queue_tasks));
  } else {
    task_mgr_.reset(new FIFOTaskManager(config_.max_queue_tasks));
  }

  // the simpler i2s solver first, then the expensive ones in cost order
  if (config_.use_i2s) solvers_.emplace_back(std::make_shared<I2SSolver>());
  if (config_.use_jigsaw) solvers_.emplace_back(std::make_shared<JITSolver>());
  if (config_.use_z3) solvers_.emplace_back(std::make_shared<Z3Solver>());
  // Not an error -- tracing still runs, and a trace with no solver is a
  // legitimate way to measure what the tracing alone costs -- but it is far
  // more likely to be a front-end that turned everything off by accident, and
  // the symptom (no inputs, ever) says nothing about the cause.
  if (solvers_.empty()) warn("no solver enabled; nothing will be solved\n");

  // allocate output buffer.  We hand this to solve() and then hand solve()'s
  // answer straight out of next_solution() as the mutator's *out_buf, so it is
  // ours to size -- and a solved input can be LONGER than the one it came from
  // (i2s lengthens a strlen by inserting bytes, an atoi by writing more
  // digits).  The input side of this is bounded by max_input_size, so the extra
  // 4096 is what covers a grown answer; without it one runs off the end.
  output_buf_.resize(config_.max_input_size + 4096 + 1);

  initialized_ = true;
  return 0;
}

int ConcolicSession::set_coverage(const uint8_t *map, size_t len) {
  if (!shared_cov_) return -1;
  shared_cov_->set_coverage(map, len);
  return 0;
}

int ConcolicSession::set_coverage_shared(const uint8_t *map, size_t len) {
  if (!shared_cov_) return -1;
  shared_cov_->set_coverage_shared(map, len);
  return 0;
}

int ConcolicSession::check_coverage(const uint32_t *covered, size_t n,
                                    JoinReport *out) const {
  if (!shared_cov_ || !out) return -1;
  if (!config_.validate_coverage) return -1;
  if (covered == nullptr && n) return -1;
  *out = JoinReport();
  shared_cov_->validate(covered, n, out);
  return 0;
}

void ConcolicSession::on_cond(const symsan::pipe_msg &msg) {
  if (SYMSAN_UNLIKELY(msg.label == 0)) {
    return;
  } else if (SYMSAN_UNLIKELY(msg.label == kInitializingLabel)) {
    warn("UBI branch cond @%p\n", (void*)msg.addr);
    return;
  }

  stats_.total_branches += 1;

  // Record the dependency before the filters below, not after: a branch we
  // throttle away is still a branch whose target is unflipped, and the bytes it
  // reads are exactly the ones a front-end should keep mutating.
  size_t branch_idx = note_branch(msg.label, (void*)msg.addr, msg.id,
                                  msg.result == 0);

  // apply a local (per input) branch filter
  //
  // For a runtime check the key is the check *kind* rather than the site, since
  // that is all its cid says, so the budget is shared by every division in the
  // program.  Which is the behaviour to want here: with solve_ub on, a check
  // rides along with every tainted arithmetic op, and a per-site budget would
  // be no bound at all on the tasks one input can produce.
  auto &lc = local_counter_[msg.id];
  if (lc > config_.max_local_branch_counter) {
    return;
  } else {
    lc += 1;
  }

  // Before the coverage and solving decisions below, and not gated on either.
  // Whether a branch is worth *solving* is a question about novelty; whether
  // its comparand is worth *mutating towards* is not, and the branches this
  // session declines are exactly the ones a token mutator has to cover.
  if (config_.collect_tokens) tokens_.scan_cond(msg.label);

  // prase flags
  bool always_solve = (msg.flags & F_ADD_CONS) == 0;
  bool loop_latch = (msg.flags & F_LOOP_LATCH) != 0;
  bool loop_exit = (msg.flags & F_LOOP_EXIT) != 0;

  // A check the runtime raised itself -- an `enum undefined_check_ids` value,
  // which is why its cid falls in the range symsan::AFL_ID_BASE holds back --
  // is not a branch in the program, and the coverage manager has nothing true
  // to say about one:
  //
  // - There is no edge behind either direction, so the fuzzer's history cannot
  //   have covered it and the branch map holds no entry.  Asking anyway lands
  //   on the unmapped degrade path and counts there, which is worse than
  //   useless: unmapped()/mapped() is the diagnostic for whether the map covers
  //   the code being traced, and with solve_ub on there are enough UB checks to
  //   swamp it.
  // - Neither key identifies the site.  The cid is one of sixteen values shared
  //   by every check of that kind in the program, and the address is
  //   __builtin_return_address(0) taken inside __taint_union, so it names a
  //   line of the runtime rather than of the target.  Recording either would
  //   collapse every UB check in the program into one bucket.
  // - The question is not novelty but reachability -- can this input be made to
  //   divide by zero here? -- and the answer does not get less interesting for
  //   having been asked before.  So it is always solved, which is what the
  //   backend's F_ADD_CONS-derived always_solve already said for it; saying it
  //   here too means the session no longer depends on that coincidence.
  //
  // The manager keeping no record of them is also the right answer for
  // input_taint()'s later re-ask: a check that never fired has nothing marking
  // it covered, so is_target_uncovered() says uncovered and its bytes stay open.
  const bool runtime_check = symsan::is_runtime_check_id(msg.id);

  // Called for the side effects -- the covered bit, trace_hits_, and validate()'s
  // census -- rather than for the context it returns, which every manager builds
  // out of the three arguments it was just handed and reuses across calls.
  if (!runtime_check) {
    cov_mgr_->add_branch((void*)msg.addr, msg.id, msg.result != 0,
                         msg.context, loop_latch, loop_exit);
  }

  // The negated branch context every consumer below wants -- its direction is
  // the one not taken -- and, being the same object the tasks will carry, also
  // the session's record of the branch.  Built here, past the local counter,
  // where the separate neg_ctx used to be: this is one allocation per branch on
  // the hottest path there is, and the counter drops the great majority of them.
  auto target = make_target(branch_idx, (void*)msg.addr, msg.id,
                            msg.result == 0, msg.context);

  bool interesting = runtime_check || cov_mgr_->is_branch_interesting(target);
  if (shared_cov_) {
    // the manager counts what it looked up; mirror it so that stats() is the
    // one place a front-end has to read
    stats_.mapped_branches = shared_cov_->mapped();
    stats_.unmapped_branches = shared_cov_->unmapped();
  }

  if (interesting || always_solve) {
    // A runtime check is never nested.  Its constraint is "could this operation
    // be undefined", which is a question about this one expression, and adding
    // the path constraints that led here would only make it harder to satisfy
    // for no gain in what the answer means.  The fastgen backend already clears
    // F_ADD_CONS for these (backend/fastgen.cpp), so this is belt and braces --
    // but the flag comes over a pipe from a process we do not control, and the
    // rule belongs to whoever builds the task.
    bool add_nested = !runtime_check && (msg.flags & F_ADD_CONS) != 0;
    // parse the uniont table AST to solving tasks
    std::vector<uint64_t> tasks;
    if (parser_->parse_cond(msg.label, msg.result != 0, add_nested, tasks) != 0) {
      warn("failed to parse the condition %u\n", msg.label);
      // session_.terminate();
      return;
    }

    // add the tasks to the task manager
    for (auto const& task_id : tasks) {
      auto task = parser_->retrieve_task(task_id);
      task->target = target;
      // the bytes this task's Reads index into, so it stays solvable after the
      // session has moved on to another seed
      task->input = input_;
      if (task_mgr_->add_task(target, task)) queued_ += 1;
      task_size_dist_[task->size()] += 1;
    }

    stats_.total_tasks += tasks.size();
    stats_.branches_to_solve += 1;
  }
}

void ConcolicSession::on_gep(const symsan::pipe_msg &msg, const symsan::gep_msg &gmsg) {
  // msg.label === gmsg.index_label
  if (SYMSAN_UNLIKELY(msg.label == 0)) {
    return;
  } else if (SYMSAN_UNLIKELY(msg.label == kInitializingLabel)) {
    warn("UBI array index @%p\n", (void*)msg.addr);
    return;
  }

  // a symbolic index is an unflipped target in the same sense a branch is:
  // the bytes it reads are worth mutating until some other index is reached.
  // Cid 0, because an index is not a branch and has none: no branch map entry
  // is keyed on it, so the re-ask in input_taint() takes the unmapped path.
  size_t branch_idx = note_branch(gmsg.index_label, (void*)msg.addr, 0, true);

  // apply a local (per input) index filter
  if (!local_index_filter_.insert(msg.label).second) {
    return;
  }

  // parse the uniont table AST to solving tasks
  std::vector<uint64_t> tasks;
  if (parser_->parse_gep(gmsg.ptr_label, gmsg.ptr, gmsg.index_label, gmsg.index,
        gmsg.num_elems, gmsg.elem_size, gmsg.current_offset, false, tasks) != 0) {
    warn("failed to parse symbolic index %u\n", gmsg.index_label);
    // session_.terminate();
    return;
  }

  // add the tasks to the task manager, with the dummy context described above
  // -- cid 0 and direction true.  Past the index filter, like on_cond's.
  auto target = make_target(branch_idx, (void*)msg.addr, 0, true, msg.context);
  for (auto const& task_id : tasks) {
    auto task = parser_->retrieve_task(task_id);
    task->target = target;
    task->input = input_;
    if (task_mgr_->add_task(target, task)) queued_ += 1;
    task_size_dist_[task->size()] += 1;
  }

  stats_.total_tasks += tasks.size();
}

void ConcolicSession::on_memcmp(const symsan::pipe_msg &msg, const uint8_t *content,
                                size_t size) {
  // no content means both operands were symbolic, or the size was zero;
  // either way there is nothing to record
  if (!content) return;
  parser_->record_memcmp(msg.label, const_cast<uint8_t*>(content), size);
  // The best dictionary token there is: the target named the exact bytes it
  // wanted, and the runtime shipped them.  Unlike the constants below there is
  // nothing to guess about width or byte order.
  if (config_.collect_tokens) tokens_.add_str(content, size);
}

void ConcolicSession::on_table(const symsan::pipe_msg &msg,
                               const symsan::table_msg &tmsg,
                               const uint8_t *content, size_t size) {
  (void)msg;
  parser_->record_table(tmsg.ptr, const_cast<uint8_t*>(content), size);
}

void ConcolicSession::on_memerr(const symsan::pipe_msg &msg) {
  warn("memory error detected @%p, type = %d\n", (void*)msg.addr, msg.flags);
}

int ConcolicSession::trace(const uint8_t *buf, size_t buf_size) {
  if (!initialized_) {
    warn("ConcolicSession::trace called before init\n");
    return -1;
  }
  if (buf_size > config_.max_input_size) {
    return 0;
  }

  // stage the input where the target will read it from
  if (lseek(input_fd_, 0, SEEK_SET) < 0) {
    warn("failed to rewind input file: %s\n", strerror(errno));
    return -1;
  }
  size_t written = 0;
  while (written < buf_size) {
    ssize_t n = write(input_fd_, buf + written, buf_size - written);
    if (n <= 0) {
      warn("failed to write input file: %s\n", strerror(errno));
      return -1;
    }
    written += (size_t)n;
  }
  fsync(input_fd_);
  if (ftruncate(input_fd_, buf_size)) {
    warn("failed to truncate input file: %s\n", strerror(errno));
    return -1;
  }

  // keep our own copy: the solvers need the original bytes to build a mutated
  // buffer, and they are called long after trace() returns
  //
  // A fresh buffer rather than assigning over the old one, because the tasks
  // built by the last trace hold a reference to it (SearchTask::input) and may
  // still be queued.  Overwriting would silently re-point their Reads at
  // another seed's bytes.
  input_ = std::make_shared<std::vector<uint8_t>>(buf, buf + buf_size);

  // clear all caches
  std::vector<symsan::input_t> inputs;
  inputs.push_back({input_->data(), input_->size()});
  parser_->restart(inputs);
  local_counter_.clear();
  local_index_filter_.clear();
  // check_coverage() asks about *this* input, so the recorded directions have
  // to be this input's.  Unconditional: cheap when nothing was recorded.
  if (shared_cov_) shared_cov_->clear_taken();
  // and whatever else the manager keeps per trace rather than per session --
  // the hit counts that tell one loop iteration from the next.
  cov_mgr_->new_trace();
  // likewise input_taint(): it describes the input being traced now.  Only the
  // list goes; the targets themselves are held by whatever tasks were built for
  // them, so a task still queued from an earlier trace keeps its own.
  traced_branches_.clear();
  traced_taint_.clear();
  traced_taint_.resize(input_->size());

  // What the queue accepted, not how much longer it got: with a bound the two
  // differ, and a trace that filled the queue and then evicted its way past its
  // own contribution would otherwise report a negative number of tasks -- which
  // is this function's error code.
  uint64_t queued_before = queued_;
  symsan::trace_result_t ret = session_.run(input_fd_, *this);
  // Labels, not tokens: the dictionary is deliberately cumulative, but a label
  // only names the same AST within one run of the target.
  //
  // After the run rather than with the cache clears above, because the run of
  // byte comparisons the target was in the middle of is only complete once it
  // has exited: flushing at the top of the next trace would hand the caller a
  // token one trace late, and never hand it the last trace's at all.  Before
  // the error return for the same reason.
  tokens_.end_input();
  if (ret == symsan::TRACE_LAUNCH_ERROR) {
    return -1;
  }

  // reinit solving state.  No solver index to reset: it belongs to the task,
  // and a task that survives this trace keeps the ladder position it earned.
  cur_task_ = nullptr;
  mutation_state_ = MUTATION_INVALID;

  // The manager keeps the running totals; mirror them so a front-end reading
  // stats() does not need to know which manager it got.
  stats_.evicted_tasks = task_mgr_->evicted();
  if (const uint64_t *graded = task_mgr_->novelty_histogram()) {
    for (int i = 0; i < kTargetNoveltyCount; i++)
      stats_.queued_novelty[i] = graded[i];
  }

  return (int)(queued_ - queued_before);
}

const uint8_t *ConcolicSession::next_solution(size_t *size) {
  *size = 0;
  if (!initialized_) {
    warn("ConcolicSession::next_solution called before init\n");
    return nullptr;
  }

  // A trace with no solver is a supported configuration -- init() warns about
  // it rather than refusing, because it is how the cmplog measurement arm holds
  // the tracing cost fixed while solving nothing -- but the loop below reaches
  // solvers_[cur_solver_index_] before anything can bound-check it, so an empty
  // vector is an out-of-bounds read followed by a call through the result.
  //
  // Drain rather than simply return: task_mgr_ belongs to the session, not to
  // the trace (trace() only takes a before/after count), so a queue nobody pops
  // grows for the whole campaign.  Popped straight off the manager and not via
  // next_pending_task(), which would charge every one of them to stale_tasks --
  // they were not stale, they were never asked about.
  if (solvers_.empty()) {
    while (task_mgr_->get_next_task() != nullptr) {}
    cur_task_ = nullptr;
    mutation_state_ = MUTATION_INVALID;
    return nullptr;
  }

  // NOTE: driver/aflpp/symsan.cpp made exactly one (task, solver) attempt per
  // call and returned an empty mutation when that attempt did not produce a
  // solution, relying on AFL++ to call it again.  We loop instead, so that a
  // nullptr means "no work left" and a caller can write a plain while loop.
  // The sequence of solutions produced is the same.
  for (;;) {
    // try to get a task if we don't already have one
    // or if we've find a valid solution from the previous mutation
    if (!cur_task_ || mutation_state_ == MUTATION_VALIDATED) {
      cur_task_ = next_pending_task();
      if (!cur_task_) {
        mutation_state_ = MUTATION_INVALID;
        return nullptr;
      }
      // reset the state.  The solver index is not reset: it lives on the task
      // now, and a task coming back out of the queue is resuming its ladder.
      mutation_state_ = MUTATION_INVALID;
    } else if (mutation_state_ == MUTATION_IN_VALIDATION) {
      // oops, not solve, move on to next solver
      //
      // Two ways to get here: the solver returned something other than SAT, or
      // it returned SAT and report_result() did not promote the answer.  Both
      // mean this rung is finished with this task, and neither says anything
      // about the rungs above it, so they escalate the same way.
      cur_task_->solver_index++;
      if (cur_task_->solver_index >= solvers_.size()) {
        // if reached the max solver, move on to the next task
        cur_task_ = nullptr;
      } else if (config_.requeue_tasks) {
        // Hand the task back instead of asking the next rung right now.  The
        // queue is the thing that knows what else is waiting: sorted and
        // bounded, the second attempt competes with every task nobody has tried
        // yet, and it carries the same score with a later seq_, so it loses to
        // all of them.  A saturated queue therefore spends its budget on breadth
        // and evicts the requeued task -- which is the give-up rule, with no
        // threshold to pick -- while an idle one comes back to it and escalates.
        //
        // Not conditional on WHY the rung failed.  A decline is better evidence
        // than a timeout, but that difference belongs in the score if it belongs
        // anywhere; encoding it here would be a second scheduler.
        task_mgr_->add_task(cur_task_->target, cur_task_);
        cur_task_ = nullptr;
      }
      if (!cur_task_) {
        cur_task_ = next_pending_task();
        if (!cur_task_) {
          mutation_state_ = MUTATION_INVALID;
          return nullptr;
        }
      }
    }

    size_t new_buf_size = 0;
    const size_t rung = cur_task_->solver_index;
    auto &solver = solvers_[rung];
    // The task's own bytes, not the last trace's: a task's Reads are offsets
    // into the input it was traced against, so once the queue outlives the
    // trace that filled it, whatever was traced most recently is a different
    // question, not a worse-conditioned version of this one.  Falls back to the
    // current input for a task nobody labelled.
    const auto &in = cur_task_->input ? *cur_task_->input : *input_;
    // Timed here rather than inside each solver: JITSolver is the only one that
    // keeps its own clocks, and its three (codegen/jit/search) answer a question
    // about jigsaw's internals, not about what a call to rung j costs the
    // scheduler.  gettimeofday is a vDSO read, and the thing being measured
    // takes microseconds to milliseconds.
    const uint64_t t0 = solve_timestamp_us();
    auto ret = solver->solve(cur_task_, in.data(), in.size(),
                             output_buf_.data(), new_buf_size);
    if (rung < ConcolicStats::kMaxSolvers) {
      stats_.solver_calls[rung] += 1;
      stats_.solver_usecs[rung] += solve_timestamp_us() - t0;
      if (ret == SOLVER_SAT) stats_.solver_sat[rung] += 1;
      else if (ret == SOLVER_DECLINE) stats_.solver_declined[rung] += 1;
      else if (ret == SOLVER_UNSAT) stats_.solver_unsat[rung] += 1;
    }
    if (SYMSAN_LIKELY(ret == SOLVER_SAT)) {
      mutation_state_ = MUTATION_IN_VALIDATION;
      if (config_.save_solved) {
        save_solved_input(output_buf_.data(), new_buf_size);
      }
      stats_.solved_tasks += 1;
      *size = new_buf_size;
      return output_buf_.data();
    } else if (ret == SOLVER_TIMEOUT || ret == SOLVER_DECLINE) {
      // if not solved, move on to next stage
      //
      // The two share an arm here on purpose: this is the behaviour that was
      // measured, and splitting the enum is not supposed to change it.  They
      // are told apart one level up, by whoever decides *when* the next rung
      // runs -- a decline says "hand this to a more capable solver, it cost
      // nothing to learn that", a timeout says "this one searched and failed,
      // and the next may too".  Same action, different evidence.
      mutation_state_ = MUTATION_IN_VALIDATION;
    } else if (ret == SOLVER_UNSAT) {
      // at any stage if the task is deemed unsolvable, just skip it
      cur_task_->skip_next = true;
      cur_task_ = nullptr;
      mutation_state_ = MUTATION_INVALID;
    } else {
      warn("unknown solver return value %d\n", ret);
      // NOTE: symsan.cpp left the task in place here, which was safe only
      // because it returned to AFL++ after every attempt.  Inside a loop that
      // would spin forever, so drop the task.
      cur_task_ = nullptr;
      mutation_state_ = MUTATION_INVALID;
    }
  }
}

int ConcolicSession::current_target(uint32_t *cid, bool *direction,
                                    uint32_t *dest) const {
  // Same guard report_result() uses: outside IN_VALIDATION there is no
  // outstanding solution for cur_task_, so whatever it points at is either
  // stale or not yet attempted, and answering would name the wrong branch.
  if (mutation_state_ != MUTATION_IN_VALIDATION || !cur_task_) {
    return -1;
  }
  const auto &target = cur_task_->target;
  if (!target) {
    return -1;
  }
  if (cid) *cid = target->id;
  if (direction) *direction = target->direction;
  if (dest) {
    // 0 for "the map cannot say", which is distinct from kPruned: kPruned is
    // the map answering that this side has no edge of its own, and the caller
    // must not read a miss there as a failure to flip.
    *dest = 0;
    if (branch_map_) {
      const uint32_t *edge = branch_map_->lookup(target->id, target->direction);
      if (edge) *dest = *edge;
    }
  }
  return 0;
}

void ConcolicSession::report_result(bool interesting, TargetOutcome outcome) {
  if (mutation_state_ != MUTATION_IN_VALIDATION) {
    return;
  }
  if (!interesting && outcome != TargetOutcome::Reached) {
    // leave the state at MUTATION_IN_VALIDATION so that next_solution() moves
    // on to the next solver for the same task
    //
    // NotReached and Unknown both land here, and they are not the same
    // statement -- NotReached is evidence the assignment was wrong, Unknown is
    // no evidence at all.  Escalating on Unknown is the old unconditional
    // behaviour, kept because a front-end that cannot see its own coverage has
    // nothing better to go on and because the ladder is bounded anyway.
    return;
  }
  mutation_state_ = MUTATION_VALIDATED;
  if (cur_task_) {
    cur_task_->skip_next = true;
    // Credit the rung that produced the answer, which is the one the task is
    // still sitting on -- next_solution() only advances solver_index when it
    // comes back here and finds the state unchanged.  Counted for Reached-but-
    // boring as well as for interesting, because both retire the task and the
    // question this answers is "did asking rung j finish the job", not "did it
    // find something new"; solved_branches below is the narrower one.
    if (cur_task_->solver_index < ConcolicStats::kMaxSolvers) {
      stats_.solver_retired[cur_task_->solver_index] += 1;
    }
    // Only an interesting solution counts as a solved branch.  Reached-but-
    // boring retires the task, because no other solver can do better than
    // reach the target, but it did not find anything and saying it did would
    // make the stat useless as a measure of what the stage contributes.
    if (interesting) {
      stats_.solved_branches += 1;
    }
    // the target this task was for has now been reached, so input_taint() can
    // stop calling its bytes open
    //
    // True on the Reached path too, and more accurately than before: a
    // solution that flipped the branch onto already-covered ground has reached
    // the target by any reading, and used to leave its bytes open forever.
    //
    // Shared with the sibling tasks built for the same branch, which is what
    // retires them in next_pending_task() below.
    if (cur_task_->target) {
      cur_task_->target->flipped = true;
    }
  }
}

size_t ConcolicSession::note_branch(dfsan_label label, void *addr, uint32_t id,
                                    bool neg_direction) {
  // The record itself is unconditional.  It used to be export_taint's alone,
  // but next_pending_task() needs to know what target a task is for in order to
  // re-ask about it, and that is not a taint-export question -- nor are
  // report_result()'s `flipped` and current_target()'s answer to --flip-log,
  // all three of which used to reach traced_branches_ through a
  // SearchTask* -> index map and so were silently empty without the export.
  // (They now read SearchTask::target, so they no longer depend on this record
  // at all; it is still unconditional because input_taint() reads it.)  Only
  // the dependency scan below is export_taint's, and that is the part the flag
  // was justified by: it makes every branch pay, including the ones that never
  // become a task.
  if (config_.export_taint) {
    // note_deps() is a linear fill up to label, so this is free for any label an
    // earlier call already reached -- which, labels being handed out in order, is
    // most of them
    if (!parser_->note_deps(label, traced_taint_)) {
      return SIZE_MAX;
    }
  }
  traced_branches_.push_back({label, addr, id, neg_direction, nullptr});
  return traced_branches_.size() - 1;
}

std::shared_ptr<TaskTarget>
ConcolicSession::make_target(size_t branch_idx, void *addr, uint32_t id,
                             bool neg_direction, uint32_t context) {
  auto target = std::make_shared<TaskTarget>();
  target->addr = addr;
  target->direction = neg_direction;
  target->id = id;
  target->context = context;
  target->flipped = false;
  // SIZE_MAX means note_branch()'s dependency scan bailed and there is no
  // record to hang this off.  The target is still handed back: a task that
  // reaches the queue with no target at all is one next_pending_task() will
  // solve without asking, and a dependency scan failing says nothing about
  // whether the branch is worth solving.
  if (branch_idx != SIZE_MAX) traced_branches_[branch_idx].target = target;
  return target;
}

task_t ConcolicSession::next_pending_task() {
  for (;;) {
    auto task = task_mgr_->get_next_task();
    if (!task) return nullptr;

    // No recorded target: nobody who built this task said what it was for.
    // Nothing to ask about, so solve it.  note_branch() now always supplies one
    // for a task this session built, so in-tree this is only reachable for a
    // task some other producer queued.
    const auto &branch = task->target;
    if (!branch) return task;

    // Already answered, and the fuzzer took the answer.  report_result() sets
    // this, and the sibling tasks built for the same branch are still queued
    // behind it -- they share the target object, which is how they see it.
    if (branch->flipped) {
      stats_.stale_tasks += 1;
      continue;
    }

    // The question is_branch_interesting() asked at parse time, asked again now
    // that solving is about to cost something.  Two things have changed since:
    // the trace took later branches, and -- the expensive one -- every solution
    // already produced for this entry has been run by the fuzzer, because
    // next_solution() hands them over one at a time and the front-end evaluates
    // each before asking for the next.  So a target one of our own earlier
    // answers reached still looks open to a filter that ran before the trace.
    //
    // Deliberately the same question and not a coarser one.  "Is this edge
    // covered at all" would be easy here and would be wrong: is_target_uncovered
    // compares hit-count *classes*, which is what makes iteration k of a loop a
    // distinct target from iteration k-1, and a covered-bit test would refuse
    // every loop branch after the first.  The counters must not move, which is
    // why this is is_target_uncovered() and not is_branch_interesting().
    if (cov_mgr_->is_target_uncovered(branch)) return task;
    stats_.stale_tasks += 1;
  }
}

int ConcolicSession::input_taint(uint8_t *out, size_t len) {
  if (!initialized_ || !config_.export_taint) {
    return -1;
  }
  if (out == nullptr && len) {
    return -1;
  }

  const size_t size = input_->size();
  // offsets some target still depends on.  Asked now rather than reusing what
  // on_cond() computed: add_branch() marks the direction taken as covered as it
  // goes, so a branch the trace later took the other way answers "covered" here
  // for free, and a solved-and-accepted one is skipped outright.
  RGDAstParser::input_dep_t open(size);
  // For a branch with no target -- one the local counter dropped, which on a
  // libxml2 trace is most of them -- there is nothing that could have flipped
  // it, and one reused context answers the coverage question just as well.
  // Only a branch that got as far as a task carries its own.
  auto ctx = std::make_shared<BranchContext>();
  for (auto const& b : traced_branches_) {
    if (b.target) {
      if (b.target->flipped) continue;
      if (!cov_mgr_->is_target_uncovered(b.target)) continue;
    } else {
      ctx->addr = b.addr;
      ctx->direction = b.neg_direction;
      ctx->id = b.id;
      if (!cov_mgr_->is_target_uncovered(ctx)) continue;
    }
    (void)parser_->note_deps(b.label, open);
  }

  // Classify per data-flow group, never per byte: the bytes of a 4-byte compare
  // are one thing to mutate, and freezing half of them would leave the caller
  // with a value it cannot move.  Accumulate onto the group's root rather than
  // expanding each byte's group -- the latter costs O(k^2) for a group of k
  // bytes, and on a large input the whole thing can end up in one group.
  auto root_of = [&](size_t i) {
    size_t r = parser_->dep_group(i);
    return r == rgd::UnionFind::INVALID ? i : r; // never merged: its own group
  };
  std::unordered_map<size_t, uint8_t> group_bits; // 1 = has an open byte, 2 = tainted
  for (size_t i = 0; i < size; ++i) {
    uint8_t bits = (open.test(i) ? 1 : 0) | (traced_taint_.test(i) ? 2 : 0);
    if (bits) group_bits[root_of(i)] |= bits;
  }

  for (size_t i = 0; i < size && i < len; ++i) {
    auto itr = group_bits.find(root_of(i));
    uint8_t bits = itr == group_bits.end() ? 0 : itr->second;
    // one unflipped target anywhere in the group keeps the whole group open
    out[i] = (bits & 1) ? 1 : ((bits & 2) ? 2 : 0);
  }

  return (int)size;
}

void ConcolicSession::save_solved_input(const uint8_t *buf, size_t size) {
  const char *dir = config_.output_dir.empty() ? "." : config_.output_dir.c_str();
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/id_%lu", dir,
           (unsigned long)stats_.solved_tasks);
  int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    warn("failed to create solved file %s: %s\n", path, strerror(errno));
    return;
  }
  size_t written = 0;
  while (written < size) {
    ssize_t n = write(fd, buf + written, size - written);
    if (n <= 0) {
      warn("failed to write solved file %s: %s\n", path, strerror(errno));
      break;
    }
    written += (size_t)n;
  }
  close(fd);
}

void ConcolicSession::print_stats(int fd) const {
  dprintf(fd,
    "Total branches: %lu,\n"
    "Total tasks: %lu,\n"
    "Solved tasks: %lu,\n"
    "Stale tasks: %lu,\n"
    "Solved branches: %lu\n",
    (unsigned long)stats_.total_branches, (unsigned long)stats_.total_tasks,
    (unsigned long)stats_.solved_tasks, (unsigned long)stats_.stale_tasks,
    (unsigned long)stats_.solved_branches);
  // Only with a bound, which is off by default: a line of zeroes in every
  // stats dump reads as a thing that failed rather than a thing not asked for.
  if (config_.max_queue_tasks) {
    dprintf(fd, "Task queue: %lu of %lu held, %lu evicted, %s order\n",
            (unsigned long)task_mgr_->get_num_tasks(),
            (unsigned long)config_.max_queue_tasks,
            (unsigned long)task_mgr_->evicted(),
            config_.priority_tasks ? "priority" : "FIFO");
  }
  // Whether the ranking had anything to rank, which is not the same question as
  // whether it helped -- and the only one that can be answered from one arm.
  if (const uint64_t *graded = task_mgr_->novelty_histogram()) {
    dprintf(fd, "Task novelty: %lu new edge, %lu new class, %lu covered\n",
            (unsigned long)graded[kTargetNewEdge],
            (unsigned long)graded[kTargetNewClass],
            (unsigned long)graded[kTargetCovered]);
  }
  if (branch_map_) {
    dprintf(fd,
      "Branch map: %lu entries, %lu mapped, %lu unmapped\n",
      (unsigned long)branch_map_->size(), (unsigned long)stats_.mapped_branches,
      (unsigned long)stats_.unmapped_branches);
  }
  // Per rung: what it cost to ask, and what the asking produced.  `other` is
  // everything that was none of those -- a search that ran out of budget, or an
  // error -- and it is the expensive column.  UNSAT is broken out of it because
  // it is a complete answer arrived at cheaply, which is the opposite of a
  // timeout in both respects.  `retired` is the one that says the asking was
  // worth it: sat counts answers, retired counts answers the fuzzer kept, and
  // sat - retired is what escalated to the next rung having satisfied the
  // recorded constraints without reaching the target.
  for (size_t i = 0; i < solvers_.size() && i < ConcolicStats::kMaxSolvers; ++i) {
    const uint64_t n = stats_.solver_calls[i];
    if (!n) continue;
    const uint64_t sat = stats_.solver_sat[i], dec = stats_.solver_declined[i];
    const uint64_t uns = stats_.solver_unsat[i];
    dprintf(fd,
            "Solver %zu (%s): %lu calls, %lu us total, %.1f us/call, "
            "%lu sat (%lu retired), %lu unsat, %lu declined, %lu other\n",
            i, solvers_[i]->name(), (unsigned long)n,
            (unsigned long)stats_.solver_usecs[i],
            (double)stats_.solver_usecs[i] / (double)n,
            (unsigned long)sat, (unsigned long)stats_.solver_retired[i],
            (unsigned long)uns, (unsigned long)dec,
            (unsigned long)(n - sat - uns - dec));
  }
  dprintf(fd, "Task size distribution:\n");
  for (auto const& kv : task_size_dist_) {
    dprintf(fd, "\t %lu: %lu\n", (unsigned long)kv.first, (unsigned long)kv.second);
  }
  for (auto const& solver : solvers_) {
    solver->print_stats(fd);
  }
}

}; // namespace rgd
