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

  return 0;
}

ConcolicSession::ConcolicSession()
    : input_fd_(-1), initialized_(false), cur_task_(nullptr),
      cur_solver_index_(0), mutation_state_(MUTATION_INVALID) {}

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
  task_mgr_.reset(new FIFOTaskManager());

  if (branch_map_) {
    auto *shared = new SharedMapCovManager(branch_map_.get());
    shared->set_validating(config_.validate_coverage);
    shared_cov_ = shared;
    cov_mgr_.reset(shared);
  } else {
    cov_mgr_.reset(new EdgeCovManager());
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

  std::shared_ptr<BranchContext> ctx;
  if (runtime_check) {
    ctx = std::make_shared<BranchContext>();
    ctx->addr = (void*)msg.addr;
    ctx->direction = msg.result != 0;
    ctx->id = msg.id;
  } else {
    ctx = cov_mgr_->add_branch((void*)msg.addr, msg.id, msg.result != 0,
                               msg.context, loop_latch, loop_exit);
  }

  std::shared_ptr<BranchContext> neg_ctx = std::make_shared<BranchContext>();
  *neg_ctx = *ctx;
  neg_ctx->direction = !ctx->direction;

  bool interesting = runtime_check || cov_mgr_->is_branch_interesting(neg_ctx);
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
    if (parser_->parse_cond(msg.label, ctx->direction, add_nested, tasks) != 0) {
      warn("failed to parse the condition %u\n", msg.label);
      // session_.terminate();
      return;
    }

    // add the tasks to the task manager
    for (auto const& task_id : tasks) {
      auto task = parser_->retrieve_task(task_id);
      if (branch_idx != SIZE_MAX) task_branch_[task.get()] = branch_idx;
      task_mgr_->add_task(neg_ctx, task);
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

  // add the tasks to the task manager, with a dummy context
  std::shared_ptr<BranchContext> ctx = std::make_shared<BranchContext>();
  ctx->addr = (void*)msg.addr;
  ctx->direction = true;
  ctx->id = 0;
  for (auto const& task_id : tasks) {
    auto task = parser_->retrieve_task(task_id);
    if (branch_idx != SIZE_MAX) task_branch_[task.get()] = branch_idx;
    task_mgr_->add_task(ctx, task);
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
  input_.assign(buf, buf + buf_size);

  // clear all caches
  std::vector<symsan::input_t> inputs;
  inputs.push_back({input_.data(), input_.size()});
  parser_->restart(inputs);
  local_counter_.clear();
  local_index_filter_.clear();
  // check_coverage() asks about *this* input, so the recorded directions have
  // to be this input's.  Unconditional: cheap when nothing was recorded.
  if (shared_cov_) shared_cov_->clear_taken();
  // and whatever else the manager keeps per trace rather than per session --
  // the hit counts that tell one loop iteration from the next.
  cov_mgr_->new_trace();
  // likewise input_taint(): it describes the input being traced now
  traced_branches_.clear();
  task_branch_.clear();
  traced_taint_.clear();
  traced_taint_.resize(input_.size());

  size_t tasks_before = task_mgr_->get_num_tasks();
  symsan::trace_result_t ret = session_.run(input_fd_, *this);
  if (ret == symsan::TRACE_LAUNCH_ERROR) {
    return -1;
  }

  // reinit solving state
  cur_task_ = nullptr;
  cur_solver_index_ = 0;
  mutation_state_ = MUTATION_INVALID;

  return (int)(task_mgr_->get_num_tasks() - tasks_before);
}

const uint8_t *ConcolicSession::next_solution(size_t *size) {
  *size = 0;
  if (!initialized_) {
    warn("ConcolicSession::next_solution called before init\n");
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
      cur_task_ = task_mgr_->get_next_task();
      if (!cur_task_) {
        mutation_state_ = MUTATION_INVALID;
        return nullptr;
      }
      // reset the solver and state
      cur_solver_index_ = 0;
      mutation_state_ = MUTATION_INVALID;
    } else if (mutation_state_ == MUTATION_IN_VALIDATION) {
      // oops, not solve, move on to next solver
      cur_solver_index_++;
      if (cur_solver_index_ >= solvers_.size()) {
        // if reached the max solver, move on to the next task
        cur_task_ = task_mgr_->get_next_task();
        if (!cur_task_) {
          mutation_state_ = MUTATION_INVALID;
          return nullptr;
        }
        cur_solver_index_ = 0; // reset solver index
      }
    }

    size_t new_buf_size = 0;
    auto &solver = solvers_[cur_solver_index_];
    auto ret = solver->solve(cur_task_, input_.data(), input_.size(),
                             output_buf_.data(), new_buf_size);
    if (SYMSAN_LIKELY(ret == SOLVER_SAT)) {
      mutation_state_ = MUTATION_IN_VALIDATION;
      if (config_.save_solved) {
        save_solved_input(output_buf_.data(), new_buf_size);
      }
      stats_.solved_tasks += 1;
      *size = new_buf_size;
      return output_buf_.data();
    } else if (ret == SOLVER_TIMEOUT) {
      // if not solved, move on to next stage
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
  auto itr = task_branch_.find(cur_task_.get());
  if (itr == task_branch_.end()) {
    return -1;
  }
  const auto &branch = traced_branches_[itr->second];
  if (cid) *cid = branch.id;
  if (direction) *direction = branch.neg_direction;
  if (dest) {
    // 0 for "the map cannot say", which is distinct from kPruned: kPruned is
    // the map answering that this side has no edge of its own, and the caller
    // must not read a miss there as a failure to flip.
    *dest = 0;
    if (branch_map_) {
      const uint32_t *edge = branch_map_->lookup(branch.id,
                                                 branch.neg_direction);
      if (edge) *dest = *edge;
    }
  }
  return 0;
}

void ConcolicSession::report_result(bool interesting) {
  if (mutation_state_ != MUTATION_IN_VALIDATION) {
    return;
  }
  if (!interesting) {
    // leave the state at MUTATION_IN_VALIDATION so that next_solution() moves
    // on to the next solver for the same task
    return;
  }
  mutation_state_ = MUTATION_VALIDATED;
  if (cur_task_) {
    cur_task_->skip_next = true;
    stats_.solved_branches += 1;
    // the target this task was for has now been reached, so input_taint() can
    // stop calling its bytes open
    auto itr = task_branch_.find(cur_task_.get());
    if (itr != task_branch_.end()) {
      traced_branches_[itr->second].flipped = true;
    }
  }
}

size_t ConcolicSession::note_branch(dfsan_label label, void *addr, uint32_t id,
                                    bool neg_direction) {
  if (!config_.export_taint) {
    return SIZE_MAX;
  }
  // note_deps() is a linear fill up to label, so this is free for any label an
  // earlier call already reached -- which, labels being handed out in order, is
  // most of them
  if (!parser_->note_deps(label, traced_taint_)) {
    return SIZE_MAX;
  }
  traced_branches_.push_back({label, addr, id, neg_direction, false});
  return traced_branches_.size() - 1;
}

int ConcolicSession::input_taint(uint8_t *out, size_t len) {
  if (!initialized_ || !config_.export_taint) {
    return -1;
  }
  if (out == nullptr && len) {
    return -1;
  }

  const size_t size = input_.size();
  // offsets some target still depends on.  Asked now rather than reusing what
  // on_cond() computed: add_branch() marks the direction taken as covered as it
  // goes, so a branch the trace later took the other way answers "covered" here
  // for free, and a solved-and-accepted one is skipped outright.
  RGDAstParser::input_dep_t open(size);
  auto ctx = std::make_shared<BranchContext>();
  for (auto const& b : traced_branches_) {
    if (b.flipped) continue;
    ctx->addr = b.addr;
    ctx->direction = b.neg_direction;
    ctx->id = b.id;
    if (!cov_mgr_->is_target_uncovered(ctx)) continue;
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
    "Solved branches: %lu\n",
    (unsigned long)stats_.total_branches, (unsigned long)stats_.total_tasks,
    (unsigned long)stats_.solved_tasks, (unsigned long)stats_.solved_branches);
  if (branch_map_) {
    dprintf(fd,
      "Branch map: %lu entries, %lu mapped, %lu unmapped\n",
      (unsigned long)branch_map_->size(), (unsigned long)stats_.mapped_branches,
      (unsigned long)stats_.unmapped_branches);
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
