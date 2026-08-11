// Standalone driver for testing the RGD (out-of-process) solver path.
//
// This is the RGD-path counterpart to fgtest.cpp: where fgtest drives the
// in-process z3 stack (parse-z3.h / z3-ts.cpp via symsan::Z3ParserSolver), this
// driver exercises the RGD stack that the AFL++ custom mutator (driver/aflpp)
// uses -- parsers/rgd-parser.cpp (rgd::RGDAstParser -> rgd::AstNode) feeding the
// rgd::Solver chain (I2SSolver, optional JITSolver, optional Z3Solver).  It lets
// us validate the RGD path deterministically on a single input, without the
// noisy afl-fuzz search loop.
//
// Usage: afltest [--dump-constraints <dir>] [--dump-tokens <file>]
//                [--target-args "<args>"] target input [input...]
//   TAINT_OPTIONS="taint_file=<file|stdin> output_dir=<dir>"
//   --dump-tokens  write the concrete bytes the target compared its input
//                  against to <file>, in AFL dictionary format.  The offline
//                  half of ConcolicSession::take_tokens(): the way to ask what
//                  a corpus would contribute to a fuzzer's dictionary, and to
//                  diff that against the target's own LTO autodict.
//   --target-args  extra argv for the target, split on whitespace, with `@@`
//                  where the input path goes (appended if there is no `@@`).
//                  A campaign's flags are part of what it traced: Magma runs
//                  `xmllint --valid --oldxml10 --push --memory @@`, and without
//                  --memory the seed never reaches an instrumented read, so the
//                  same corpus through the same binary traces nothing symbolic.
//   SYMSAN_USE_JIGSAW=1  add the jigsaw JIT solver to the chain
//   SYMSAN_USE_Z3=1      add the z3 solver to the chain (needed for FP)
//   SYMSAN_USE_NESTED=1  enable nested constraint solving in the parser
//   SYMSAN_MAX_AST_SIZE=N the parser's AST size limit, default 200.  Raising it
//                        is the control that tells a real constant fold apart
//                        from a size-forced concretization.
//   SYMSAN_NO_I2S=1      drop the i2s solver, which is otherwise always first;
//                        the way to ask what one of the others can do alone
//   SYMSAN_PARSE_ONLY=1  build the SearchTasks and drop them; report why the
//                        parser refused the rest.  See below.
//   SYMSAN_DUMP_CONDS=<f> under parse-only, also write one line per condition,
//                        keyed by (input, label), so that this driver's
//                        outcomes can be joined against fgtest's over the same
//                        corpus -- see driver/sweep.h and tools/cond-diff.py.
//                        Millions of lines on a real corpus; off by default.
//   SYMSAN_ONLY_CIDS=a,b,c  solve only these branch ids (AFL edge ids under the
//                        two-stage build).  Everything is still parsed, so the
//                        parser sees the same trace; only the solver chain and
//                        the output are skipped.  The way to ask one frontier
//                        branch a question on a seed whose full solve does not
//                        finish.
//   SYMSAN_VERBOSE=1     the per-event trace, off by default
//   SYMSAN_NO_OUTPUT=1   solve, but do not write the solved inputs out.  The
//                        fuzzer hands a solution back in memory
//                        (ConcolicSession::next_solution); only this driver
//                        turns each one into a file plus a result line.  On a
//                        corpus sweep that is millions of open/write/close
//                        triples and tens of megabytes of stdout, which is the
//                        wrong thing to be measuring when profiling the
//                        parser or the solvers.
//   SYMSAN_SOLVE_UB=1    also trace the runtime's own undefined-behaviour
//                        checks, which arrive as conditions with cids in the
//                        range reserved below the branch map base
//   SYMSAN_ENUM_GEP=1    ask parse_gep to enumerate indices.  ConcolicSession
//                        passes false unconditionally, so without this the
//                        first line of parse_gep returns and the whole GEP
//                        path is unreachable -- a sweep reports every GEP as
//                        skipped and learns nothing about the parser.  It is
//                        off by default here for the same reason it is off
//                        there, so that a plain run matches what the fuzzer
//                        does; turn it on to audit the path.
//
// More than one input sweeps a corpus in one process, sharing the fork server
// and the parser across seeds -- see run_one and the loop in main.
//
// --dump-constraints writes every distinct constraint of every task to
// <dir>/c-<n>.rgdc in the flat binary format of rgd::Constraint::save(), and
// round trips each one on the way out (reload, re-serialize, compare bytes and
// ASTs).  That check is the point of the option as much as the files are: it is
// what keeps the format from rotting the way the old NEED_OFFLINE path did.
//
// Solved inputs are written to <output_dir>/id-<inst>-<sess>-<idx>, one per
// solved task, mirroring fgtest's output naming so the lit tests can reuse the
// same CHECK-GEN pattern.

#include "defs.h"
#include "debug.h"
#include "version.h"

#include "dfsan/dfsan.h"

#include "ast.h"
#include "task.h"
#include "solver.h"

extern "C" {
#include "launch.h"
}

#include "parse-rgd.h"
#include "session.h"
#include "sweep.h"
#include "tokens.h"

#include <algorithm>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

using namespace __dfsan;

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// SYMSAN_VERBOSE: the per-event trace.
//
// AOUT fires once per branch and once per GEP, which is what you want when you
// are staring at one seed and is unusable the moment afltest is pointed at a
// corpus.  Off by default; set SYMSAN_VERBOSE to get it back, no rebuild
// needed.  Same switch and same reasoning as fgtest.
//
// What is *not* under it: the "generate #N output" line and the constraint
// round-trip warnings, which are results rather than trace, and the
// fprintf(stderr) failures, which have no other channel.  Rejected parses lose
// their prose here but keep last_error(), which parse-only mode buckets into
// PARSE-REASON.
static int __verbose = 0;

#undef AOUT
# define AOUT(...)                                      \
  do {                                                  \
    if (__verbose) printf(__VA_ARGS__);                 \
  } while(false)

// A result line, always printed.
# define ROUT(...)                                      \
  do {                                                  \
    printf(__VA_ARGS__);                                \
  } while(false)

// SYMSAN_PARSE_ONLY: build the SearchTasks but never solve them.
//
// construct_task() is what parse_cond and parse_gep already do; this mode just
// drops the result instead of handing it to the solver chain.  Solving
// dominates the wall clock of a trace and is also where most of the noise
// lives, so a sweep meant to answer "which branches does the RGD parser refuse,
// and why" runs an order of magnitude faster -- and produces countable output
// -- with i2s, jigsaw and z3 out of the picture.  What it prints instead is a
// machine-readable summary per input; see sweep.h.
//
// This is deliberately the *parser* question only.  A task that gets built and
// then declined by jigsaw's codegen is a different finding, counted elsewhere
// (see the parse-vs-jit split in tools/magma/results.sh).
static int __parse_only = 0;

// for input
static char *input_buf;
static size_t input_size;

// for output
static const char* __output_dir = ".";
static uint32_t __instance_id = 0;
static uint32_t __session_id = 0;
static uint32_t __current_index = 0;
static int __enum_gep = 0;  // GEP enumeration disabled by default
static const char* __dump_dir = nullptr;  // --dump-constraints, off by default

// --dump-tokens <file>: the dictionary the trace could hand a token mutator.
//
// This is the offline half of ConcolicSession::take_tokens(): the same
// collector, over the same events, written out in AFL's dictionary format so a
// corpus sweep's answer can be diffed against the target's own autodict.  Null
// unless the option is given, and the collector is then never fed.
static const char* __token_file = nullptr;
static symsan::TokenCollector __tokens;
// SYMSAN_NO_OUTPUT: still solve, still count, just skip generate_input.  See
// the option list at the top of the file.
static int __no_output = 0;

// SYMSAN_ONLY_CIDS: solve only these branch ids, empty for all of them.
//
// The filter is on *solving*, not on parsing: every condition is still parsed,
// so the parser's branch history and its constraint cache see the whole trace
// and a filtered run asks the same question of the same task a full run would.
// Only the solver chain and the output are skipped.
//
// This is what makes a frontier branch answerable one branch at a time.  A
// libxml2 seed traces 728854 conditions and a full solve writes a solution per
// task; picking the twelve that never flipped out of that is not a filter you
// can apply afterwards, because the run does not finish.
static std::unordered_set<uint32_t> __only_cids;

// the parse-reason counters, shared in shape with fgtest so that the two
// parsers can be swept over one corpus and read side by side
static symsan::sweep::parse_stats __stats;

// Where the target is pointed for every run of a corpus sweep.  path() is null
// in the single-input case, which still runs the seed where it lies.
static symsan::sweep::input_stager __staged;

// --target-args, tokenized.  Empty unless asked for, in which case the child's
// argv is program + these, with `@@` standing for the input path exactly as
// AFL++ spells it; without an `@@` the path is appended, which is what every
// caller before this option got.
//
// This exists because a target's flags decide which code the trace even covers.
// Magma runs xmllint as `--valid --oldxml10 --push --memory @@`, and without
// --memory the file never reaches an instrumented read, so a sweep of the same
// corpus through the same binary sees 28 concrete conditions and reads like a
// target with no symbolic input at all.  Reproducing a campaign's frontier off
// line is not possible without the campaign's argv.
static std::vector<std::string> __target_args;

// Build the child argv into @p out (which owns nothing; the strings belong to
// __target_args, @p program and @p input).  Always NULL terminated, and the
// count returned excludes that terminator, matching symsan_set_args.
static int build_target_argv(char *program, const char *input,
                             std::vector<char *> &out) {
  out.clear();
  out.push_back(program);
  bool saw_placeholder = false;
  for (auto &a : __target_args) {
    if (a == "@@") {
      out.push_back((char *)input);
      saw_placeholder = true;
    } else {
      out.push_back((char *)a.c_str());
    }
  }
  if (!saw_placeholder) out.push_back((char *)input);
  const int argc = (int)out.size();
  out.push_back(nullptr);
  return argc;
}

// the mapped union table (shared with the launched target)
static const size_t MAX_LABEL = uniontable_size / sizeof(dfsan_label_info);

// the RGD parser and the solver chain (matching driver/aflpp/symsan.cpp)
static rgd::RGDAstParser *__parser = nullptr;
static std::vector<std::shared_ptr<rgd::Solver>> __solvers;

// output buffer for solved inputs (RGD solvers write the full mutated buffer)
static uint8_t *__output_buf = nullptr;
static size_t __output_buf_size = 0;

// the i2s solver calls the global __dfsan::get_label_info; symsan-session
// provides the one definition, we just have to point it at the union table
// (see symsan::set_label_info_base below)

static void generate_input(const uint8_t *buf, size_t size) {
  // count it either way, so the index keeps meaning "how many were solved"
  if (__no_output) { __current_index++; return; }

  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "%s/id-%d-%d-%d", __output_dir,
           __instance_id, __session_id, __current_index++);
  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    ROUT("failed to open new input file for write\n");
    return;
  }

  ROUT("generate #%d output (size: %zu -> %zu)\n",
       __current_index - 1, input_size, size);

  if (write(fd, buf, size) == -1) {
    ROUT("failed to write new input\n");
  }

  close(fd);
}

// serialize every distinct constraint of a task, and check the round trip.
// Constraints are shared between tasks (the parser caches them by label), so
// dedup by pointer -- otherwise a hot branch's constraint is written once per
// task that reuses it.
static void dump_constraints(rgd::task_t task) {
  static std::unordered_set<const rgd::Constraint*> seen;
  static uint32_t index = 0;

  for (size_t i = 0; i < task->size(); i++) {
    const auto &c = task->constraints(i);
    if (!seen.insert(c.get()).second) continue;

    std::vector<uint8_t> buf;
    if (!c->save(buf)) {
      ROUT("WARNING: failed to serialize constraint %p\n", (void*)c.get());
      continue;
    }

    // reload and compare.  Byte equality of the re-serialization covers the
    // scalar fields; isEqualAst covers the tree, which the bytes would also
    // catch but only as an opaque mismatch.
    auto rt = std::make_shared<rgd::Constraint>(0);
    std::vector<uint8_t> rebuf;
    if (!rt->load(buf.data(), buf.size())) {
      ROUT("WARNING: failed to deserialize constraint %p\n", (void*)c.get());
    } else if (!rt->save(rebuf) || rebuf != buf) {
      ROUT("WARNING: constraint %p did not round trip byte-identically\n",
           (void*)c.get());
    } else if (!rgd::isEqualAst(*c->get_root(), *rt->get_root())) {
      ROUT("WARNING: constraint %p round tripped to a different AST\n",
           (void*)c.get());
    }

    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "%s/c-%d.rgdc", __dump_dir, index++);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
      ROUT("failed to open %s for write\n", path);
      continue;
    }
    if (write(fd, buf.data(), buf.size()) == -1) {
      ROUT("failed to write %s\n", path);
    }
    close(fd);
  }
}

// run a solving task through the solver chain; on the first SAT result write
// out the mutated input.  Mirrors the per-solver fall-through in aflpp's
// afl_custom_fuzz (i2s -> jigsaw -> z3), but drives it synchronously.
static void solve_task(rgd::task_t task, void *addr) {
  if (!task) return;
  if (__dump_dir) dump_constraints(task);
  for (auto &solver : __solvers) {
    size_t new_size = 0;
    auto ret = solver->solve(task, (uint8_t*)input_buf, input_size,
                             __output_buf, new_size);
    if (ret == rgd::SOLVER_SAT) {
      AOUT("task solved\n");
      generate_input(__output_buf, new_size);
      return;
    } else if (ret == rgd::SOLVER_UNSAT) {
      // deemed unsolvable, no point trying the remaining solvers
      AOUT("task not solvable @%p\n", addr);
      return;
    }
    // SOLVER_TIMEOUT / SOLVER_DECLINE / SOLVER_ERROR: fall through to the next
    // solver.  This driver tries the whole ladder unconditionally, so it has no
    // use for the timeout-vs-decline split; the scheduler in
    // ConcolicSession does.
  }
  AOUT("task not solved @%p\n", addr);
}

// `cid` is the branch id the trace event carried.  Under the two-stage build it
// is the AFL edge id, which is the only key that joins a parse outcome to the
// fuzzer's coverage map; it is otherwise unused here.
static void __solve_cond(dfsan_label label, uint8_t r, bool add_nested, void *addr,
                         uint32_t cid) {

  // cid is in the line so that an offline reader can tell which branch each
  // "generate #N output" belongs to: the two lines interleave in trace order,
  // and the index in the second is the id-<inst>-<sess>-<index> file name.
  // Without it a solved input cannot be joined back to a coverage map edge.
  AOUT("solving label %d = %d, cid %u, add_nested: %d\n", label, r, cid,
       add_nested);
  // Before parse_cond(), and not gated on what it says: a condition the parser
  // refuses is exactly the one whose comparand a token mutator has to cover.
  if (__token_file) __tokens.scan_cond(label);
  if (__parse_only && label == 0) {
    // A loop-exit notification, not a condition -- there is no AST to build and
    // no branch to flip, so it is neither a success nor a failure.  parse_cond
    // does reject label 0 with "invalid label", but the caller is what decides
    // whether that counts: on a loop-heavy target this is tens of thousands of
    // events, and bucketing them as rejections is what put 38600 phantom
    // entries in fgtest's first sweep.
    __stats.conds++;
    __stats.loop_exits++;
    symsan::sweep::log_cond_loop_exit();
    return;
  }
  std::vector<uint64_t> tasks;
  int failed = __parser->parse_cond(label, r != 0, add_nested, tasks);
  if (__parse_only) {
    __stats.conds++;
    __stats.cond_tasks += tasks.size();
    __stats.note(failed != 0, tasks.size(), __parser->last_error(), addr,
                 __stats.cond_ok, __stats.cond_empty, __stats.cond_failed, cid);
    __stats.log(label, failed != 0, tasks.size(), __parser->last_error(), addr,
                cid);
    // Drop the tasks: retrieve_task hands over ownership, so without this the
    // parser's task table grows for the whole trace.
    for (auto id : tasks) __parser->retrieve_task(id);
    return;
  }
  if (failed) {
    AOUT("WARNING: failed to parse condition %d @%p\n", label, addr);
    return;
  }

  for (auto id : tasks) {
    auto task = __parser->retrieve_task(id);
    // retrieve_task hands over ownership either way, so a filtered-out task is
    // still taken out of the parser's table -- dropping it here is what keeps
    // that table from growing for the whole trace.
    if (!__only_cids.empty() && !__only_cids.count(cid)) continue;
    solve_task(task, addr);
  }
}

static void __handle_gep(dfsan_label ptr_label, uptr ptr,
                         dfsan_label index_label, int64_t index,
                         uint64_t num_elems, uint64_t elem_size,
                         int64_t current_offset, void* addr) {

  AOUT("tainted GEP index: %ld = %d, ne: %ld, es: %ld, offset: %ld\n",
      index, index_label, num_elems, elem_size, current_offset);

  std::vector<uint64_t> tasks;
  int failed = __parser->parse_gep(ptr_label, ptr, index_label, index, num_elems,
                                   elem_size, current_offset, __enum_gep, tasks);
  if (__parse_only) {
    __stats.geps++;
    __stats.gep_tasks += tasks.size();
    __stats.gep_shape[(num_elems != 0) * 2 + (ptr_label != 0)]++;
    // A GEP the parser only declined because we did not ask it to enumerate is
    // not a rejection to attribute -- see gep_skipped.  It still has to have
    // reached that early return: a -1 here is a label the parser refused before
    // ever looking at enum_index, and that is a real failure.
    if (!__enum_gep && failed == 0) {
      __stats.gep_skipped++;
      __stats.gep_empty++;
    } else {
      __stats.note(failed != 0, tasks.size(), __parser->last_error(), addr,
                   __stats.gep_ok, __stats.gep_empty, __stats.gep_failed);
    }
    for (auto id : tasks) __parser->retrieve_task(id);
    return;
  }
  if (failed) {
    AOUT("WARNING: failed to parse gep %d @%p\n", index_label, addr);
    return;
  }

  for (auto id : tasks) {
    auto task = __parser->retrieve_task(id);
    solve_task(task, addr);
  }
}

// Trace one input end to end: run the target, then drain and parse the event
// stream it produces.  Split out of main() so that one process can walk a whole
// corpus -- see the loop at the bottom.  Everything that can be kept across
// inputs is: symsan_init maps the union table once, the fork server is spawned
// once, and the parser is reset with restart() rather than rebuilt, which is
// what restart() is for.
//
// Returns 0 on success, -1 if this input could not be traced.  A failure is per
// input rather than fatal, so that one unreadable seed does not end a sweep.
static int run_one(char *program, char *input, int is_stdin) {
  // load input file
  struct stat st;
  int input_fd = open(input, O_RDONLY);
  if (input_fd == -1) {
    fprintf(stderr, "Failed to open input file %s: %s\n", input, strerror(errno));
    return -1;
  }
  fstat(input_fd, &st);
  input_size = st.st_size;
  // mmap of a zero-length file fails; an empty seed is a thing a corpus has, and
  // it is not worth ending the run over
  input_buf = input_size ? (char *)mmap(NULL, input_size, PROT_READ, MAP_PRIVATE,
                                        input_fd, 0)
                         : (char *)MAP_FAILED;
  if (input_buf == MAP_FAILED) {
    fprintf(stderr, "Failed to map input file %s: %s\n", input,
            input_size ? strerror(errno) : "empty file");
    close(input_fd);
    return -1;
  }

  // grow the output buffer if this seed is longer than any before it.  RGD
  // solvers write the full (possibly grown) input; give some headroom for
  // INSERT-style solutions.
  if (input_size + 4096 > __output_buf_size) {
    size_t want = input_size + 4096;
    uint8_t *grown = (uint8_t *)realloc(__output_buf, want);
    if (!grown) {
      fprintf(stderr, "Failed to alloc output buffer\n");
      goto fail;
    }
    __output_buf = grown;
    __output_buf_size = want;
  }

  if (__staged.path()) {
    // input path and args were set once, before the server was spawned; only
    // the contents change
    if (__staged.stage(input_buf, input_size) != 0) {
      fprintf(stderr, "Failed to stage %s: %s\n", input, strerror(errno));
      goto fail;
    }
    close(input_fd);
    input_fd = __staged.fd();
  } else if (symsan_set_input(is_stdin ? "stdin" : input) != 0) {
    fprintf(stderr, "Failed to set input\n");
    goto fail;
  }

  {
    if (!__staged.path()) {
      std::vector<char *> args;
      const int nargs = build_target_argv(program, input, args);
      if (symsan_set_args(nargs, args.data()) != 0) {
        fprintf(stderr, "Failed to set args\n");
        goto fail;
      }
    }

    // launch the target
    int ret = symsan_run(input_fd);
    if (ret < 0) {
      fprintf(stderr, "Failed to launch target: %s\n", strerror(errno));
      goto fail;
    } else if (ret > 0) {
      fprintf(stderr, "SymSan launch error %d\n", ret);
      goto fail;
    }
    if (input_fd != __staged.fd()) close(input_fd);
    input_fd = -1;

    std::vector<symsan::input_t> inputs;
    inputs.push_back({(uint8_t*)input_buf, input_size});
    if (__parser->restart(inputs) != 0) {
      fprintf(stderr, "Failed to restart parser\n");
      goto fail;
    }

    pipe_msg msg;
    gep_msg gmsg;
    dfsan_label_info *info;
    size_t msg_size;
    memcmp_msg *mmsg = nullptr;
    table_msg *tmsg = nullptr;

    while (symsan_read_event(&msg, sizeof(msg), 0) > 0) {
      // Every message type, not just the ones that parse: this is the "did the
      // target trace anything at all" number, and a sweep that cannot separate
      // that from "the parser accepted everything" is unreadable.  #115 is an
      // open bug where afltest reads zero events under a concurrent lit run,
      // which without this line a sweep would report as a clean result.
      __stats.events++;
      // solve constraints
      switch (msg.msg_type) {
        case cond_type:
          __solve_cond(msg.label, msg.result, msg.flags & F_ADD_CONS, (void*)msg.addr,
                       msg.id);
          break;
        case gep_type:
          if (symsan_read_event(&gmsg, sizeof(gmsg), 0) != sizeof(gmsg)) {
            fprintf(stderr, "Failed to receive gep msg: %s\n", strerror(errno));
            break;
          }
          // double check
          if (msg.label != gmsg.index_label) {
            fprintf(stderr, "Incorrect gep msg: %d vs %d\n", msg.label, gmsg.index_label);
            break;
          }
          __handle_gep(gmsg.ptr_label, gmsg.ptr, gmsg.index_label, gmsg.index,
                       gmsg.num_elems, gmsg.elem_size, gmsg.current_offset, (void*)msg.addr);
          break;
        case memcmp_type:
          if (msg.label == 0 || msg.label >= MAX_LABEL) {
            fprintf(stderr, "Invalid memcmp label: %d\n", msg.label);
            break;
          }
          info = get_label_info(msg.label);
          // if both operands are symbolic, no content to be read
          if (info->l1 != CONST_LABEL && info->l2 != CONST_LABEL)
            break;
          msg_size = sizeof(memcmp_msg) + msg.result;
          mmsg = (memcmp_msg*)malloc(msg_size);
          if (symsan_read_event(mmsg, msg_size, 0) != msg_size) {
            fprintf(stderr, "Failed to receive memcmp msg: %s\n", strerror(errno));
            free(mmsg);
            break;
          }
          // double check
          if (msg.label != mmsg->label) {
            fprintf(stderr, "Incorrect memcmp msg: %d vs %d\n", msg.label, mmsg->label);
            free(mmsg);
            break;
          }
          // save the content
          __parser->record_memcmp(msg.label, mmsg->content, msg.result);
          // The best dictionary token there is: the target named the exact
          // bytes it wanted, and the runtime shipped them.  Unlike an ICmp
          // constant there is nothing to guess about width or byte order.
          if (__token_file) __tokens.add_str(mmsg->content, msg.result);
          free(mmsg);
          break;
        case table_type:
          // always carries a payload, so drain it before validating anything
          msg_size = sizeof(table_msg) + msg.result;
          tmsg = (table_msg*)malloc(msg_size);
          if (symsan_read_event(tmsg, msg_size, 0) != msg_size) {
            fprintf(stderr, "Failed to receive table msg: %s\n", strerror(errno));
            free(tmsg);
            break;
          }
          // double check
          if (tmsg->num_elems * tmsg->elem_size != msg.result) {
            fprintf(stderr, "Incorrect table msg: %lu x %lu vs %lu\n",
                    tmsg->num_elems, tmsg->elem_size, msg.result);
            free(tmsg);
            break;
          }
          // save the content
          __parser->record_table(tmsg->ptr, tmsg->content, msg.result);
          free(tmsg);
          break;
        case add_constraint_type:
          __parser->add_constraints(msg.label, msg.result);
          break;
        default:
          break;
      }
    }
  }

  munmap(input_buf, input_size);
  input_buf = nullptr;
  return 0;

fail:
  munmap(input_buf, input_size);
  input_buf = nullptr;
  if (input_fd != -1 && input_fd != __staged.fd()) close(input_fd);
  return -1;
}

// Write the collected dictionary to @p path in AFL's format, one
// `token_N="..."` per line, so that `afl-fuzz -x` and `libafl`'s Tokens::from_file
// both read it and so that it can be diffed against the target's own autodict.
//
// Escaping is AFL's: everything outside printable ASCII, plus `"` and `\`, goes
// out as \xNN.  Sorted, because the file's whole purpose here is to be diffed.
static void dump_tokens(const char *path) {
  FILE *f = fopen(path, "w");
  if (!f) {
    fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
    return;
  }
  std::vector<std::string> sorted(__tokens.all().begin(), __tokens.all().end());
  std::sort(sorted.begin(), sorted.end());
  size_t n = 0;
  for (const std::string &t : sorted) {
    fprintf(f, "token_%zu=\"", n++);
    for (unsigned char c : t) {
      if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
      else if (c >= 0x20 && c < 0x7f) fputc(c, f);
      else fprintf(f, "\\x%02x", c);
    }
    fprintf(f, "\"\n");
  }
  fclose(f);
  fprintf(stderr, "wrote %zu tokens to %s\n", n, path);
}

int main(int argc, char* const argv[]) {

  int optind = 1;
  while (argc - optind > 2) {
    if (strcmp(argv[optind], "--dump-constraints") == 0) {
      __dump_dir = argv[optind + 1];
      optind += 2;
    } else if (strcmp(argv[optind], "--dump-tokens") == 0) {
      __token_file = argv[optind + 1];
      optind += 2;
    } else if (strcmp(argv[optind], "--target-args") == 0) {
      // One shell-style word list, split on whitespace only: enough for every
      // Magma command line, and quoting rules are not this driver's business.
      const char *s = argv[optind + 1];
      while (*s) {
        while (*s == ' ' || *s == '\t') s++;
        const char *b = s;
        while (*s && *s != ' ' && *s != '\t') s++;
        if (s > b) __target_args.emplace_back(b, (size_t)(s - b));
      }
      optind += 2;
    } else {
      break;
    }
  }

  if (argc - optind < 2) {
    fprintf(stderr,
            "Usage: %s [--dump-constraints <dir>] [--dump-tokens <file>] "
            "[--target-args \"<args>\"] target input [input...]\n",
            argv[0]);
    exit(1);
  }

  char *program = argv[optind];
  const int first_input = optind + 1;

  // A target that cannot be exec'd is not an error anywhere below: the launcher
  // forks, execv fails in the child, and every read comes back empty -- so the
  // run reports zero events and exits 0, which over a corpus reads exactly like
  // a target that parses cleanly.  Say so here instead.
  if (access(program, X_OK) != 0) {
    fprintf(stderr, "Cannot execute %s: %s\n", program, strerror(errno));
    exit(1);
  }

  int is_stdin = 0;
  int debug = 0;
  __parse_only = getenv("SYMSAN_PARSE_ONLY") != nullptr;
  if (!symsan::sweep::open_cond_log("rgd")) {
    fprintf(stderr, "Cannot open SYMSAN_DUMP_CONDS file: %s\n",
            strerror(errno));
    exit(1);
  }
  __verbose = getenv("SYMSAN_VERBOSE") != nullptr;
  __enum_gep = getenv("SYMSAN_ENUM_GEP") != nullptr;
  __no_output = getenv("SYMSAN_NO_OUTPUT") != nullptr;
  if (const char *only = getenv("SYMSAN_ONLY_CIDS")) {
    for (const char *p = only; *p;) {
      char *end = nullptr;
      unsigned long v = strtoul(p, &end, 0);
      if (end == p) break;
      __only_cids.insert((uint32_t)v);
      p = (*end == ',' || *end == ' ') ? end + 1 : end;
    }
    fprintf(stderr, "solving only %zu cid(s)\n", __only_cids.size());
  }
  char *options = getenv("TAINT_OPTIONS");
  if (options) {
    // setup output dir
    char *output = strstr(options, "output_dir=");
    if (output) {
      output += 11; // skip "output_dir="
      char *end = strchr(output, ':'); // try ':' first, then ' '
      if (end == NULL) end = strchr(output, ' ');
      size_t n = end == NULL? strlen(output) : (size_t)(end - output);
      __output_dir = strndup(output, n);
    }

    // check if input is stdin
    char *taint_file = strstr(options, "taint_file=");
    if (taint_file) {
      taint_file += strlen("taint_file="); // skip "taint_file="
      char *end = strchr(taint_file, ':');
      if (end == NULL) end = strchr(taint_file, ' ');
      size_t n = end == NULL? strlen(taint_file) : (size_t)(end - taint_file);
      if (n == 5 && !strncmp(taint_file, "stdin", 5))
        is_stdin = 1;
    }

    // check for debug
    char *debug_opt = strstr(options, "debug=");
    if (debug_opt) {
      debug_opt += strlen("debug="); // skip "debug="
      if (strncmp(debug_opt, "1", 1) == 0 || strncmp(debug_opt, "true", 4) == 0)
        debug = 1;
    }
  }

  // enable nested solving in the parser?
  bool nested = getenv("SYMSAN_USE_NESTED") != nullptr;

  // The parser's AST size limit, normally 200.  Exposed because "cond folded to
  // constant" conflates two different things: a condition the program itself
  // made constant, and one whose operands were *concretized because the AST was
  // too big* (rgd-parser.cpp:1654 sets `concretize`, and the concrete_ops == 3
  // arm then makes the same rgd::Bool a genuine fold would).  Raising the limit
  // and re-running is the control that separates them -- whatever stops folding
  // was never constant, it was only large.
  // No "unlimited" spelling on purpose: ast_size_cache counts the AST as a
  // *tree*, and on a libpng loop that is billions of nodes, so lifting the cap
  // entirely throws std::length_error out of the arena reserve in ast.h:477.
  // Raise it in steps instead and watch where the folding stops.
  size_t max_ast_size = 200;
  if (const char *m = getenv("SYMSAN_MAX_AST_SIZE")) {
    size_t v = strtoull(m, nullptr, 0);
    if (v) max_ast_size = v;
  }

  // setup launcher
  void *shm_base = symsan_init(program, uniontable_size);
  if (shm_base == (void *)-1) {
    fprintf(stderr, "Failed to map shm: %s\n", strerror(errno));
    exit(1);
  }
  symsan::set_label_info_base(shm_base, uniontable_size);
  // No cap: the point of a sweep is to see the whole dictionary a corpus
  // yields, and deciding what to keep is the front-end's job (see
  // ConcolicConfig::max_tokens).  Only fed when --dump-tokens was given.
  if (__token_file) __tokens.init(shm_base, uniontable_size, SIZE_MAX);

  symsan_set_debug(debug);
  symsan_set_bounds_check(1);
  // The runtime synthesises the UB checks itself, on arithmetic it already
  // traces, and gives them cids in the range reserved below the branch map's
  // base -- so this needs nothing from the target build.  Off by default to
  // match the fuzzer's default and to keep a plain sweep comparable with one.
  symsan_set_solve_ub(getenv("SYMSAN_SOLVE_UB") != nullptr);

  // setup the RGD parser and the solver chain (matching driver/aflpp).  One
  // parser for the whole corpus: restart() per input is what it is for.
  __parser = new rgd::RGDAstParser(shm_base, uniontable_size, nested,
                                   max_ast_size);

  // the simple i2s solver first, unless it is the thing being measured out.
  // Skipped entirely in parse-only mode -- building a JIT or a z3 context we
  // will never call is the cost that mode exists to avoid.
  if (!__parse_only) {
    if (!getenv("SYMSAN_NO_I2S"))
      __solvers.emplace_back(std::make_shared<rgd::I2SSolver>());
    if (getenv("SYMSAN_USE_JIGSAW"))
      __solvers.emplace_back(std::make_shared<rgd::JITSolver>());
    if (getenv("SYMSAN_USE_Z3"))
      __solvers.emplace_back(std::make_shared<rgd::Z3Solver>());
  }

  // More than one input: serve them all from one fork server, which skips
  // execv, dynamic linking and the shadow and union table setup per seed.  That
  // needs a single fixed input path (see sweep.h), so it is only on for a
  // corpus -- a lone input keeps running where it lies, which is what every
  // existing caller and lit test expects.  A stdin target is excluded because
  // its fd has to be wired up per run, which cannot be done from out here.
  const bool many = (argc - first_input > 1);
  if (many && !is_stdin) {
    if (!__staged.open_staging("afltest")) {
      fprintf(stderr, "Failed to create staging file: %s\n", strerror(errno));
      exit(1);
    }
    char *path = (char *)__staged.path();

    std::vector<char *> args;
    const int nargs = build_target_argv(program, path, args);
    if (symsan_set_input(path) != 0 || symsan_set_args(nargs, args.data()) != 0) {
      fprintf(stderr, "Failed to set input\n");
      exit(1);
    }
    // A no-op against a target whose backend has no server: the launcher falls
    // back to exec per run, which still reads the staged file.
    symsan_set_forkserver(1);
  }

  const uint32_t session_base = __session_id;
  int failures = 0;
  for (int i = first_input; i < argc; i++) {
    if (many) {
      // Generated inputs are named id-<instance>-<session>-<index>, so give each
      // seed its own session: without it a corpus run's output is one flat
      // sequence with nothing saying which seed produced what.  Counted from
      // whatever TAINT_OPTIONS asked for, so setting session_id still means
      // something.  __current_index stays monotonic, so nothing collides either
      // way.
      __session_id = session_base + (uint32_t)(i - first_input);
      // per input, so that a corpus run says as much as the same seeds run one
      // at a time; a consumer wanting the total can sum the blocks
      __stats = symsan::sweep::parse_stats();
      if (__parse_only) printf("PARSE-INPUT %s\n", argv[i]);
    }
    // Outside the `many` guard: the per-condition dump is keyed by (input,
    // label), so it needs the input named even for a single seed, where the
    // PARSE-INPUT line above is deliberately not printed.
    if (__parse_only) symsan::sweep::log_cond_input(argv[i]);
    const int rc = run_one(program, argv[i], is_stdin);
    // Labels, not tokens: the dictionary is cumulative over the corpus, which
    // is the whole point of a sweep, but a label only names the same AST within
    // one run of the target.
    //
    // After the run rather than before it, and outside the failure check: the
    // byte-comparison run the target was in the middle of is only complete once
    // it has exited, so flushing at the top of the next iteration would lose
    // the last input's -- and on a single-seed run, lose it entirely.
    if (__token_file) __tokens.end_input();
    if (rc != 0) {
      failures++;
      continue;
    }
    if (__parse_only) {
      // the parser's counter is cumulative over the corpus; the sweep reports
      // per input, so hand it the delta
      static uint64_t weakened_base = 0;
      const uint64_t weakened = __parser->weakened_clauses();
      __stats.cond_weakened = weakened - weakened_base;
      weakened_base = weakened;
      __stats.report();
    }
  }

  // destroy the solvers (and their z3 solver members) here, while the global
  // z3 context in z3-solver.cpp is still alive -- relying on static destruction
  // order across translation units would free the context first and crash.
  __solvers.clear();

  if (__token_file) dump_tokens(__token_file);

  symsan::sweep::close_cond_log();
  symsan_destroy();
  exit(failures ? 1 : 0);
}

