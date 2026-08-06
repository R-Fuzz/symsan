#include "defs.h"
#include "debug.h"
#include "version.h"

#include "dfsan/dfsan.h"

extern "C" {
#include "launch.h"
}

#include "parse-z3.h"
#include "sweep.h"

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

using namespace __dfsan;

#define OPTIMISTIC 1

// SYMSAN_VERBOSE: the per-event trace.
//
// AOUT fires once per branch, per GEP and per solution byte, which is what you
// want when you are staring at one seed and is unusable the moment fgtest is
// pointed at a corpus -- the 811-seed libpng sweep is millions of lines, and
// writing them costs more than the parse. Off by default; set SYMSAN_VERBOSE
// to get it back, no rebuild needed.
//
// What is *not* under it: the "generate #N output" line, which is a result
// rather than a trace (tests/fuzzing/branch_map_join.c checks for it), and the
// fprintf(stderr) failures, which have no other channel. Rejected parses lose
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

// for input
static char *input_buf;
static size_t input_size;

// for output
static const char* __output_dir = ".";
static uint32_t __instance_id = 0;
static uint32_t __session_id = 0;
static uint32_t __current_index = 0;
// GEP index enumeration, off by default -- which is what ConcolicSession does
// too (it passes enum_index=false unconditionally), so fgtest matches the path
// the fuzzer actually runs.  The comment here used to claim the opposite while
// the initializer said 0, and TAINT_OPTIONS only ever knew how to set it *to*
// 0, so the option could not turn enumeration on and nothing did: on the
// 811-seed libpng corpus all 908543 GEPs took parse_gep's "not enumerable"
// early return.  enum_gep=1 now works, and is the only way to reach that code.
static int __enum_gep = 0;
static z3::context __z3_context;

// z3parser
symsan::Z3ParserSolver *__z3_parser = nullptr;

// SYMSAN_PARSE_ONLY: build the tasks but never solve them.
//
// Solving dominates the wall clock of a trace and is also where most of the
// noise lives, so a sweep meant to answer "which branches does the parser
// refuse, and why" runs an order of magnitude faster -- and produces countable
// output -- with the solvers out of the picture.  What it prints instead is a
// machine-readable summary on exit; see report_parse_stats.  The per-event
// trace is separate and off by default either way -- see SYMSAN_VERBOSE, which
// still works here if you want to read a rejection in context.
static int __parse_only = 0;

namespace {

// The counters, the bucketing and the report now live in driver/sweep.h, so
// that afltest reports the same shape over the same corpus and the two parsers
// can be read side by side.
using symsan::sweep::parse_stats;

parse_stats __stats;

} // namespace

static void generate_input(symsan::Z3ParserSolver::solution_t &solutions) {
  using op_t = symsan::Z3ParserSolver::solution_op_t;

  // Build the new input in memory to handle INSERT/DELETE properly
  std::vector<uint8_t> new_input(input_buf, input_buf + input_size);

  // Sort solutions by offset in descending order so INSERT/DELETE don't
  // invalidate subsequent offsets
  std::vector<size_t> order(solutions.size());
  for (size_t i = 0; i < order.size(); ++i) order[i] = i;
  std::sort(order.begin(), order.end(), [&solutions](size_t a, size_t b) {
    return solutions[a].offset > solutions[b].offset;
  });

  for (size_t idx : order) {
    const auto& sol = solutions[idx];
    switch (sol.op) {
      case op_t::SET:
        if (sol.offset < new_input.size()) {
          AOUT("SET offset %d = %x\n", sol.offset, sol.val);
          new_input[sol.offset] = sol.val;
        }
        break;

      case op_t::INSERT:
        if (sol.offset <= new_input.size()) {
          AOUT("INSERT %zu bytes at offset %d\n", sol.data.size(), sol.offset);
          new_input.insert(new_input.begin() + sol.offset,
                          sol.data.begin(), sol.data.end());
        }
        break;

      case op_t::DELETE:
        if (sol.offset < new_input.size()) {
          size_t del_len = std::min((size_t)sol.len,
                                    new_input.size() - sol.offset);
          AOUT("DELETE %zu bytes at offset %d\n", del_len, sol.offset);
          new_input.erase(new_input.begin() + sol.offset,
                         new_input.begin() + sol.offset + del_len);
        }
        break;
    }
  }

  // Write the new input to file
  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "%s/id-%d-%d-%d", __output_dir,
           __instance_id, __session_id, __current_index++);
  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    ROUT("failed to open new input file for write");
    return;
  }

  ROUT("generate #%d output (size: %zu -> %zu)\n",
       __current_index - 1, input_size, new_input.size());

  if (write(fd, new_input.data(), new_input.size()) == -1) {
    ROUT("failed to write new input\n");
  }

  close(fd);
}

// `cid` is the branch id the trace event carried.  Under the two-stage build it
// is the AFL edge id, which is the only key that joins a parse outcome to the
// fuzzer's coverage map; it is otherwise unused here.
static void __solve_cond(dfsan_label label, uint8_t r, bool add_nested, void *addr,
                         uint32_t cid) {

  AOUT("solving label %d = %d, add_nested: %d\n", label, r, add_nested);
  if (__parse_only && label == 0) {
    // A loop-exit notification, not a condition -- there is no AST to build and
    // no branch to flip, so it is neither a success nor a failure.
    __stats.conds++;
    __stats.loop_exits++;
    return;
  }
  std::vector<uint64_t> tasks;
  int failed = __z3_parser->parse_cond(label, r, add_nested, tasks);
  if (__parse_only) {
    __stats.conds++;
    __stats.cond_tasks += tasks.size();
    __stats.note(failed != 0, tasks.size(), __z3_parser->last_error(), addr,
                 __stats.cond_ok, __stats.cond_empty, __stats.cond_failed, cid);
    // Drop the tasks: retrieve_task hands over ownership, so without this the
    // parser's task table grows for the whole trace.
    for (auto id : tasks) __z3_parser->retrieve_task(id);
    return;
  }
  if (failed) {
    AOUT("WARNING: failed to parse condition %d @%p\n", label, addr);
    return;
  }

  for (auto id : tasks) {
    // solve
    symsan::Z3ParserSolver::solution_t solutions;
    auto status = __z3_parser->solve_task(id, 30000U, solutions);  // 30 seconds
    if (solutions.size() != 0) {
      AOUT("branch solved\n");
      generate_input(solutions);
    } else {
      AOUT("branch not solvable @%p\n", addr);
    }
    solutions.clear();
  }

}

static void __handle_gep(dfsan_label ptr_label, uptr ptr,
                         dfsan_label index_label, int64_t index,
                         uint64_t num_elems, uint64_t elem_size,
                         int64_t current_offset, void* addr) {

  AOUT("tainted GEP index: %ld = %d, ne: %ld, es: %ld, offset: %ld\n",
      index, index_label, num_elems, elem_size, current_offset);

  std::vector<uint64_t> tasks;
  int failed = __z3_parser->parse_gep(ptr_label, ptr, index_label, index, num_elems,
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
      __stats.note(failed != 0, tasks.size(), __z3_parser->last_error(), addr,
                   __stats.gep_ok, __stats.gep_empty, __stats.gep_failed);
    }
    for (auto id : tasks) __z3_parser->retrieve_task(id);
    return;
  }
  if (failed) {
    AOUT("WARNING: failed to parse gep %d @%p\n", index_label, addr);
    return;
  }

  for (auto id : tasks) {
    symsan::Z3ParserSolver::solution_t solutions;
    auto status = __z3_parser->solve_task(id, 30000U, solutions);  // 30 seconds
    if (solutions.size() != 0) {
      AOUT("gep solved\n");
      generate_input(solutions);
    } else {
      AOUT("gep not solvable @%p\n", addr);
    }
    solutions.clear();
  }
}

// Where the target is pointed for every run of a corpus sweep, and the fd we
// keep open on it.  path() is null in the single-input case, which still runs
// the seed where it lies.  See driver/sweep.h for why a corpus needs one fixed
// path whose contents change per seed.
static symsan::sweep::input_stager __staged;

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
      char* args[3];
      args[0] = program;
      args[1] = input;
      args[2] = NULL;
      if (symsan_set_args(2, args) != 0) {
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
    if (__z3_parser->restart(inputs) != 0) {
      fprintf(stderr, "Failed to restart parser\n");
      goto fail;
    }

    pipe_msg msg;
    gep_msg gmsg;
    size_t msg_size;
    memcmp_msg *mmsg = nullptr;
    table_msg *tmsg = nullptr;

    while (symsan_read_event(&msg, sizeof(msg), 0) > 0) {
      // Every message type, not just the ones that parse: this is the "did the
      // target trace anything at all" number, and a sweep that cannot separate
      // that from "the parser accepted everything" is unreadable.
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
          // flags = 0 means both operands are symbolic thus no content to read
          if (!msg.flags)
            break;
          msg_size = sizeof(memcmp_msg) + msg.result;
          mmsg = (memcmp_msg*)malloc(msg_size); // not freed until terminate
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
          __z3_parser->record_memcmp(msg.label, mmsg->content, msg.result);
          free(mmsg);
          break;
        case table_type:
          // The z3 backend declines tlookup, so the contents go unused here --
          // but the payload must still be drained or the rest of the stream is
          // misparsed.  Recorded anyway, so that a future z3 implementation only
          // has to touch the solver.
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
          __z3_parser->record_table(tmsg->ptr, tmsg->content, msg.result);
          free(tmsg);
          break;
        case add_constraint_type:
          if (__z3_parser->add_constraints(msg.label, msg.result) != 0) {
            fprintf(stderr, "Failed to add constraint %d = %lu @%p\n",
                    msg.label, msg.result, (void*)msg.addr);
          }
          break;
        case minimize_type:
          __z3_parser->record_minimize(msg.label);
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

// Does a TAINT_OPTIONS value start with `want` and end there?  Options are
// separated by ':' or ' ', so a value runs to the first of either, and a plain
// strcmp() against the rest of the string would only ever match the last one.
static bool opt_is(const char *val, const char *want) {
  size_t n = strlen(want);
  return strncmp(val, want, n) == 0 &&
         (val[n] == '\0' || val[n] == ':' || val[n] == ' ');
}

int main(int argc, char* const argv[]) {

  if (argc < 3) {
    fprintf(stderr, "Usage: %s target input [input...]\n", argv[0]);
    exit(1);
  }

  char *program = argv[1];

  // A target that cannot be exec'd is not an error anywhere below: the launcher
  // forks, execv fails in the child, and every read comes back empty -- so the
  // run reports zero events and exits 0, which over a corpus reads exactly like
  // a target that parses cleanly.  Say so here instead.
  if (access(program, X_OK) != 0) {
    fprintf(stderr, "Cannot execute %s: %s\n", program, strerror(errno));
    exit(1);
  }

  int is_stdin = 0;
  int solve_ub = 0;
  int debug = 0;
  __parse_only = getenv("SYMSAN_PARSE_ONLY") != nullptr;
  __verbose = getenv("SYMSAN_VERBOSE") != nullptr;
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
      // Terminated at the separator, like output_dir= and taint_file= above:
      // strcmp() here would run to the end of the whole option string, so
      // debug= would be honoured only when nothing followed it -- and be
      // silently ignored anywhere else in the line.
      if (opt_is(debug_opt, "1") || opt_is(debug_opt, "true"))
        debug = 1;
    }

    // check for session_id
    char *session_opt = strstr(options, "session_id=");
    if (session_opt) {
      session_opt += strlen("session_id=");
      __session_id = atoi(session_opt);
    }

    // check if solve_ub is enabled
    char *solve_ub_opt = strstr(options, "solve_ub=");
    if (solve_ub_opt) {
      solve_ub_opt += strlen("solve_ub="); // skip "solve_ub="
      // see the note on debug= above
      if (opt_is(solve_ub_opt, "1") || opt_is(solve_ub_opt, "true"))
        solve_ub = 1;
    }

    // check if GEP enumeration is enabled or disabled
    char *enum_gep_opt = strstr(options, "enum_gep=");
    if (enum_gep_opt) {
      enum_gep_opt += strlen("enum_gep="); // skip "enum_gep="
      if (strncmp(enum_gep_opt, "0", 1) == 0 || strncmp(enum_gep_opt, "false", 5) == 0)
        __enum_gep = 0;
      else if (strncmp(enum_gep_opt, "1", 1) == 0 || strncmp(enum_gep_opt, "true", 4) == 0)
        __enum_gep = 1;
    }
  }

  // setup launcher
  void *shm_base = symsan_init(program, uniontable_size);
  if (shm_base == (void *)-1) {
    fprintf(stderr, "Failed to map shm: %s\n", strerror(errno));
    exit(1);
  }

  symsan_set_debug(debug);
  symsan_set_bounds_check(1);
  symsan_set_solve_ub(solve_ub);

  // setup z3 parser.  One parser for the whole corpus: restart() per input is
  // what it is for, and rebuilding it would throw away nothing worth keeping
  // but cost a z3 context teardown per seed.
  __z3_parser = new symsan::Z3ParserSolver(shm_base, uniontable_size, __z3_context);

  // More than one input: serve them all from one fork server, which skips
  // execv, dynamic linking and the shadow and union table setup per seed.  That
  // needs a single fixed input path (see __staged.path()), so it is only on for a
  // corpus -- a lone input keeps running where it lies, which is what every
  // existing caller and lit test expects.  A stdin target is excluded because
  // its fd has to be wired up per run, which cannot be done from out here.
  const bool many = (argc > 3);
  if (many && !is_stdin) {
    if (!__staged.open_staging("fgtest")) {
      fprintf(stderr, "Failed to create staging file: %s\n", strerror(errno));
      exit(1);
    }
    char *path = (char *)__staged.path();

    char *args[3];
    args[0] = program;
    args[1] = path;
    args[2] = NULL;
    if (symsan_set_input(path) != 0 || symsan_set_args(2, args) != 0) {
      fprintf(stderr, "Failed to set input\n");
      exit(1);
    }
    // A no-op against a target whose backend has no server: the launcher falls
    // back to exec per run, which still reads the staged file.
    symsan_set_forkserver(1);
  }

  const uint32_t session_base = __session_id;
  int failures = 0;
  for (int i = 2; i < argc; i++) {
    if (many) {
      // Generated inputs are named id-<instance>-<session>-<index>, so give each
      // seed its own session: without it a corpus run's output is one flat
      // sequence with nothing saying which seed produced what.  Counted from
      // whatever TAINT_OPTIONS asked for, so setting session_id still means
      // something.  __current_index stays monotonic, so nothing collides either
      // way.
      __session_id = session_base + (uint32_t)(i - 2);
      // per input, so that a corpus run says as much as the same seeds run one
      // at a time; a consumer wanting the total can sum the blocks
      __stats = parse_stats();
      if (__parse_only) printf("PARSE-INPUT %s\n", argv[i]);
    }
    if (run_one(program, argv[i], is_stdin) != 0) {
      failures++;
      continue;
    }
    if (__parse_only) __stats.report();
  }

  symsan_destroy();
  exit(failures ? 1 : 0);
}

