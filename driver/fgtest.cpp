#include "defs.h"
#include "debug.h"
#include "version.h"

#include "dfsan/dfsan.h"

extern "C" {
#include "launch.h"
}

#include "parse-z3.h"

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

#undef AOUT
# define AOUT(...)                                      \
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
// output -- with the solvers out of the picture.  The per-event chatter goes
// too, replaced by a machine-readable summary on exit; see report_parse_stats.
static int __parse_only = 0;

namespace {

struct parse_stats {
  uint64_t conds = 0;         // cond messages seen
  uint64_t cond_tasks = 0;    // tasks the parser built from them
  uint64_t cond_ok = 0;       // parsed, at least one task
  uint64_t cond_empty = 0;    // parsed, no task -- a silent drop
  uint64_t cond_failed = 0;   // parse_cond returned -1
  // Loop-exit notifications carrying no condition.  The runtime forwards a
  // cond message with label 0 when a loop leaves by a concrete test (see
  // __taint_trace_cond), because the backend wants to know the loop ended even
  // though there is nothing to solve.  Counting those as parse failures put
  // 38600 phantom "invalid label" rejections in the first sweep, all of them at
  // loop latches, so they get their own line rather than a reason bucket.
  uint64_t loop_exits = 0;
  uint64_t geps = 0;
  uint64_t gep_tasks = 0;
  uint64_t gep_ok = 0;
  uint64_t gep_empty = 0;
  uint64_t gep_failed = 0;
  // GEPs parse_gep declined on the strength of enum_index alone.  Its own line
  // rather than a reason bucket, because the answer is the same for every GEP
  // in the trace and it is our own argument coming back: with enum_gep=0 it is
  // simply the whole gep count, and the reason histogram would say nothing
  // except that we passed 0.  Kept as a count so that a run still reports how
  // many GEPs it walked past.
  uint64_t gep_skipped = 0;
  // Why a GEP was not enumerable, by the shape of what the runtime sent: the
  // parser needs either an array extent (num_elems) or a bounds label on the
  // pointer, and "neither" is a different problem from "the index would not
  // parse".  Indexed by (num_elems != 0) * 2 + (ptr_label != 0).
  uint64_t gep_shape[4] = {0, 0, 0, 0};
  // reason -> count, over both the -1 returns and the parsed-but-empty ones.
  // Ordered so that two runs of the sweep diff cleanly.
  std::map<std::string, uint64_t> reasons;
  // (call site, reason) -> count.  A whole-corpus reason histogram says what the
  // parser refuses but not where, and "where" is what decides whether a
  // rejection is a parser bug or a property of the target -- a mismatch under an
  // uninstrumented library looks exactly like one under a broken AST until the
  // address is symbolized.  The site is the runtime return address the trace
  // event carried; the binary is non-PIE, so addr2line resolves it directly.
  std::map<std::pair<uint64_t, std::string>, uint64_t> sites;
};

parse_stats __stats;

// Attribute one parse. `reason` is the parser's own account of why it stopped;
// an empty one on an empty result means the parser had nothing to say, which is
// itself worth a bucket rather than being silently dropped.
void note_parse(bool failed, size_t produced, const std::string &reason,
                void *addr, uint64_t &ok, uint64_t &empty, uint64_t &fail) {
  const char *bucket = nullptr;
  if (failed) {
    fail++;
    bucket = reason.empty() ? "(unreported)" : reason.c_str();
  } else if (produced == 0) {
    empty++;
    bucket = reason.empty() ? "(no task, unreported)" : reason.c_str();
  } else {
    ok++;
    return;
  }
  __stats.reasons[bucket]++;
  __stats.sites[{(uint64_t)addr, bucket}]++;
}

void report_parse_stats() {
  const auto &s = __stats;
  printf("PARSE-SUMMARY conds=%lu ok=%lu empty=%lu failed=%lu tasks=%lu loop_exits=%lu\n",
         s.conds, s.cond_ok, s.cond_empty, s.cond_failed, s.cond_tasks,
         s.loop_exits);
  printf("PARSE-SUMMARY geps=%lu ok=%lu empty=%lu failed=%lu tasks=%lu skipped=%lu\n",
         s.geps, s.gep_ok, s.gep_empty, s.gep_failed, s.gep_tasks,
         s.gep_skipped);
  printf("PARSE-GEPSHAPE none=%lu ptr_only=%lu elems_only=%lu both=%lu\n",
         s.gep_shape[0], s.gep_shape[1], s.gep_shape[2], s.gep_shape[3]);
  for (const auto &kv : s.reasons) {
    printf("PARSE-REASON %lu\t%s\n", kv.second, kv.first.c_str());
  }
  for (const auto &kv : s.sites) {
    printf("PARSE-SITE %lu\t0x%lx\t%s\n", kv.second, kv.first.first,
           kv.first.second.c_str());
  }
}

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
    AOUT("failed to open new input file for write");
    return;
  }

  AOUT("generate #%d output (size: %zu -> %zu)\n",
       __current_index - 1, input_size, new_input.size());

  if (write(fd, new_input.data(), new_input.size()) == -1) {
    AOUT("failed to write new input\n");
  }

  close(fd);
}

static void __solve_cond(dfsan_label label, uint8_t r, bool add_nested, void *addr) {

  if (!__parse_only)
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
    note_parse(failed != 0, tasks.size(), __z3_parser->last_error(), addr,
               __stats.cond_ok, __stats.cond_empty, __stats.cond_failed);
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

  if (!__parse_only)
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
      note_parse(failed != 0, tasks.size(), __z3_parser->last_error(), addr,
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
// keep open on it.  Null in the single-input case, which still runs the seed
// where it lies.
//
// A fork server can only be told the input path once -- the launcher bakes it
// into the server's environment at spawn time, and every forked child re-reads
// that same path -- so serving a corpus means one fixed path whose *contents*
// change per seed.  That is what AFL does, and the reason the file lives in
// /dev/shm: it is rewritten once per seed and read once per seed, and there is
// no reason for any of that to reach a disk.
static const char *__staged_path = nullptr;
static int __staged_fd = -1;

static void staged_cleanup(void) {
  if (__staged_fd != -1) close(__staged_fd);
  if (__staged_path) unlink(__staged_path);
}

// Point the fixed input file at this seed's bytes.  Truncate first: a short
// seed after a long one would otherwise be read with the tail of its
// predecessor still attached.
static int stage_bytes(const char *buf, size_t size) {
  if (ftruncate(__staged_fd, 0) != 0) return -1;
  size_t done = 0;
  while (done < size) {
    ssize_t w = pwrite(__staged_fd, buf + done, size - done, done);
    if (w > 0) done += (size_t)w;
    else if (w < 0 && errno == EINTR) continue;
    else return -1;
  }
  if (lseek(__staged_fd, 0, SEEK_SET) == (off_t)-1) return -1;
  return 0;
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

  if (__staged_path) {
    // input path and args were set once, before the server was spawned; only
    // the contents change
    if (stage_bytes(input_buf, input_size) != 0) {
      fprintf(stderr, "Failed to stage %s: %s\n", input, strerror(errno));
      goto fail;
    }
    close(input_fd);
    input_fd = __staged_fd;
  } else if (symsan_set_input(is_stdin ? "stdin" : input) != 0) {
    fprintf(stderr, "Failed to set input\n");
    goto fail;
  }

  {
    if (!__staged_path) {
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
    if (input_fd != __staged_fd) close(input_fd);
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
      // solve constraints
      switch (msg.msg_type) {
        case cond_type:
          __solve_cond(msg.label, msg.result, msg.flags & F_ADD_CONS, (void*)msg.addr);
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
  if (input_fd != -1 && input_fd != __staged_fd) close(input_fd);
  return -1;
}

int main(int argc, char* const argv[]) {

  if (argc < 3) {
    fprintf(stderr, "Usage: %s target input [input...]\n", argv[0]);
    exit(1);
  }

  char *program = argv[1];

  int is_stdin = 0;
  int solve_ub = 0;
  int debug = 0;
  __parse_only = getenv("SYMSAN_PARSE_ONLY") != nullptr;
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
      if (strcmp(debug_opt, "1") == 0 || strcmp(debug_opt, "true") == 0)
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
      if (strcmp(solve_ub_opt, "1") == 0 || strcmp(solve_ub_opt, "true") == 0)
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
  // needs a single fixed input path (see __staged_path), so it is only on for a
  // corpus -- a lone input keeps running where it lies, which is what every
  // existing caller and lit test expects.  A stdin target is excluded because
  // its fd has to be wired up per run, which cannot be done from out here.
  const bool many = (argc > 3);
  if (many && !is_stdin) {
    static char path[PATH_MAX];
    // /dev/shm if it will have us, since this is written and read once per seed
    // and never needs to survive the process
    const char *dirs[] = {"/dev/shm", getenv("TMPDIR"), "/tmp"};
    for (const char *dir : dirs) {
      if (!dir) continue;
      snprintf(path, sizeof(path), "%s/fgtest-%d.input", dir, getpid());
      __staged_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
      if (__staged_fd != -1) break;
    }
    if (__staged_fd == -1) {
      fprintf(stderr, "Failed to create staging file: %s\n", strerror(errno));
      exit(1);
    }
    __staged_path = path;
    atexit(staged_cleanup);

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
    if (__parse_only) report_parse_stats();
  }

  symsan_destroy();
  exit(failures ? 1 : 0);
}

