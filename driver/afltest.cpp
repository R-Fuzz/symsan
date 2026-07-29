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
// Usage: afltest target input
//   TAINT_OPTIONS="taint_file=<file|stdin> output_dir=<dir>"
//   SYMSAN_USE_JIGSAW=1  add the jigsaw JIT solver to the chain
//   SYMSAN_USE_Z3=1      add the z3 solver to the chain (needed for FP)
//   SYMSAN_USE_NESTED=1  enable nested constraint solving in the parser
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

#include <memory>
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

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

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
static int __enum_gep = 0;  // GEP enumeration disabled by default

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
  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "%s/id-%d-%d-%d", __output_dir,
           __instance_id, __session_id, __current_index++);
  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    AOUT("failed to open new input file for write\n");
    return;
  }

  AOUT("generate #%d output (size: %zu -> %zu)\n",
       __current_index - 1, input_size, size);

  if (write(fd, buf, size) == -1) {
    AOUT("failed to write new input\n");
  }

  close(fd);
}

// run a solving task through the solver chain; on the first SAT result write
// out the mutated input.  Mirrors the per-solver fall-through in aflpp's
// afl_custom_fuzz (i2s -> jigsaw -> z3), but drives it synchronously.
static void solve_task(rgd::task_t task, void *addr) {
  if (!task) return;
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
    // SOLVER_TIMEOUT / SOLVER_ERROR: fall through to the next solver
  }
  AOUT("task not solved @%p\n", addr);
}

static void __solve_cond(dfsan_label label, uint8_t r, bool add_nested, void *addr) {

  AOUT("solving label %d = %d, add_nested: %d\n", label, r, add_nested);
  std::vector<uint64_t> tasks;
  if (__parser->parse_cond(label, r != 0, add_nested, tasks)) {
    AOUT("WARNING: failed to parse condition %d @%p\n", label, addr);
    return;
  }

  for (auto id : tasks) {
    auto task = __parser->retrieve_task(id);
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
  if (__parser->parse_gep(ptr_label, ptr, index_label, index, num_elems,
                          elem_size, current_offset, __enum_gep, tasks)) {
    AOUT("WARNING: failed to parse gep %d @%p\n", index_label, addr);
    return;
  }

  for (auto id : tasks) {
    auto task = __parser->retrieve_task(id);
    solve_task(task, addr);
  }
}

int main(int argc, char* const argv[]) {

  if (argc != 3) {
    fprintf(stderr, "Usage: %s target input\n", argv[0]);
    exit(1);
  }

  char *program = argv[1];
  char *input = argv[2];

  int is_stdin = 0;
  int debug = 0;
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

  // load input file
  struct stat st;
  int input_fd = open(input, O_RDONLY);
  if (input_fd == -1) {
    fprintf(stderr, "Failed to open input file: %s\n", strerror(errno));
    exit(1);
  }
  fstat(input_fd, &st);
  input_size = st.st_size;
  input_buf = (char *)mmap(NULL, input_size, PROT_READ, MAP_PRIVATE, input_fd, 0);
  if (input_buf == (void *)-1) {
    fprintf(stderr, "Failed to map input file: %s\n", strerror(errno));
    exit(1);
  }

  // allocate the output buffer.  RGD solvers write the full (possibly grown)
  // input; give some headroom for INSERT-style solutions.
  __output_buf_size = input_size + 4096;
  __output_buf = (uint8_t *)malloc(__output_buf_size);
  if (!__output_buf) {
    fprintf(stderr, "Failed to alloc output buffer\n");
    exit(1);
  }

  // setup launcher
  void *shm_base = symsan_init(program, uniontable_size);
  if (shm_base == (void *)-1) {
    fprintf(stderr, "Failed to map shm: %s\n", strerror(errno));
    exit(1);
  }
  symsan::set_label_info_base(shm_base, uniontable_size);

  if (symsan_set_input(is_stdin ? "stdin" : input) != 0) {
    fprintf(stderr, "Failed to set input\n");
    exit(1);
  }

  char* args[3];
  args[0] = program;
  args[1] = input;
  args[2] = NULL;
  if (symsan_set_args(2, args) != 0) {
    fprintf(stderr, "Failed to set args\n");
    exit(1);
  }

  symsan_set_debug(debug);
  symsan_set_bounds_check(1);

  // launch the target
  int ret = symsan_run(input_fd);
  if (ret < 0) {
    fprintf(stderr, "Failed to launch target: %s\n", strerror(errno));
    exit(1);
  } else if (ret > 0) {
    fprintf(stderr, "SymSan launch error %d\n", ret);
    exit(1);
  }
  close(input_fd);

  // setup the RGD parser and the solver chain (matching driver/aflpp)
  __parser = new rgd::RGDAstParser(shm_base, uniontable_size, nested);
  std::vector<symsan::input_t> inputs;
  inputs.push_back({(uint8_t*)input_buf, input_size});
  if (__parser->restart(inputs) != 0) {
    fprintf(stderr, "Failed to restart parser\n");
    exit(1);
  }

  // always use the simple i2s solver first
  __solvers.emplace_back(std::make_shared<rgd::I2SSolver>());
  if (getenv("SYMSAN_USE_JIGSAW"))
    __solvers.emplace_back(std::make_shared<rgd::JITSolver>());
  if (getenv("SYMSAN_USE_Z3"))
    __solvers.emplace_back(std::make_shared<rgd::Z3Solver>());

  pipe_msg msg;
  gep_msg gmsg;
  dfsan_label_info *info;
  size_t msg_size;
  memcmp_msg *mmsg = nullptr;

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
        free(mmsg);
        break;
      case add_constraint_type:
        __parser->add_constraints(msg.label, msg.result);
        break;
      default:
        break;
    }
  }

  // destroy the solvers (and their z3 solver members) here, while the global
  // z3 context in z3-solver.cpp is still alive -- relying on static destruction
  // order across translation units would free the context first and crash.
  __solvers.clear();

  symsan_destroy();
  exit(0);
}
