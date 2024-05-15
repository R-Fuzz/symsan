/*
  a custom mutator for AFL++
  (c) 2023 - 2024 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#include "dfsan/dfsan.h"

#include "ast.h"
#include "task.h"
#include "solver.h"
#include "cov.h"
#include "task_mgr.h"

extern "C" {
#include "afl-fuzz.h"
#include "launch.h"
}

#include "parse-rgd.h"

#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <queue>
#include <memory>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

using namespace __dfsan;

#ifndef DEBUG
#define DEBUG 0
#endif

#if !DEBUG
#undef DEBUGF
#define DEBUGF(_str...) do { } while (0)
#endif

#define PRINT_STATS 0

#define MAX_AST_SIZE 200

#define MIN_TIMEOUT 50U

#define MAX_LOCAL_BRANCH_COUNTER 128

static bool NestedSolving = false;
static int TraceBounds = 0;

#undef alloc_printf
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = (char*)ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

using solver_t = std::shared_ptr<rgd::Solver>;
using branch_ctx_t = std::shared_ptr<rgd::BranchContext>;

enum mutation_state_t {
  MUTATION_INVALID,
  MUTATION_IN_VALIDATION,
  MUTATION_VALIDATED,
};

struct my_mutator_t {
  my_mutator_t() = delete;
  my_mutator_t(const afl_state_t *afl, rgd::TaskManager* tmgr, rgd::CovManager* cmgr) :
    afl(afl), out_dir(NULL), out_file(NULL), symsan_bin(NULL),
    argv(NULL), out_fd(-1), cur_queue_entry(NULL),
    cur_mutation_state(MUTATION_INVALID), output_buf(NULL),
    cur_task(nullptr), cur_solver_index(-1),
    task_mgr(tmgr), cov_mgr(cmgr) {}

  ~my_mutator_t() {
    if (out_fd >= 0) close(out_fd);
    ck_free(out_dir);
    ck_free(out_file);
    ck_free(output_buf);
    ck_free(argv);
    delete task_mgr;
    delete cov_mgr;
  }

  const afl_state_t *afl;
  char *out_dir;
  char *out_file;
  char *symsan_bin;
  char **argv;
  int out_fd;
  u8* cur_queue_entry;
  int cur_mutation_state;
  u8* output_buf;
  int log_fd;

  std::unordered_set<u32> fuzzed_inputs;
  rgd::TaskManager* task_mgr;
  rgd::CovManager* cov_mgr;
  rgd::RGDAstParser* parser;
  std::vector<solver_t> solvers;

  // XXX: well, we have to keep track of solving states
  rgd::task_t cur_task;
  size_t cur_solver_index;
};

// FIXME: find another way to make the union table hash work
static dfsan_label_info *__dfsan_label_info;
static const size_t MAX_LABEL = uniontable_size / sizeof(dfsan_label_info);

dfsan_label_info* __dfsan::get_label_info(dfsan_label label) {
  if (unlikely(label >= MAX_LABEL)) {
    throw std::out_of_range("label too large " + std::to_string(label));
  }
  return &__dfsan_label_info[label];
}

// FIXME: local filter?
static std::unordered_map<uint32_t, uint8_t> local_counter;
// staticstics
static uint64_t total_branches = 0;
static uint64_t branches_to_solve = 0;
static uint64_t total_tasks = 0;
static std::map<uint64_t, uint64_t> task_size_dist;
static uint64_t solved_tasks = 0;
static uint64_t solved_branches = 0;

static void reset_global_caches(size_t buf_size) {
  local_counter.clear();
}

static void handle_cond(pipe_msg &msg, const u8 *buf, size_t buf_size,
                        my_mutator_t *my_mutator) {
  if (unlikely(msg.label == 0)) {
    return;
  } else if (unlikely(msg.label == kInitializingLabel)) {
    WARNF("UBI branch cond @%p\n", (void*)msg.addr);
    return;
  }

  total_branches += 1;

  // apply a local (per input) branch filter
  auto &lc = local_counter[msg.id];
  if (lc > MAX_LOCAL_BRANCH_COUNTER) {
    return;
  } else {
    lc += 1;
  }

  const branch_ctx_t ctx = my_mutator->cov_mgr->add_branch((void*)msg.addr,
      msg.id, msg.result != 0, msg.context, false, false);

  branch_ctx_t neg_ctx = std::make_shared<rgd::BranchContext>();
  *neg_ctx = *ctx;
  neg_ctx->direction = !ctx->direction;

  if (my_mutator->cov_mgr->is_branch_interesting(neg_ctx)) {
    // parse the uniont table AST to solving tasks
    std::vector<uint64_t> tasks;
    if (my_mutator->parser->parse_cond(msg.label, ctx->direction, msg.flags & F_ADD_CONS, tasks) != 0) {
      WARNF("Failed to parse the condition\n");
      symsan_terminate();
    }
    // construct_tasks(neg_ctx->direction, msg.label, buf, buf_size, tasks);

    // add the tasks to the task manager
    for (auto const& task_id : tasks) {
      auto task = my_mutator->parser->retrieve_task(task_id);
      my_mutator->task_mgr->add_task(neg_ctx, task);
#if PRINT_STATS
      task_size_dist[task->constraints.size()] += 1;
#endif
    }

    total_tasks += tasks.size();
    branches_to_solve += 1;
  }
}

static void handle_gep(gep_msg &gmsg, pipe_msg &msg) {
}

/// no splice input
extern "C" void afl_custom_splice_optout(my_mutator_t *data) {
  (void)(data);
}

/// @brief init the custom mutator
/// @param afl aflpp state
/// @param seed not used
/// @return custom mutator state
extern "C" my_mutator_t *afl_custom_init(afl_state *afl, unsigned int seed) {

  (void)(seed);

  struct stat st;
  rgd::TaskManager *tmgr = new rgd::FIFOTaskManager();
  rgd::CovManager *cmgr = new rgd::EdgeCovManager();
  my_mutator_t *data = new my_mutator_t(afl, tmgr, cmgr);
  if (!data) {
    FATAL("afl_custom_init alloc");
    return NULL;
  }
  // always use the simpler i2s solver
  data->solvers.emplace_back(std::make_shared<rgd::I2SSolver>());
  if (getenv("SYMSAN_USE_JIGSAW"))
    data->solvers.emplace_back(std::make_shared<rgd::JITSolver>());
  if (getenv("SYMSAN_USE_Z3"))
    data->solvers.emplace_back(std::make_shared<rgd::Z3Solver>());
  // make nested solving optional too
  if (getenv("SYMSAN_USE_NESTED")) {
    NestedSolving = true;
  }
  // enable trace bounds?
  if (getenv("SYMSAN_TRACE_BOUNDS")) {
    TraceBounds = 1;
  }

  if (!(data->symsan_bin = getenv("SYMSAN_TARGET"))) {
    FATAL(
        "SYMSAN_TARGET not defined, this should point to the full path of the "
        "symsan compiled binary.");
  }

  if (!(data->out_dir = getenv("SYMSAN_OUTPUT_DIR"))) {
    data->out_dir = alloc_printf("%s/symsan", afl->out_dir);
  }

  if (stat(data->out_dir, &st) && mkdir(data->out_dir, 0755)) {
    PFATAL("Could not create the output directory %s", data->out_dir);
  }

  // setup output file
  char *out_file;
  if (afl->file_extension) {
    out_file = alloc_printf("%s/.cur_input.%s", data->out_dir, afl->file_extension);
  } else {
    out_file = alloc_printf("%s/.cur_input", data->out_dir);
  }
  if (data->out_dir[0] == '/') {
    data->out_file = out_file;
  } else {
    char cwd[PATH_MAX];
    if (getcwd(cwd, (size_t)sizeof(cwd)) == NULL) { PFATAL("getcwd() failed"); }
    data->out_file = alloc_printf("%s/%s", cwd, out_file);
    ck_free(out_file);
  }

  // create the output file
  data->out_fd = open(data->out_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (data->out_fd < 0) {
    PFATAL("Failed to create output file %s: %s\n", data->out_file, strerror(errno));
  }

  // setup symsan launcher
  __dfsan_label_info = (dfsan_label_info *)symsan_init(data->symsan_bin, uniontable_size);
  if (__dfsan_label_info == (void *)-1) {
    FATAL("Failed to init symsan launcher: %s\n", strerror(errno));
  }

  // setup the parser
  data->parser = new rgd::RGDAstParser(__dfsan_label_info, uniontable_size, NestedSolving, MAX_AST_SIZE);
  if (!data->parser) {
    FATAL("Failed to create parser\n");
  }

  // allocate output buffer
  data->output_buf = (u8 *)malloc(MAX_FILE+1);
  if (!data->output_buf) {
    FATAL("Failed to alloc output buffer\n");
  }

#if PRINT_STATS
  char *log_f = getenv("SYMSAN_LOG_FILE");
  if (log_f) {
    data->log_fd = open(log_f, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (data->log_fd < 0) {
      PFATAL("Failed to create log file: %s\n", strerror(errno));
    }
  } else {
    data->log_fd = 2; // stderr by default
  }
#endif

  return data;
}

extern "C" void afl_custom_deinit(my_mutator_t *data) {
  symsan_destroy();
  delete data;
}

/// @brief the trace stage for symsan
/// @param data the custom mutator state
/// @param buf input buffer
/// @param buf_size
/// @return the number of solving tasks
extern "C" u32 afl_custom_fuzz_count(my_mutator_t *data, const u8 *buf,
                                     size_t buf_size) {

  // check the input id to see if it's been run before
  // we don't use the afl_custom_queue_new_entry() because we may not
  // want to solve all the tasks
  u32 input_id = data->afl->queue_cur->id;
  u32 timeout = std::min(MIN_TIMEOUT, data->afl->fsrv.exec_tmout);
  if (data->fuzzed_inputs.find(input_id) != data->fuzzed_inputs.end()) {
    return 0;
  }
  data->fuzzed_inputs.insert(input_id);

  // record the name of the current queue entry
  data->cur_queue_entry = data->afl->queue_cur->fname;
  DEBUGF("Fuzzing %s\n", data->cur_queue_entry);

  // FIXME: should we use the afl->queue_cur->fname instead?
  // write the buf to the file
  lseek(data->out_fd, 0, SEEK_SET);
  ck_write(data->out_fd, buf, buf_size, data->out_file);
  fsync(data->out_fd);
  if (ftruncate(data->out_fd, buf_size)) {
    WARNF("Failed to truncate output file: %s\n", strerror(errno));
    return 0;
  }

  // setup argv in case of initialized
  if (unlikely(!data->argv)) {
    int argc = 0;
    while (data->afl->argv[argc]) { argc++; }
    data->argv = (char **)calloc(argc + 1, sizeof(char *));
    if (!data->argv) {
      FATAL("Failed to alloc argv\n");
    }
    for (int i = 0; i < argc; i++) {
      if (strstr(data->afl->argv[i], (char*)data->afl->tmp_dir)) {
        DEBUGF("Replacing %s with %s\n", data->afl->argv[i], data->out_file);
        data->argv[i] = data->out_file;
      } else {
        data->argv[i] = data->afl->argv[i];
      }
    }
    data->argv[argc] = NULL;
    // setup symsan launcher
    symsan_set_input(data->afl->fsrv.use_stdin ? "stdin" : data->out_file);
    symsan_set_args(argc, data->argv);
    symsan_set_debug(DEBUG);
    symsan_set_bounds_check(TraceBounds);
  }

  // launch the symsan child process
  int ret = symsan_run(data->out_fd);
  if (ret < 0) {
    WARNF("Failed to start symsan bin: %s\n", strerror(errno));
    return 0;
  } else if (ret > 0) {
    WARNF("symsan_run failed %d\n", ret);
    return 0;
  }

  pipe_msg msg;
  gep_msg gmsg;
  memcmp_msg *mmsg;
  dfsan_label_info *info;
  size_t msg_size;
  u32 num_tasks = 0;
  u32 num_msgs = 0;
  bool timedout = false;
  struct timeval start, end;
  gettimeofday(&start, NULL);

  // clear all caches
  std::vector<symsan::input_t> inputs;
  inputs.push_back({buf, buf_size});
  data->parser->restart(inputs);
  reset_global_caches(buf_size);

  while (symsan_read_event(&msg, sizeof(msg), timeout) == sizeof(msg)) {
    // create solving tasks
    switch (msg.msg_type) {
      // conditional branch
      case cond_type:
        handle_cond(msg, buf, buf_size, data);
        break;
      case gep_type:
        if (symsan_read_event(&gmsg, sizeof(gmsg), 0) != sizeof(gmsg)) {
          WARNF("Failed to receive gep msg: %s\n", strerror(errno));
          break;
        }
        // double check
        if (msg.label != gmsg.index_label) {
          WARNF("Incorrect gep msg: %d vs %d\n", msg.label, gmsg.index_label);
          break;
        }
        handle_gep(gmsg, msg);
        break;
      case memcmp_type:
        if (msg.label == 0 || msg.label >= MAX_LABEL) {
          WARNF("Invalid memcmp label: %d\n", msg.label);
          break;
        }
        info = get_label_info(msg.label);
        // if both operands are symbolic, no content to be read
        if (info->l1 != CONST_LABEL && info->l2 != CONST_LABEL)
          break;
        // flags = 0 means both operands are symbolic thus no content to read
        // if (!msg.flags)
        //  break;
        msg_size = sizeof(memcmp_msg) + msg.result;
        mmsg = (memcmp_msg*)malloc(msg_size);
        if (symsan_read_event(mmsg, msg_size, 0) != msg_size) {
          WARNF("Failed to receive memcmp msg: %s\n", strerror(errno));
          free(mmsg);
          break;
        }
        // double check
        if (msg.label != mmsg->label) {
          WARNF("Incorrect memcmp msg: %d vs %d\n", msg.label, mmsg->label);
          free(mmsg);
          break;
        }
        // save the content
        data->parser->record_memcmp(msg.label, mmsg->content, msg.result);
        free(mmsg);
        break;
      case fsize_type:
        break;
      case memerr_type:
        WARNF("Memory error detected @%p, type = %d\n", (void*)msg.addr, msg.flags);
        break;
      default:
        break;
    }
    // naive deadloop detection
    num_msgs += 1;
    if (unlikely((num_msgs & 0xffffe000) != 0)) {
      gettimeofday(&end, NULL);
      if ((end.tv_sec - start.tv_sec) * 10 > timeout) {
        // allow 100x slowdown, sec * 1000 > ms * 100
        WARNF("Possible deadloop, break\n");
        timedout = true;
        break;
      }
    }
  }

  if (timedout) {
    // kill the symsan process
    symsan_terminate();
  }

  // reinit solving state
  data->cur_task = nullptr;

  size_t max_stages = data->solvers.size();
  // to be conservative, we return the maximum number of possible mutations
  return (u32)(data->task_mgr->get_num_tasks() * max_stages);

}

static void print_stats(my_mutator_t *data) {
  dprintf(data->log_fd,
    "Total branches: %zu,\n"\
    "Total tasks: %zu,\n"\
    "Solved tasks: %zu,\n"\
    "Solved branches: %zu\n",
    total_branches, total_tasks, solved_tasks, solved_branches);
  dprintf(data->log_fd, "Task size distribution:\n");
  for (auto const& kv : task_size_dist) {
    dprintf(data->log_fd, "\t %zu: %zu\n", kv.first, kv.second);
  }
  for (auto &solver : data->solvers) {
    solver->print_stats(data->log_fd);
  }
}

extern "C"
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  (void)(add_buf);
  (void)(add_buf_size);
  (void)(max_size);
  if (buf_size > MAX_FILE) {
    *out_buf = buf;
    return 0;
  }

  // try to get a task if we don't already have one
  // or if we've find a valid solution from the previous mutation
  if (!data->cur_task || data->cur_mutation_state == MUTATION_VALIDATED) {
    data->cur_task = data->task_mgr->get_next_task();
    if (!data->cur_task) {
      DEBUGF("No more tasks to solve\n");
      data->cur_mutation_state = MUTATION_INVALID;
      *out_buf = buf;
#if PRINT_STATS
      print_stats(data);
#endif
      return 0;
    }
    // reset the solver and state
    data->cur_solver_index = 0;
    data->cur_mutation_state = MUTATION_INVALID;
  }

  // check the previous mutation state
  if (data->cur_mutation_state == MUTATION_IN_VALIDATION) {
    // oops, not solve, move on to next solver
    data->cur_solver_index++;
    if (data->cur_solver_index >= data->solvers.size()) {
      // if reached the max solver, move on to the next task
      data->cur_task = data->task_mgr->get_next_task();
      if (!data->cur_task) {
        DEBUGF("No more tasks to solve\n");
        data->cur_mutation_state = MUTATION_INVALID;
        *out_buf = buf;
#if PRINT_STATS
        print_stats(data);
#endif
        return 0;
      }
      data->cur_solver_index = 0; // reset solver index
    }
  }

  // default return values
  size_t new_buf_size = 0;
  *out_buf = buf;
  auto &solver = data->solvers[data->cur_solver_index];
  auto ret = solver->solve(data->cur_task, buf, buf_size,
      data->output_buf, new_buf_size);
  if (likely(ret == rgd::SOLVER_SAT)) {
    DEBUGF("task solved\n");
    data->cur_mutation_state = MUTATION_IN_VALIDATION;
    *out_buf = data->output_buf;
    solved_tasks += 1;
  } else if (ret == rgd::SOLVER_TIMEOUT) {
    // if not solved, move on to next stage
    data->cur_mutation_state = MUTATION_IN_VALIDATION;
  } else if (ret == rgd::SOLVER_UNSAT) {
    // at any stage if the task is deemed unsolvable, just skip it
    DEBUGF("task not solvable\n");
    data->cur_task->skip_next = true;
    data->cur_task = nullptr;
  } else {
    WARNF("Unknown solver return value %d\n", ret);
    *out_buf = NULL;
    new_buf_size = 0;
  }

  return new_buf_size;
}


// FIXME: use new queue entry as feedback to see if the last mutation is successful
extern "C"
uint8_t afl_custom_queue_new_entry(my_mutator_t * data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {
  // if we're in validation state and the current queue entry is the same as
  // mark the constraints as solved
  DEBUGF("new queue entry: %s\n", filename_new_queue);
  if (data->cur_queue_entry == filename_orig_queue &&
      data->cur_mutation_state == MUTATION_IN_VALIDATION) {
    data->cur_mutation_state = MUTATION_VALIDATED;
    if (data->cur_task) {
      data->cur_task->skip_next = true;
      solved_branches += 1;
    }
  }
  return 0;
}
