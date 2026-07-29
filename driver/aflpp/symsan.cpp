/*
  a custom mutator for AFL++

  All the concolic-execution logic lives in rgd::ConcolicSession
  (driver/session/concolic-session.cpp), shared with the other front-ends.
  What is left here is the AFL++ glue: the afl_custom_* entry points, the
  output-file plumbing, and translating AFL++'s queue callbacks into the
  session's solved/unsolved feedback.

  (c) 2023 - 2024 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#include "concolic.h"

extern "C" {
#include "afl-fuzz.h"
}

#include <memory>
#include <unordered_set>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if !DEBUG
#undef DEBUGF
#define DEBUGF(_str...) do { } while (0)
#endif

#define PRINT_STATS 0

#define MIN_TIMEOUT 50U

#undef alloc_printf
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = (char*)ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

struct my_mutator_t {
  my_mutator_t() = delete;
  my_mutator_t(const afl_state_t *afl) :
    afl(afl), out_dir(NULL), out_file(NULL), cur_queue_entry(NULL),
    log_fd(2), session_started(false) {}

  ~my_mutator_t() {
    ck_free(out_dir);
    ck_free(out_file);
  }

  const afl_state_t *afl;
  char *out_dir;
  char *out_file;
  u8* cur_queue_entry;
  int log_fd;

  /// the session cannot be started until we know afl->argv, which is not
  /// available in afl_custom_init, so it is deferred to the first trace
  bool session_started;
  rgd::ConcolicConfig config;
  rgd::ConcolicSession session;

  std::unordered_set<u32> fuzzed_inputs;
};

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
  my_mutator_t *data = new my_mutator_t(afl);
  if (!data) {
    FATAL("afl_custom_init alloc");
    return NULL;
  }

  // solver ladder and tracing options all come from the SYMSAN_* environment
  // variables, parsed once in ConcolicConfig::from_env so that every front-end
  // honours the same knobs
  if (data->config.from_env() != 0) {
    FATAL(
        "SYMSAN_TARGET not defined, this should point to the full path of the "
        "symsan compiled binary.");
  }

  if (data->config.output_dir.empty()) {
    data->out_dir = alloc_printf("%s/symsan", afl->out_dir);
    data->config.output_dir = data->out_dir;
  }

  if (stat(data->config.output_dir.c_str(), &st) &&
      mkdir(data->config.output_dir.c_str(), 0755)) {
    PFATAL("Could not create the output directory %s", data->config.output_dir.c_str());
  }

  // setup output file
  char *out_file;
  if (afl->file_extension) {
    out_file = alloc_printf("%s/.cur_input.%s", data->config.output_dir.c_str(),
                            afl->file_extension);
  } else {
    out_file = alloc_printf("%s/.cur_input", data->config.output_dir.c_str());
  }
  if (data->config.output_dir[0] == '/') {
    data->out_file = out_file;
  } else {
    char cwd[PATH_MAX];
    if (getcwd(cwd, (size_t)sizeof(cwd)) == NULL) { PFATAL("getcwd() failed"); }
    data->out_file = alloc_printf("%s/%s", cwd, out_file);
    ck_free(out_file);
  }
  data->config.input_file = data->out_file;

  data->config.debug = DEBUG;
  data->config.max_input_size = MAX_FILE;

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
  delete data;
}

/// @brief finish setting up the session, now that afl->argv is known
static bool start_session(my_mutator_t *data) {
  int argc = 0;
  while (data->afl->argv[argc]) { argc++; }
  for (int i = 0; i < argc; i++) {
    // the target reads its input from our staging file, so substitute it
    // wherever AFL++ would have passed its own
    if (strstr(data->afl->argv[i], (char*)data->afl->tmp_dir)) {
      DEBUGF("Replacing %s with %s\n", data->afl->argv[i], data->out_file);
      data->config.args.push_back(data->out_file);
    } else {
      data->config.args.push_back(data->afl->argv[i]);
    }
  }

  data->config.use_stdin = data->afl->fsrv.use_stdin;
  data->config.timeout_ms = std::min(MIN_TIMEOUT, data->afl->fsrv.exec_tmout);

  if (data->session.init(data->config) != 0) {
    WARNF("Failed to init the symsan session\n");
    return false;
  }
  data->session_started = true;
  return true;
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
  if (data->fuzzed_inputs.find(input_id) != data->fuzzed_inputs.end()) {
    return 0;
  }
  data->fuzzed_inputs.insert(input_id);

  // record the name of the current queue entry
  data->cur_queue_entry = data->afl->queue_cur->fname;
  DEBUGF("Fuzzing %s\n", data->cur_queue_entry);

  if (unlikely(!data->session_started)) {
    if (!start_session(data)) return 0;
  }

  if (data->session.trace(buf, buf_size) < 0) {
    return 0;
  }

  // to be conservative, we return the maximum number of possible mutations
  return (u32)(data->session.num_pending_tasks() * data->session.num_solvers());
}

extern "C"
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  (void)(add_buf);
  (void)(add_buf_size);
  (void)(max_size);

  // default return values
  *out_buf = buf;
  if (buf_size > MAX_FILE || unlikely(!data->session_started)) {
    return 0;
  }

  size_t new_buf_size = 0;
  const uint8_t *solution = data->session.next_solution(&new_buf_size);
  if (!solution) {
    DEBUGF("No more tasks to solve\n");
#if PRINT_STATS
    data->session.print_stats(data->log_fd);
#endif
    return 0;
  }

  DEBUGF("task solved\n");
  *out_buf = (u8 *)solution;
  return new_buf_size;
}


extern "C"
uint8_t afl_custom_queue_new_entry(my_mutator_t * data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {
  // a new queue entry derived from the input we are currently tracing means the
  // last solution we handed out was interesting
  //
  // NOTE: this is still the filename-comparison guess the mutator has always
  // made -- AFL++ gives us no better signal.  A front-end that can see its own
  // execution result (the LibAFL stage) reports the truth to report_result()
  // instead.
  DEBUGF("new queue entry: %s\n", filename_new_queue);
  if (data->cur_queue_entry == filename_orig_queue) {
    data->session.report_result(true);
  }
  return 0;
}
