/*
  a custom mutator for AFL++
  (c) 2023 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#include "dfsan/dfsan.h"
#include "rgd.pb.h"

extern "C" {
#include "afl-fuzz.h"
}

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
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

using namespace __dfsan;

#ifndef DEBUG
#define DEBUG 1
#endif

#undef alloc_printf
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = (char*)ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

typedef struct my_mutator {
  afl_state_t *afl;
  char *out_dir;
  char *out_file;
  char *symsan_bin;
  char **argv;
  int out_fd;
  int shm_id;
  dfsan_label_info *label_info;
} my_mutator_t;

// FIXME: a temporary way to find out input that has been fuzzed before
static std::unordered_set<u32> __fuzzed_inputs;

// global caches
static std::unordered_map<dfsan_label, std::shared_ptr<u8>> memcmp_cache;

static inline dfsan_label_info *get_label_info(dfsan_label label, dfsan_label_info *label_info) {
  return &label_info[label];
}

static void clear_global_caches() {
  memcmp_cache.clear();
}

static void handle_cond(pipe_msg *msg, dfsan_label_info *label_info) {
}

static void handle_gep(gep_msg *gmsg, pipe_msg *msg, dfsan_label_info *label_info) {
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
  my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
  if (!data) {
    FATAL("afl_custom_init alloc");
    return NULL;
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
  data->out_fd = open(data->out_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (data->out_fd < 0) {
    FATAL("Failed to create output file %s: %s\n", data->out_file, strerror(errno));
  }

  // setup shmem for label info
  data->shm_id = shmget(IPC_PRIVATE, 0xc00000000,
    O_CREAT | SHM_NORESERVE | S_IRUSR | S_IWUSR);
  if (data->shm_id == -1) {
    FATAL("Failed to get shmid: %s\n", strerror(errno));
  }

  data->label_info = (dfsan_label_info *)shmat(data->shm_id, NULL, SHM_RDONLY);
  if (data->label_info == (void *)-1) {
    FATAL("Failed to map shm(%d): %s\n", data->shm_id, strerror(errno));
  }

  data->afl = afl;

  return data;
}

extern "C" void afl_custom_deinit(my_mutator_t *data) {
  close(data->out_fd);
  // unlink(data->out_file);
  shmdt(data->label_info);
  ck_free(data->argv);
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
  if (__fuzzed_inputs.find(input_id) != __fuzzed_inputs.end()) {
    return 0;
  }
  __fuzzed_inputs.insert(input_id);

  // setup argv in case of initialized
  if (unlikely(!data->argv)) {
    int argc = 0;
    while (data->afl->argv[argc]) { argc++; }
    data->argv = (char **)calloc(argc, sizeof(char *));
    if (!data->argv) {
      FATAL("Failed to alloc argv\n");
    }
    for (int i = 0; i < argc; i++) {
      if (strstr(data->afl->argv[i], (char*)data->afl->fsrv.out_file)) {
        DEBUGF("Replacing %s with %s\n", data->afl->argv[i], data->out_file);
        data->argv[i] = data->out_file;
      } else {
        data->argv[i] = data->afl->argv[i];
      }
    }
  }

  // FIXME: should we use the afl->queue_cur->fname instead?
  // write the buf to the file
  ck_write(data->out_fd, buf, buf_size, data->out_file);
  if (ftruncate(data->out_fd, buf_size)) {
    WARNF("Failed to truncate output file: %s\n", strerror(errno));
    return 0;
  }

  // create pipe for communication
  int pipefds[2];
  if (pipe(pipefds) != 0) {
    WARNF("Failed to create pipe fds: %s\n", strerror(errno));
    return 0;
  }

  // setup the env vars for SYMSAN
  const char *taint_file = data->afl->fsrv.use_stdin ? "stdin" : data->out_file;
  char *options = alloc_printf("taint_file=%s:shm_id=%d:pipe_fd=%d:debug=%d",
                                taint_file, data->shm_id, pipefds[1], DEBUG);
  DEBUGF("TAINT_OPTIONS=%s\n", options);
  
  int pid = fork();
  if (pid < 0) {
    WARNF("Failed to fork: %s\n", strerror(errno));
    return 0;
  }

  if (pid == 0) {
    close(pipefds[0]); // close the read fd
    setenv("TAINT_OPTIONS", (char*)options, 1);
    if (data->afl->fsrv.use_stdin) {
      close(0);
      dup2(data->out_fd, 0);
    }
#if !DEBUG
    close(1);
    close(2);
    dup2(data->afl->fsrv.dev_null_fd, 1);
    dup2(data->afl->fsrv.dev_null_fd, 2);
#endif
    execv(data->symsan_bin, data->argv);
    DEBUGF("Failed to execv: %s", data->symsan_bin);
    exit(-1);
  }

  close(pipefds[1]); // close the write fd

  pipe_msg msg;
  gep_msg gmsg;
  dfsan_label_info *info;
  size_t msg_size;
  std::shared_ptr<u8> msg_buf;
  std::shared_ptr<memcmp_msg> mmsg;
  u32 num_tasks = 0;

  // clear all caches
  clear_global_caches();

  while (read(pipefds[0], &msg, sizeof(msg)) > 0) {
    // create solving tasks
    switch (msg.msg_type) {
      // conditional branch
      case cond_type:
        handle_cond(&msg, data->label_info);
        break;
      case gep_type:
        if (read(pipefds[0], &gmsg, sizeof(gmsg)) != sizeof(gmsg)) {
          WARNF("Failed to receive gep msg: %s\n", strerror(errno));
          break;
        }
        // double check
        if (msg.label != gmsg.index_label) {
          WARNF("Incorrect gep msg: %d vs %d\n", msg.label, gmsg.index_label);
          break;
        }
        handle_gep(&gmsg, &msg, data->label_info);
        break;
      case memcmp_type:
        info = get_label_info(msg.label, data->label_info);
        // if both operands are symbolic, no content to be read
        if (info->l1 != CONST_LABEL && info->l2 != CONST_LABEL)
          break;
        msg_size = sizeof(memcmp_msg) + msg.result;
        msg_buf = std::make_shared<u8>(msg_size); // use shared_ptr to avoid memory leak
        if (read(pipefds[0], msg_buf.get(), msg_size) != msg_size) {
          WARNF("Failed to receive memcmp msg: %s\n", strerror(errno));
          break;
        }
        // double check
        mmsg = std::reinterpret_pointer_cast<memcmp_msg>(msg_buf);
        if (msg.label != mmsg->label) {
          WARNF("Incorrect memcmp msg: %d vs %d\n", msg.label, mmsg->label);
          break;
        }
        // save the content
        memcmp_cache[msg.label] = msg_buf;
        break;
      case fsize_type:
        break;
      default:
        break;
    }
  }

  pid = waitpid(pid, NULL, 0);

  return 0;

}

extern "C" size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                                  u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                                  size_t max_size) {
  return 0;
}