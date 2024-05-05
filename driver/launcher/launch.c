#include "defs.h"
#include "debug.h"
#include "version.h"
#include "launch.h"

#include <stdio.h>
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

#undef alloc_printf
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = (char*)malloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

struct symsan_config {
  char *symsan_bin;
  char *input_file;
  char **argv;
  char *shm_name;
  int shm_fd;
  void *label_info;
  int pipefds[2];
  char *symsan_env;
  int symsan_pid;

  int is_input_file;
  int is_input_sdtin;
  int is_input_network;
  int enable_debug;
  int enable_bounds_check;

  int dev_null_fd;
};

static struct symsan_config g_config;

__attribute__((visibility("default")))
void* symsan_init(const char *symsan_bin, const size_t uniontable_size) {

  if (!symsan_bin) {
    return (void *)-1;
  }

  g_config.symsan_bin = strdup(symsan_bin);
  g_config.input_file = NULL;
  g_config.argv = NULL;
  g_config.shm_name = NULL;
  g_config.shm_fd = -1;
  g_config.label_info = NULL;
  g_config.pipefds[0] = -1;
  g_config.pipefds[1] = -1;
  g_config.symsan_env = NULL;
  g_config.symsan_pid = -1;
  g_config.is_input_file = 0;
  g_config.is_input_sdtin = 0;
  g_config.is_input_network = 0;
  g_config.enable_debug = 0;
  g_config.enable_bounds_check = 0;

  // open /dev/null
  g_config.dev_null_fd = open("/dev/null", O_RDWR);
  if (g_config.dev_null_fd == -1) {
    return (void *)-1;
  }

  // create a new shm name
  g_config.shm_name = alloc_printf("/symsan-union-table-%d", getpid());
  if (!g_config.shm_name) {
    return (void *)-1;
  }
  // create shm
  g_config.shm_fd = shm_open(g_config.shm_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (g_config.shm_fd == -1) {
    return (void *)-1;
  }
  // set the size of the shm
  if (ftruncate(g_config.shm_fd, uniontable_size) == -1) {
    return (void *)-1;
  }
  // clear O_CLOEXEC flag
  fcntl(g_config.shm_fd, F_SETFD, fcntl(g_config.shm_fd, F_GETFD) & ~FD_CLOEXEC);
  // mmap the shm
  g_config.label_info = mmap(NULL, uniontable_size, PROT_READ, MAP_SHARED,
      g_config.shm_fd, 0);

  return g_config.label_info;
}

__attribute__((visibility("default")))
int symsan_set_input(const char *input) {
  if (!input) {
    return SYMSAN_INVALID_ARGS;
  }

  g_config.input_file = strdup(input);
  if (!g_config.input_file) {
    return SYMSAN_NO_MEMORY;
  }

  if (strcmp(input, "stdin") == 0) {
    g_config.is_input_sdtin = 1;
  } else if (strstr(input, "tcp@") == input) {
    g_config.is_input_network = 1;
  } else if (strstr(input, "udp@") == input) {
    g_config.is_input_network = 1;
  } else if (strstr(input, "unix@") == input) {
    g_config.is_input_network = 1;
  } else {
    g_config.is_input_file = 1;
  }

  return 0;
}

__attribute__((visibility("default")))
int symsan_set_args(const int argc, char* const argv[]) {
  if (argc < 1 || !argv) {
    return SYMSAN_INVALID_ARGS;
  }

  g_config.argv = (char **)malloc(sizeof(char *) * (argc + 1));
  if (!g_config.argv) {
    return SYMSAN_NO_MEMORY;
  }

  int err = 0, i = 0;
  for (;i < argc; i++) {
    if (!argv[i]) {
      err = SYMSAN_INVALID_ARGS;
      goto error;
    }

    g_config.argv[i] = strdup(argv[i]);
    if (!g_config.argv[i]) {
      err = SYMSAN_NO_MEMORY;
      goto error;
    }
  }
  g_config.argv[argc] = NULL;

  return 0;

error:
  for (int j = 0; j < i; j++) {
    free(g_config.argv[j]);
  }
  free(g_config.argv);
  g_config.argv = NULL;
  return err;
}

__attribute__((visibility("default")))
int symsan_set_debug(int enable) {
  g_config.enable_debug = !!enable;
  return 0;
}

__attribute__((visibility("default")))
int symsan_set_bounds_check(int enable) {
  g_config.enable_bounds_check = !!enable;
  return 0;
}

__attribute__((visibility("default")))
int symsan_run(int fd) {
  if (fd < 0) {
    return SYMSAN_INVALID_ARGS;
  }
  if (!g_config.symsan_bin) {
    return SYMSAN_MISSING_BIN;
  }
  if (!g_config.label_info) {
    return SYMSAN_MISSING_SHM;
  }
  if (!g_config.input_file) {
    return SYMSAN_MISSING_INPUT;
  }
  if (!g_config.argv) {
    return SYMSAN_MISSING_ARGS;
  }

  if (g_config.is_input_network && !g_config.input_file) {
    return SYMSAN_MISSING_INPUT;
  }

  int ret = pipe(g_config.pipefds);
  if (ret != 0) {
    return SYMSAN_NO_MEMORY;
  }

  if (!g_config.symsan_env) {
    g_config.symsan_env = alloc_printf("taint_file=%s:shm_fd=%d:pipe_fd=%d:debug=%d:trace_bound=%d",
        g_config.input_file, g_config.shm_fd, g_config.pipefds[1],
        g_config.enable_debug, g_config.enable_bounds_check);
    if (!g_config.symsan_env) {
      return SYMSAN_NO_MEMORY;
    }
  }

  g_config.symsan_pid = fork();
  if (g_config.symsan_pid == 0) {
    close(g_config.pipefds[0]); // close the read fd
    setenv("TAINT_OPTIONS", (char*)g_config.symsan_env, 1);
    unsetenv("LD_PRELOAD"); // don't preload anything
    if (g_config.is_input_sdtin) {
      close(0);
      lseek(fd, 0, SEEK_SET);
      dup2(fd, 0);
    }
    if (!g_config.enable_debug) {
      close(1);
      close(2);
      int dev_null_fd = open("/dev/null", O_RDWR);
      dup2(g_config.dev_null_fd, 1);
      dup2(g_config.dev_null_fd, 2);
    }
    ret = execv(g_config.symsan_bin, g_config.argv);
    return ret;
  } else if (g_config.symsan_pid < 0) {
    close(g_config.pipefds[0]);
    close(g_config.pipefds[1]);
    return g_config.symsan_pid;
  }

  close(g_config.pipefds[1]); // close the write fd

  return 0;
}

__attribute__((visibility("default")))
ssize_t symsan_read_event(void *buf, size_t size, unsigned int timeout) {
  if (size == 0) {
    return 0;
  }

  int ret = 1;

  if (timeout) {
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(g_config.pipefds[0], &rfds);

    tv.tv_sec = (timeout / 1000);
    tv.tv_usec = (timeout % 1000) * 1000;

    ret = select(g_config.pipefds[0] + 1, &rfds, NULL, NULL, &tv);
  }

  ssize_t n = -1;
  if (ret > 0) { // no timeout or select okay
    n = read(g_config.pipefds[0], buf, size);
  } else {
    // time out or error on select
    kill(g_config.symsan_pid, SIGKILL);
  }

  if (n != size) {
    // error or EOF
    waitpid(g_config.symsan_pid, NULL, 0);
    g_config.symsan_pid = -1;
  }

  return n;
}

__attribute__((visibility("default")))
void symsan_destroy() {
  if (g_config.symsan_pid > 0) {
    kill(g_config.symsan_pid, SIGKILL);
    waitpid(g_config.symsan_pid, NULL, 0);
  }

  if (g_config.dev_null_fd != -1) {
    close(g_config.dev_null_fd);
  }

  if (g_config.shm_fd != -1) {
    close(g_config.shm_fd);
  }

  if (g_config.shm_name) {
    shm_unlink(g_config.shm_name);
    free(g_config.shm_name);
  }

  if (g_config.input_file) {
    free(g_config.input_file);
  }

  if (g_config.argv) {
    for (int i = 0; g_config.argv[i]; i++) {
      free(g_config.argv[i]);
    }
    free(g_config.argv);
  }

  if (g_config.symsan_env) {
    free(g_config.symsan_env);
  }

  if (g_config.symsan_bin) {
    free(g_config.symsan_bin);
  }
}
