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
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

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
  size_t shm_size;

  int is_input_file;
  int is_input_sdtin;
  int is_input_network;
  int enable_debug;
  int enable_bounds_check;
  int enable_solve_ub;
  int exit_on_memerror;
  int trace_file_size;
  int force_stdin;

  int dev_null_fd;

  // AFL++-compatible coverage map: the segment the target's edge counters write
  // into, handed over as __AFL_SHM_ID and read back by the caller after a run.
  // SysV rather than POSIX shm, unlike the union table above, because the
  // attaching end is runtime/dfsan/afl_compat.cpp speaking AFL++'s ABI, and that
  // ABI is an integer id in an environment variable.
  int cov_shm_id;
  uint8_t *cov_map;
  size_t cov_map_size;

  int exit_status;
  int is_killed;

  // fork server state.  requested is what the caller asked for; active is
  // whether the handshake actually came back, so that a target built without
  // a fork server silently keeps the exec-per-run path.
  int forksrv_requested;
  int forksrv_active;
  int forksrv_ctl_fd;   // we write "go" here, child reads it on fd 198
  int forksrv_st_fd;    // child writes pid then status here, on fd 199
  int forksrv_pid;      // the server itself, as opposed to the current child
};

// AFL's fork server descriptors, which the target hard-codes; see
// backend/forkserver.cpp.
#define FORKSRV_FD 198

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
  g_config.shm_size = uniontable_size;
  g_config.pipefds[0] = -1;
  g_config.pipefds[1] = -1;
  g_config.symsan_env = NULL;
  g_config.symsan_pid = -1;
  g_config.is_input_file = 0;
  g_config.is_input_sdtin = 0;
  g_config.is_input_network = 0;
  g_config.enable_debug = 0;
  g_config.enable_bounds_check = 0;
  g_config.enable_solve_ub = 0;
  g_config.exit_on_memerror = 1;
  g_config.trace_file_size = 0;
  g_config.force_stdin = 0;
  g_config.dev_null_fd = -1;
  g_config.cov_shm_id = -1;
  g_config.cov_map = NULL;
  g_config.cov_map_size = 0;
  g_config.exit_status = 0;
  g_config.is_killed = 0;
  g_config.forksrv_requested = 0;
  g_config.forksrv_active = 0;
  g_config.forksrv_ctl_fd = -1;
  g_config.forksrv_st_fd = -1;
  g_config.forksrv_pid = -1;

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
int symsan_set_solve_ub(int enable) {
  g_config.enable_solve_ub = !!enable;
  return 0;
}

__attribute__((visibility("default")))
int symsan_set_exit_on_memerror(int enable) {
  g_config.exit_on_memerror = !!enable;
  return 0;
}

__attribute__((visibility("default")))
int symsan_set_trace_file_size(int enable) {
  g_config.trace_file_size = !!enable;
  return 0;
}

__attribute__((visibility("default")))
int symsan_set_force_stdin(int enable) {
  g_config.force_stdin = !!enable;
  return 0;
}

__attribute__((visibility("default")))
int symsan_set_forkserver(int enable) {
  g_config.forksrv_requested = !!enable;
  return 0;
}

/* Read exactly n bytes, retrying on a short read.  Pipe reads of four bytes
   will not normally split, but a signal can still cut one short and the
   protocol has no way to resynchronize afterwards. */
static int read_exact(int fd, void *buf, size_t n) {
  size_t done = 0;
  while (done < n) {
    ssize_t r = read(fd, (char *)buf + done, n - done);
    if (r > 0) {
      done += (size_t)r;
    } else if (r == 0) {
      return -1; // the other end closed
    } else if (errno != EINTR) {
      return -1;
    }
  }
  return 0;
}

/* AFL++'s MAP_SIZE (include/config.h), which is both the smallest map it will
   work with and what runtime/dfsan/afl_compat.cpp falls back to when nobody has
   said otherwise.  Keeping the two the same means a target built without the
   AFL++ pass -- __afl_final_loc == 0, so it never attaches at all -- and one
   built with it agree about how big "unspecified" is. */
#define SYMSAN_DEFAULT_COV_MAP_SIZE (1U << 16)

/* Drop the coverage segment.

   IPC_RMID rather than merely detaching, and here rather than right after
   shmget(): the target attaches by id, once per exec'd child or once per fork
   server, so the id has to stay resolvable for as long as we might start
   another one.  The cost is that a launcher killed outright leaks the segment,
   which is a real failure mode -- symsan-fuzz accumulating segments until
   shmget() starts returning ENOSPC is a debugging session nobody should repeat
   -- so anything embedding this should reap on the way out.  `ipcs -m` lists
   them; the owner is whoever ran the launcher. */
static void cov_map_destroy(void) {
  if (g_config.cov_map != NULL) {
    shmdt(g_config.cov_map);
    g_config.cov_map = NULL;
  }
  if (g_config.cov_shm_id != -1) {
    shmctl(g_config.cov_shm_id, IPC_RMID, NULL);
    g_config.cov_shm_id = -1;
  }
  g_config.cov_map_size = 0;
}

/* Make a coverage segment of at least `size` bytes, replacing any existing one
   that is too small.  Returns 0 on success. */
static int cov_map_create(size_t size) {
  if (size == 0) {
    size = SYMSAN_DEFAULT_COV_MAP_SIZE;
  }
  /* A map smaller than AFL++'s minimum is not worth the special cases: the
     target's own size check compares against __afl_final_loc, which the pass
     rounds up, and every consumer of the map assumes it can be indexed by any
     edge id the binary holds. */
  if (size < SYMSAN_DEFAULT_COV_MAP_SIZE) {
    size = SYMSAN_DEFAULT_COV_MAP_SIZE;
  }
  if (g_config.cov_map != NULL && g_config.cov_map_size >= size) {
    return 0; // the one we have already covers it
  }

  cov_map_destroy();

  int id = shmget(IPC_PRIVATE, size, IPC_CREAT | IPC_EXCL | 0600);
  if (id < 0) {
    return -1;
  }
  void *base = shmat(id, NULL, 0);
  if (base == (void *)-1) {
    shmctl(id, IPC_RMID, NULL);
    return -1;
  }

  g_config.cov_shm_id = id;
  g_config.cov_map = (uint8_t *)base;
  g_config.cov_map_size = size;
  memset(g_config.cov_map, 0, size);
  return 0;
}

/* Hand the segment to the child we are about to exec.

   Overwrite, emphatically: symsan-fuzz publishes __AFL_SHM_ID into its own
   environment for its own map, and every child inherits that value.  Passing 0
   for the overwrite flag would leave it in place and the traced process would
   count its edges into the map the fuzzer reads its coverage out of --
   corrupting the fuzzer's picture of the target with the concolic executor's
   footprints, silently and in the direction that looks like progress. */
static void cov_map_export(void) {
  if (g_config.cov_shm_id == -1) {
    return;
  }
  char buf[32];
  snprintf(buf, sizeof(buf), "%d", g_config.cov_shm_id);
  setenv("__AFL_SHM_ID", buf, 1);
}

/* Build the TAINT_OPTIONS string for the child.  Its own function because the
   fork server fallback has to build it a second time with forksrv turned back
   off. */
static char *build_symsan_env(int use_forksrv) {
  return alloc_printf(
      "taint_file=\"%s\":shm_fd=%d:pipe_fd=%d:debug=%d:trace_bounds=%d:"
      "solve_ub=%d:exit_on_memerror=%d:trace_fsize=%d:force_stdin=%d:"
      "forksrv=%d",
      g_config.input_file, g_config.shm_fd, g_config.pipefds[1],
      g_config.enable_debug, g_config.enable_bounds_check,
      g_config.enable_solve_ub, g_config.exit_on_memerror,
      g_config.trace_file_size, g_config.force_stdin, use_forksrv);
}

/* Spawn the fork server itself.  Unlike the exec-per-run path this happens
   once, so the event pipe and the two protocol pipes all outlive a single
   traced input. */
static int forksrv_spawn(void) {
  int ctl[2], st[2];

  if (pipe(ctl) != 0) {
    return SYMSAN_NO_MEMORY;
  }
  if (pipe(st) != 0) {
    close(ctl[0]);
    close(ctl[1]);
    return SYMSAN_NO_MEMORY;
  }

  g_config.forksrv_pid = fork();
  if (g_config.forksrv_pid < 0) {
    close(ctl[0]); close(ctl[1]);
    close(st[0]); close(st[1]);
    return g_config.forksrv_pid;
  }

  if (g_config.forksrv_pid == 0) {
    // clear signal handlers and masks
    sigset_t set;
    sigemptyset(&set);
    sigprocmask(SIG_SETMASK, &set, NULL);

    // disable core dump as shadow mem is toooooo large
    struct rlimit limit;
    limit.rlim_cur = limit.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &limit);

    close(g_config.pipefds[0]); // close the read fd

    // Move the protocol ends onto the numbers the target expects.  dup2()
    // clears FD_CLOEXEC, which matters because we are about to execv().
    if (dup2(ctl[0], FORKSRV_FD) < 0) _exit(1);
    if (dup2(st[1], FORKSRV_FD + 1) < 0) _exit(1);
    close(ctl[0]); close(ctl[1]);
    close(st[0]); close(st[1]);

    setenv("TAINT_OPTIONS", (char*)g_config.symsan_env, 1);
    // The fork server attaches once, in dfsan_init, ahead of the fork point, so
    // every child it goes on to make shares this one segment.  That is what we
    // want -- the launcher zeroes it per run -- but it does mean the size is
    // fixed here and symsan_set_cov_map_size() cannot move it afterwards.
    cov_map_export();
    unsetenv("LD_PRELOAD"); // don't preload anything
    if (!g_config.enable_debug) {
      close(1);
      close(2);
      dup2(g_config.dev_null_fd, 1);
      dup2(g_config.dev_null_fd, 2);
    }
    execv(g_config.symsan_bin, g_config.argv);
    _exit(1); // only reached if execv failed
  }

  close(ctl[0]);
  close(st[1]);
  g_config.forksrv_ctl_fd = ctl[1];
  g_config.forksrv_st_fd = st[0];

  // The handshake doubles as a check that this target actually has a fork
  // server: an older binary ignores forksrv=1 and runs straight through, so
  // the read fails and we fall back rather than hanging.
  //
  // The wait is bounded because a target can also hang *before* saying hello --
  // a constructor that blocks on something that never arrives -- and there is
  // no per-run timeout to catch it here, only on the event pipe.  Ten seconds
  // is AFL's default for the same handshake and is far more than a process
  // needs to reach dfsan_init().
  uint32_t hello = 0;
  fd_set hfds;
  FD_ZERO(&hfds);
  FD_SET(g_config.forksrv_st_fd, &hfds);
  struct timeval htv = { .tv_sec = 10, .tv_usec = 0 };
  int hready = select(g_config.forksrv_st_fd + 1, &hfds, NULL, NULL, &htv);
  if (hready <= 0 ||
      read_exact(g_config.forksrv_st_fd, &hello, sizeof(hello)) != 0) {
    if (g_config.forksrv_pid > 0) {
      kill(g_config.forksrv_pid, SIGKILL);
    }
    close(g_config.forksrv_ctl_fd);
    close(g_config.forksrv_st_fd);
    g_config.forksrv_ctl_fd = -1;
    g_config.forksrv_st_fd = -1;
    waitpid(g_config.forksrv_pid, NULL, 0);
    g_config.forksrv_pid = -1;
    return -1;
  }

  // From here on we write to a pipe whose far end is a process that can die --
  // a target that faults during init, say -- and the default SIGPIPE would
  // take the whole driver down with it.  A short write is what we want to see
  // instead, so that forksrv_poke() can report the failure.
  //
  // Deliberately after the fork: SIG_IGN survives execve(), so doing this any
  // earlier would hand the target a signal disposition it did not ask for.
  // Only claim the disposition if nobody else has, since this is a library.
  struct sigaction old;
  if (sigaction(SIGPIPE, NULL, &old) == 0 && old.sa_handler == SIG_DFL) {
    struct sigaction ign;
    memset(&ign, 0, sizeof(ign));
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    sigaction(SIGPIPE, &ign, NULL);
  }

  g_config.forksrv_active = 1;
  return 0;
}

/* Ask the fork server for another child, and learn its pid so that a timeout
   can kill the run rather than the server. */
static int forksrv_poke(void) {
  uint32_t go = 0;
  if (write(g_config.forksrv_ctl_fd, &go, sizeof(go)) != (ssize_t)sizeof(go)) {
    return -1;
  }

  int pid = -1;
  if (read_exact(g_config.forksrv_st_fd, &pid, sizeof(pid)) != 0) {
    return -1;
  }

  g_config.symsan_pid = pid;
  g_config.is_killed = 0;
  return 0;
}

static int forksrv_nfds(void) {
  int hi = g_config.pipefds[0] > g_config.forksrv_st_fd
               ? g_config.pipefds[0]
               : g_config.forksrv_st_fd;
  return hi + 1;
}

/* Collect the finished child's wait status, throwing away anything it left in
   the event pipe.  Called once per run, whether the run ended by itself or we
   killed it: leftover bytes would otherwise turn up as phantom events at the
   head of the *next* trace. */
static void forksrv_reap(void) {
  if (!g_config.forksrv_active || g_config.symsan_pid < 0) {
    return;
  }

  char scratch[4096];

  while (1) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(g_config.pipefds[0], &rfds);
    FD_SET(g_config.forksrv_st_fd, &rfds);

    if (select(forksrv_nfds(), &rfds, NULL, NULL, NULL) < 0) {
      if (errno == EINTR) continue;
      g_config.forksrv_active = 0; // the server is gone; fall back next run
      break;
    }

    // Events first, always: the status only shows up after the child has been
    // reaped, so whatever is still in the pipe belongs to the run we are
    // closing out.
    if (FD_ISSET(g_config.pipefds[0], &rfds)) {
      ssize_t n = read(g_config.pipefds[0], scratch, sizeof(scratch));
      if (n > 0) continue;
      if (n < 0 && errno == EINTR) continue;
      g_config.forksrv_active = 0;
      break;
    }

    if (read_exact(g_config.forksrv_st_fd, &g_config.exit_status,
                   sizeof(g_config.exit_status)) != 0) {
      g_config.forksrv_active = 0;
    }
    break;
  }

  g_config.symsan_pid = -1;
}

/* One event, fork-server flavoured.

   The event pipe's write end lives in the fork server rather than in the child,
   so it never reaches EOF and cannot mark the end of a run the way it does on
   the exec path.  What does mark it is the child's wait status turning up on fd
   199 -- and since the server only writes that after waitpid() has reaped the
   child, every event the child produced is already in the pipe by then.  So we
   watch both, drain the pipe first, and report "pipe empty and status ready" to
   the caller as this run's end of file. */
static ssize_t forksrv_read_event(void *buf, size_t size,
                                  unsigned int timeout) {
  // The run this call belongs to is already over and the next one has not been
  // asked for.  On the exec path the closed pipe reports that by itself; here
  // the pipe is still open and shared with the server, so a select() would
  // simply block on a child that is not coming.  Callers that read a message
  // header and then go back for its payload can land here after an error, so
  // this is not just belt and braces.
  if (g_config.symsan_pid < 0) {
    return 0;
  }

  while (1) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(g_config.pipefds[0], &rfds);
    FD_SET(g_config.forksrv_st_fd, &rfds);

    struct timeval tv;
    struct timeval *ptv = NULL;
    if (timeout) {
      tv.tv_sec = (timeout / 1000);
      tv.tv_usec = (timeout % 1000) * 1000;
      ptv = &tv;
    }

    int ret = select(forksrv_nfds(), &rfds, NULL, NULL, ptv);
    if (ret < 0) {
      if (errno == EINTR) continue;
      return -1;
    }

    if (ret == 0) {
      // Timed out.  Kill the run, not the server -- then still wait for the
      // status, so the next run starts on clean pipes.
      if (g_config.symsan_pid > 0) {
        kill(g_config.symsan_pid, SIGKILL);
      }
      g_config.is_killed = 1;
      forksrv_reap();
      return -1;
    }

    if (FD_ISSET(g_config.pipefds[0], &rfds)) {
      ssize_t n = read(g_config.pipefds[0], buf, size);
      if (n > 0) {
        return n;
      }
      if (n < 0 && errno == EINTR) {
        continue;
      }
      // n == 0 cannot happen while the server holds the write end, so this is
      // a real error.
      forksrv_reap();
      return n;
    }

    forksrv_reap();
    return 0; // end of this run's trace
  }
}

/* Shut the fork server itself down.  Closing the control pipe is its cue: the
   blocking read on fd 198 comes up short and it exits. */
static void forksrv_shutdown(void) {
  if (g_config.forksrv_ctl_fd >= 0) {
    close(g_config.forksrv_ctl_fd);
    g_config.forksrv_ctl_fd = -1;
  }
  if (g_config.forksrv_st_fd >= 0) {
    close(g_config.forksrv_st_fd);
    g_config.forksrv_st_fd = -1;
  }
  if (g_config.forksrv_pid > 0) {
    // It has no state of its own to flush -- the shm and the input file are
    // ours -- so there is nothing to lose by not waiting for a clean exit.
    kill(g_config.forksrv_pid, SIGKILL);
    waitpid(g_config.forksrv_pid, NULL, 0);
    g_config.forksrv_pid = -1;
  }
  g_config.forksrv_active = 0;
}

__attribute__((visibility("default")))
int symsan_set_cov_map_size(size_t edges) {
  // Growing the map under a running fork server would be a lie: the server
  // attached to the old segment before it forked anything and cannot be told
  // about a new one, so every child would keep writing where we are no longer
  // looking.  Refuse instead, which turns a silently empty map into an error at
  // the call that caused it.
  if (g_config.forksrv_active && g_config.cov_map != NULL &&
      edges > g_config.cov_map_size) {
    return SYMSAN_INVALID_ARGS;
  }
  return cov_map_create(edges) == 0 ? 0 : SYMSAN_NO_MEMORY;
}

__attribute__((visibility("default")))
uint8_t *symsan_get_cov_map(size_t *size) {
  if (size != NULL) {
    *size = g_config.cov_map_size;
  }
  return g_config.cov_map;
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

  // Coverage is per run, so the map is zeroed here rather than anywhere the
  // caller has to remember.  Both paths below come through this point exactly
  // once per traced input -- the fork server returns just underneath, the exec
  // path falls through -- which is the property that makes one memset enough.
  //
  // Created lazily and at the default size if the caller never sized it: a
  // target whose edge ids overflow that will refuse to start with a message
  // saying so (afl_compat.cpp's AttachCoverageMap), which is a better failure
  // than a launcher that insists on knowing the edge count up front.
  if (g_config.cov_map == NULL) {
    if (cov_map_create(0) != 0) {
      return SYMSAN_NO_MEMORY;
    }
  } else {
    memset(g_config.cov_map, 0, g_config.cov_map_size);
  }

  // Fork server already up: everything below has been done once already, and
  // all that is left is to ask for another child.  The input is picked up from
  // the file the caller just wrote, which is why the target forks before it
  // loads its input rather than after.
  if (g_config.forksrv_active) {
    return forksrv_poke();
  }

  // A fork server cannot serve a stdin or network target: those need their fd
  // wired into the child, and there is no way to reach into a process that is
  // already running.  Silently use the exec path instead of failing, so that
  // turning the fork server on is safe regardless of the input mode.
  int use_forksrv = g_config.forksrv_requested && g_config.is_input_file;

  // unlikely but double check
  if (g_config.pipefds[0] != -1) {
    close(g_config.pipefds[0]);
  }
  if (g_config.pipefds[1] != -1) {
    close(g_config.pipefds[1]);
  }
  if (g_config.symsan_env == NULL) {
    free(g_config.symsan_env);
  }

  int ret = pipe(g_config.pipefds);
  if (ret != 0) {
    return SYMSAN_NO_MEMORY;
  }

  // fds and configs could have been changed, so always set up new ones
  g_config.symsan_env = build_symsan_env(use_forksrv);
  if (g_config.symsan_env == NULL) {
    return SYMSAN_NO_MEMORY;
  }

  if (g_config.enable_debug) {
    fprintf(stderr, "SYMSAN_ENV: %s\n", g_config.symsan_env);
  }

  if (use_forksrv) {
    int err = forksrv_spawn();
    if (err == 0) {
      free(g_config.symsan_env);
      g_config.symsan_env = NULL;
      close(g_config.pipefds[1]); // the server holds the write end now
      g_config.pipefds[1] = -1;
      g_config.is_killed = 0;
      return forksrv_poke();
    }
    // The target does not have a fork server, or we could not spawn one.
    // Fall through to the exec path -- but only after telling the caller, in
    // debug builds, since a silent 100x slowdown is worth a line of output.
    if (g_config.enable_debug) {
      fprintf(stderr, "SYMSAN: no fork server in %s, exec'ing per run\n",
              g_config.symsan_bin);
    }
    g_config.forksrv_requested = 0;

    // Rebuild the options without forksrv, so the child we are about to exec
    // does not go looking for a fork server pipe that nobody is holding.
    free(g_config.symsan_env);
    g_config.symsan_env = build_symsan_env(0);
    if (g_config.symsan_env == NULL) {
      close(g_config.pipefds[0]);
      close(g_config.pipefds[1]);
      g_config.pipefds[0] = -1;
      g_config.pipefds[1] = -1;
      return SYMSAN_NO_MEMORY;
    }
  }

  g_config.symsan_pid = fork();
  if (g_config.symsan_pid == 0) {
    // clear signal handlers and masks
    sigset_t set;
    sigemptyset(&set);
    sigprocmask(SIG_SETMASK, &set, NULL);

    // disable core dump as shadow mem is toooooo large
    struct rlimit limit;
    limit.rlim_cur = limit.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &limit);

    close(g_config.pipefds[0]); // close the read fd
    setenv("TAINT_OPTIONS", (char*)g_config.symsan_env, 1);
    cov_map_export();
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

  free(g_config.symsan_env);
  g_config.symsan_env = NULL;
  close(g_config.pipefds[1]); // close the write fd
  g_config.pipefds[1] = -1;
  g_config.is_killed = 0; // reset kill flag

  return 0;
}

__attribute__((visibility("default")))
ssize_t symsan_read_event(void *buf, size_t size, unsigned int timeout) {
  if (size == 0) {
    return 0;
  }

  if (g_config.forksrv_active) {
    return forksrv_read_event(buf, size, timeout);
  }

  // The run this call belongs to is already over: the block below closed the
  // pipe and cleared the pid when the last read came up short.  Say so now,
  // before select() gets an fd of -1 to FD_SET and the timeout path gets a pid
  // of -1 to kill -- and kill(-1) is every process this uid owns.
  if (g_config.pipefds[0] < 0) {
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
    if (g_config.symsan_pid > 0) {
      kill(g_config.symsan_pid, SIGKILL);
    }
    g_config.is_killed = 1;
  }

  if (n != size) {
    // error or EOF
    if (g_config.symsan_pid > 0) {
      waitpid(g_config.symsan_pid, &g_config.exit_status, 0);
      g_config.symsan_pid = -1;
    }
    if (g_config.pipefds[0] >= 0) {
      close(g_config.pipefds[0]); // close the read fd
      g_config.pipefds[0] = -1;
    }
  }

  return n;
}

__attribute__((visibility("default")))
int symsan_terminate() {
  if (g_config.forksrv_active) {
    // End this run, but keep the server: it is the thing we spawned once and
    // want to keep for the next input.  Tearing it down is symsan_destroy()'s
    // job.  The event pipe stays open too, for the same reason.
    if (g_config.symsan_pid > 0) {
      kill(g_config.symsan_pid, SIGKILL);
      g_config.is_killed = 1;
      forksrv_reap();
    }
    return 0;
  }

  if (g_config.symsan_pid == -1) {
    // already terminated
    return 0;
  } else if (g_config.symsan_pid > 0) {
    kill(g_config.symsan_pid, SIGKILL);
    g_config.is_killed = 1;
    waitpid(g_config.symsan_pid, &g_config.exit_status, 0);
    g_config.symsan_pid = -1;
    close(g_config.pipefds[0]);
    return 0;
  } else {
    return -1;
  }
}

__attribute__((visibility("default")))
int symsan_get_exit_status(int *status) {
  if (!status) {
    return -1;
  }

  *status = g_config.exit_status;
  return g_config.is_killed;
}

__attribute__((visibility("default")))
void symsan_destroy() {
  symsan_terminate();
  forksrv_shutdown();

  if (g_config.pipefds[0] != -1) {
    close(g_config.pipefds[0]);
    g_config.pipefds[0] = -1;
  }

  if (g_config.label_info != NULL) {
    munmap(g_config.label_info, g_config.shm_size);
    g_config.label_info = NULL;
  }

  if (g_config.dev_null_fd != -1) {
    close(g_config.dev_null_fd);
    g_config.dev_null_fd = -1;
  }

  // After forksrv_shutdown() above, so that nothing is still attached to the
  // segment when it goes.
  cov_map_destroy();

  if (g_config.shm_fd != -1) {
    close(g_config.shm_fd);
    g_config.shm_fd = -1;
  }

  if (g_config.shm_name != NULL) {
    shm_unlink(g_config.shm_name);
    free(g_config.shm_name);
    g_config.shm_name = NULL;
  }

  if (g_config.input_file != NULL) {
    free(g_config.input_file);
    g_config.input_file = NULL;
  }

  if (g_config.argv != NULL) {
    for (int i = 0; g_config.argv[i]; i++) {
      free(g_config.argv[i]);
    }
    free(g_config.argv);
    g_config.argv = NULL;
  }

  if (g_config.symsan_env != NULL) {
    free(g_config.symsan_env);
    g_config.symsan_env = NULL;
  }

  if (g_config.symsan_bin != NULL) {
    free(g_config.symsan_bin);
    g_config.symsan_bin = NULL;
  }

  if (g_config.pipefds[0] != -1) {
    close(g_config.pipefds[0]);
    g_config.pipefds[0] = -1;
  }

  if (g_config.pipefds[1] != -1) {
    close(g_config.pipefds[1]);
    g_config.pipefds[1] = -1;
  }
}
