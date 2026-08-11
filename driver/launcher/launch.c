#include "defs.h"
#include "debug.h"
#include "version.h"
#include "launch.h"
#include "symsan_ring.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/select.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
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

  // The trace event ring (include/symsan_ring.h).  pipefds is still here and
  // still open: with the ring up it carries the wake-up doorbell instead of the
  // events, and on the exec-per-run path its EOF is still how we learn the
  // child is gone.  ring == NULL means we could not get one and everything
  // below falls back to the old one-write-per-event protocol.
  int ring_fd;
  struct symsan_ring_hdr *ring;
  size_t ring_size;

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

/* ---------------------------------------------------------------------------
   The trace event ring.  See include/symsan_ring.h for the layout and for why
   the events left the pipe; what stays here is our half of the protocol.

   The consumer's contract does not change: symsan_read_event(buf, size,
   timeout) still returns `size` on an event, 0 at end of trace and -1 on a
   timeout or error, so none of the four callers know this happened.
   --------------------------------------------------------------------------*/

/* Spin this many times before telling the producer we are going to sleep.
   PAUSE is anywhere from ~10 to ~140 cycles depending on the part, so this is
   roughly a microsecond on current hardware -- enough to cover the gap between
   two events the target emits back to back, and short enough that a target
   which has wandered off into non-symbolic code does not cost us much.  Not
   tuned against a measurement yet; the profile in step 7 of the plan is where
   to revisit it. */
#define RING_SPINS 64

/* The longest the consumer will stay in one FUTEX_WAIT.  Nothing depends on
   waking up this often: the producer wakes us when it commits and the fork
   server wakes us when the run ends, so in normal operation this expiry never
   fires.  What it is for is the case neither of those covers -- the fork server
   itself dying, which used to show up immediately as fd 199 going readable at
   EOF and now has nobody to report it.  Each expiry costs one zero-timeout
   select() to ask that question; see forksrv_ring_read_event(). */
#define RING_WAIT_SLICE_NSEC (250 * 1000 * 1000L)

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Wake a producer that is blocked on a full ring.  Rare -- it needs the target
   to outrun us by a whole ring -- but the futex wait on the other side is
   bounded and gives up eventually, so missing this would cost a trace. */
static void ring_wake_producer(void) {
  /* Clearing the bit is part of the wake-up, not bookkeeping after it: a
     producer that reaches FUTEX_WAIT a moment from now must not find the word
     in the state it expected.  Our advance already changed it, so strictly this
     is redundant for that producer -- what it prevents is the *next* advance
     finding a stale bit and paying a syscall for a producer that is long since
     running. */
  symsan_ring_disarm(&g_config.ring->tail);
  syscall(SYS_futex, symsan_ring_futex_word(&g_config.ring->tail),
          SYMSAN_FUTEX_WAKE, 1, NULL, NULL, 0);
}

/* Take exactly `size` bytes if that many are queued.  1 on success, and no
   syscall on the way -- this is the path that replaces select() + read(). */
static int ring_take(void *buf, size_t size) {
  struct symsan_ring_hdr *ring = g_config.ring;
  uint64_t tail = symsan_ring_load_own(&ring->tail);

  if (symsan_ring_used(symsan_ring_load_head_acq(ring), tail) < size) {
    return 0;
  }

  symsan_ring_get(ring, tail, buf, size);
  // Publishing the new tail is what frees the space, so it has to happen after
  // the copy out.  One `lock xadd`, and the word it returns says whether a
  // producer is blocked waiting for exactly this space -- no second load, and
  // no window between freeing the space and learning who wanted it.
  uint64_t prev = symsan_ring_advance(&ring->tail, size);
  if (prev & SYMSAN_RING_WAITING) {
    ring_wake_producer();
  }
  return 1;
}

/* Take whatever is left, up to `size`.  Only ever called once the writer is
   known to be dead -- child reaped on the fork-server path, pipe at EOF on the
   exec path -- where a short count means a genuinely truncated record rather
   than one that has not arrived yet.  The callers already treat a return
   other than `size` as a desync and skip the event, which is what they do with
   a short pipe read today.

   No wake-up here, and that is not an omission: the only process that could be
   waiting on tail is the one we already know is gone. */
static size_t ring_take_partial(void *buf, size_t size) {
  struct symsan_ring_hdr *ring = g_config.ring;
  uint64_t tail = symsan_ring_load_own(&ring->tail);
  uint64_t avail = symsan_ring_used(symsan_ring_load_head_acq(ring), tail);

  size_t n = avail < size ? (size_t)avail : size;
  if (n == 0) {
    return 0;
  }
  symsan_ring_get(ring, tail, buf, n);
  symsan_ring_advance(&ring->tail, n);
  return n;
}

/* Spin waiting for `size` bytes.  1 if they turned up, so the caller can return
   without ever touching the kernel; this is the path that replaces select() +
   read() and it is the one almost every event takes. */
static int ring_spin(void *buf, size_t size) {
  for (int i = 0; i < RING_SPINS; i++) {
    if (ring_take(buf, size)) {
      return 1;
    }
    SYMSAN_RING_PAUSE();
  }
  return 0;
}

/* Claim the waiting bit in the head cursor and hand back the word that claim
   returned.  Everything the caller decides next -- are the bytes here after
   all, has the run ended, what value do I pass to FUTEX_WAIT -- comes out of
   this one word, which is what makes the decision race-free: the producer and
   the fork server both learn we are waiting through the same atomic that
   publishes whatever they were about to tell us.

   The caller must clear the bit again on every path out, including the one
   where it never sleeps.  Leaving it set is not a correctness bug -- the peer
   just wakes someone who is already awake -- but it is a syscall per event
   afterwards, which is the cost this whole file exists to avoid. */
static uint64_t ring_arm_head(void) {
  return symsan_ring_arm(&g_config.ring->head) | SYMSAN_RING_WAITING;
}

static void ring_disarm_head(void) {
  symsan_ring_disarm(&g_config.ring->head);
}

/* Sleep on the head cursor until it changes away from `expect`, or the slice
   runs out.  Returns nothing: every caller re-derives its state from the ring
   afterwards rather than trusting why it woke, because a futex wait can return
   for reasons that mean nothing (a spurious wake, an EAGAIN from a peer that
   moved between our arm and this call, a signal). */
static void ring_futex_wait_head(uint32_t expect, long nsec) {
  struct timespec ts;
  ts.tv_sec = nsec / 1000000000L;
  ts.tv_nsec = nsec % 1000000000L;
  syscall(SYS_futex, symsan_ring_futex_word(&g_config.ring->head),
          SYMSAN_FUTEX_WAIT, expect, &ts, NULL, 0);
}

/* Set when this run has taken bytes off the pipe; see ring_check_target(). */
static int ring_saw_pipe_bytes;

/* Swallow doorbell bytes.  They carry nothing -- the producer writes one only
   to break us out of select() -- so all that matters is emptying the pipe, or
   the next select() returns on the same byte forever.  Returns the read()
   result, because 0 still means EOF and that is how the exec path learns the
   child is gone. */
static ssize_t ring_drain_doorbell(void) {
  char scratch[256];
  ssize_t n = read(g_config.pipefds[0], scratch, sizeof(scratch));
  if (n > 0) {
    ring_saw_pipe_bytes = 1;
  }
  return n;
}

/* Called at end of trace, and the reason it exists: a target built before the
   ring writes its events down the pipe, and dfsan's flag parser ignores the
   ring_fd it does not know about rather than refusing to start.  We would then
   read those events as doorbells, throw them away, and hand the caller an
   empty trace with no error anywhere -- which is the single worst way for this
   change to fail, and indistinguishable from #115.

   A ring-aware target that produced anything has moved head; one that produced
   nothing wrote no doorbells either, since the producer only rings after a
   commit.  So "the pipe had bytes and head never moved" is exactly this case
   and nothing else.  Once per process is enough to name it. */
static void ring_check_target(void) {
  static int warned;

  if (!warned && ring_saw_pipe_bytes &&
      symsan_ring_bytes(symsan_ring_load_head_acq(g_config.ring)) == 0) {
    warned = 1;
    WARNF("%s wrote trace events to the pipe instead of the event ring, so "
          "this trace is empty. It was built against a SymSan runtime from "
          "before the ring; rebuild it, or set SYMSAN_NO_RING=1.",
          g_config.symsan_bin != NULL ? g_config.symsan_bin : "the target");
  }
  ring_saw_pipe_bytes = 0;
}

/* Create the segment.  Unlinked the moment it is mapped: the fd is what the
   child gets (through ring_fd in TAINT_OPTIONS, like shm_fd for the union
   table), the mapping keeps it alive, and a crash leaves nothing behind in
   /dev/shm for the next run to trip over.

   Not fatal if it fails.  Every path below checks g_config.ring and falls back
   to the pipe, which is also what SYMSAN_NO_RING=1 selects -- that is the A/B
   switch, and the escape hatch if this turns out to have a bug in the field. */
static void ring_create(void) {
  if (getenv("SYMSAN_NO_RING") != NULL) {
    return;
  }

  size_t capacity = SYMSAN_RING_DEFAULT_CAPACITY;
  const char *env = getenv("SYMSAN_RING_SIZE");
  if (env != NULL) {
    size_t want = (size_t)strtoull(env, NULL, 0);
    if (!symsan_ring_size_ok(want)) {
      WARNF("SYMSAN_RING_SIZE=%s is not a power of two >= 4096, ignoring", env);
    } else {
      capacity = want;
    }
  }

  char *name = alloc_printf("/symsan-event-ring-%d", getpid());
  if (name == NULL) {
    return;
  }

  int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    WARNF("cannot create the event ring (%s), falling back to the pipe",
          strerror(errno));
    free(name);
    return;
  }
  shm_unlink(name);
  free(name);

  size_t total = symsan_ring_total_size(capacity);
  if (ftruncate(fd, total) == -1) {
    WARNF("cannot size the event ring (%s), falling back to the pipe",
          strerror(errno));
    close(fd);
    return;
  }

  void *base = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    WARNF("cannot map the event ring (%s), falling back to the pipe",
          strerror(errno));
    close(fd);
    return;
  }

  // The child inherits this across execv(), so it must survive it.
  fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) & ~FD_CLOEXEC);

  symsan_ring_init((struct symsan_ring_hdr *)base, capacity);

  g_config.ring_fd = fd;
  g_config.ring = (struct symsan_ring_hdr *)base;
  g_config.ring_size = total;
}

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
  g_config.ring_fd = -1;
  g_config.ring = NULL;
  g_config.ring_size = 0;
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

  ring_create();

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

__attribute__((visibility("default")))
int symsan_forkserver_active(void) {
  // The request is not the answer: forksrv_active is set only once the
  // handshake has come back, and is cleared again if the server dies.
  return g_config.forksrv_active ? 1 : 0;
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
  // ring_fd=-1 is the "no ring, keep writing events down the pipe" case, which
  // is exactly the flag's default, so this needs no conditional spelling.
  return alloc_printf(
      "taint_file=\"%s\":shm_fd=%d:pipe_fd=%d:ring_fd=%d:ring_size=%zu:"
      "debug=%d:trace_bounds=%d:"
      "solve_ub=%d:exit_on_memerror=%d:trace_fsize=%d:force_stdin=%d:"
      "forksrv=%d",
      g_config.input_file, g_config.shm_fd, g_config.pipefds[1],
      g_config.ring_fd,
      g_config.ring != NULL ? (size_t)g_config.ring->capacity : (size_t)0,
      g_config.enable_debug, g_config.enable_bounds_check,
      g_config.enable_solve_ub, g_config.exit_on_memerror,
      g_config.trace_file_size, g_config.force_stdin, use_forksrv);
}

/* Turn ASLR off for the traced child.  Call between fork() and execv():
   ADDR_NO_RANDOMIZE survives execve(), so setting it here is enough, and the
   fork server's own children inherit it along with everything else.

   This is about where the kernel puts the *mmap base*, not about the
   executable, which is non-PIE and linked at a fixed 0x700000200000.  dfsan_init
   reserves [UnusedAddr(), AppAddr()) so that no application allocation can ever
   come back without shadow behind it, and mmap_base is TASK_SIZE less the stack
   rlimit, the guard gap and the 16GB stack-randomization pad, less a draw
   uniform over 16TB (vm.mmap_rnd_bits=32).  The bottom 16GB of that range sit
   below AppAddr(), so one run in 2^10 dropped ld.so inside the region we were
   about to reserve -- measured at 3/3000, which is exactly the rate of "a traced
   run read zero events" we spent a while blaming on the event transport.  With
   randomization off the base pins to the top of the address space, well clear.

   The runtime detects the collision and recovers on its own (it re-execs with
   this same flag), so this is not what makes the bug survivable -- doing it here
   just means the recovery path stays unexercised on the paths we control, and
   traced runs get a reproducible address space for free.  Note it does *not*
   help under an unlimited stack rlimit: that flips the kernel to the legacy
   bottom-up layout at TASK_SIZE/3, below AppAddr() and growing toward it, which
   no personality bit can move.  The runtime names that case separately.

   A failure here is not worth aborting the run over -- personality() can be
   refused by seccomp, and all we lose is the 1-in-1024. */
static void child_disable_aslr(void) {
  int old = personality(0xffffffff);
  if (old != -1 && (old & ADDR_NO_RANDOMIZE) == 0)
    personality((unsigned long)old | ADDR_NO_RANDOMIZE);
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
    //
    // 1, not 0, and the difference is not cosmetic: the kernel only compares
    // RLIMIT_CORE against the dump size when core_pattern names a *file*.  When
    // it starts with '|' -- Ubuntu ships `|/usr/share/apport/apport ...` -- that
    // check is skipped and a limit of 0 dumps anyway; 1 is the value do_coredump
    // treats as "abort the core" for pipes (its recursive-crash guard).  With 0,
    // a target that abort()s walks its ~114 TB of shadow VMAs inside
    // do_coredump, at 100% system time, and SIGKILL does not land while
    // PF_DUMPCORE is set -- so the launcher's timeout kill cannot reclaim it.
    struct rlimit limit;
    limit.rlim_cur = limit.rlim_max = 1;
    setrlimit(RLIMIT_CORE, &limit);

    child_disable_aslr();

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

/* Is there something to read on fd 199?  Zero timeout, so this is a question
   and not a wait.  Only the ring path asks it, and only as a liveness check --
   see forksrv_ring_read_event. */
static int forksrv_status_ready(void) {
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(g_config.forksrv_st_fd, &rfds);

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 0;

  return select(g_config.forksrv_st_fd + 1, &rfds, NULL, NULL, &tv) > 0;
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

/* Give up on the current run: kill the child, mark it, and still collect the
   status so the next run starts on clean pipes.  Never kills the server. */
static ssize_t forksrv_kill_run(void) {
  if (g_config.symsan_pid > 0) {
    kill(g_config.symsan_pid, SIGKILL);
  }
  g_config.is_killed = 1;
  forksrv_reap();
  return -1;
}

/* Everything the ring still holds once the run is over, then end of file.
   Reached from the EOR bit; the child is reaped by then, so a record that is
   short is short for good. */
static ssize_t forksrv_ring_finish(void *buf, size_t size) {
  // Events can land between any check above and getting here, so look once
  // more before calling it the end.  EOR stays set and the next call comes
  // straight back, which is why this returns without reaping.
  if (ring_take(buf, size)) {
    return (ssize_t)size;
  }
  size_t partial = ring_take_partial(buf, size);
  if (partial > 0) {
    // A record the child was cut off in the middle of.  Same shape as a short
    // pipe read, and the callers already treat it as a desync.
    forksrv_reap();
    return (ssize_t)partial;
  }
  ring_check_target();
  forksrv_reap();
  return 0; // end of this run's trace
}

/* One event, fork server plus ring: no fd is involved at all while the run is
   in flight.

   Both of the things that can end a wait here now arrive as a change to the
   head cursor -- the producer's commit, and the fork server's end-of-run bit
   after waitpid() (backend/forkserver.cpp).  So the wait is a FUTEX_WAIT on
   that one word, and the value we hand the kernel is the word our own arm
   returned, which is what makes it impossible to sleep through either of them:
   if the change landed first, the compare fails and we come back immediately.

   The status on fd 199 is still what a run ended with and still what
   forksrv_reap() collects.  What the bit replaces is only the select() that
   used to be how we noticed, and the doorbell byte that used to be how the
   producer got our attention. */
static ssize_t forksrv_ring_read_event(void *buf, size_t size,
                                       unsigned int timeout) {
  uint64_t deadline = timeout ? now_ms() + timeout : 0;

  while (1) {
    // The whole point: when the target is keeping up this returns and we make
    // no syscall at all, so everything below runs once per drained queue rather
    // than once per event -- 151 times against 150,149 events on libpng.
    if (ring_spin(buf, size)) {
      return (ssize_t)size;
    }

    uint64_t head = ring_arm_head();
    if (symsan_ring_used(head, symsan_ring_load_own(&g_config.ring->tail)) >=
        size) {
      ring_disarm_head();
      continue; // it arrived while we were arming; take it on the next pass
    }
    if (head & SYMSAN_RING_EOR) {
      ring_disarm_head();
      return forksrv_ring_finish(buf, size);
    }

    long slice = RING_WAIT_SLICE_NSEC;
    if (deadline) {
      uint64_t now = now_ms();
      if (now >= deadline) {
        ring_disarm_head();
        return forksrv_kill_run();
      }
      uint64_t left = deadline - now;
      if ((long)left * 1000000L < slice) {
        slice = (long)left * 1000000L;
      }
    }

    ring_futex_wait_head(symsan_ring_futex_expect(head), slice);
    ring_disarm_head();

    if (deadline && now_ms() >= deadline) {
      return forksrv_kill_run();
    }

    // The one thing neither wake-up covers: the fork server itself dying.  That
    // used to surface instantly as fd 199 going readable at EOF, and with
    // nobody left to set the end-of-run bit it would otherwise be a hang.  So
    // every slice expiry asks the question directly.  It costs one syscall per
    // 250ms of genuine idling and none at all when a wake-up is what brought us
    // here, because then the loop above has already returned.
    if (forksrv_status_ready()) {
      return forksrv_ring_finish(buf, size);
    }
  }
}

/* One event, fork server on the pipe -- the fallback when no ring was mapped
   (SYMSAN_NO_RING=1, or a shm_open that failed).

   The event pipe's write end lives in the fork server rather than in the child,
   so it never reaches EOF and cannot mark the end of a run the way it does on
   the exec path.  What does mark it is the child's wait status turning up on fd
   199 -- and since the server only writes that after waitpid() has reaped the
   child, every event the child produced is already in the pipe by then.  So we
   watch both, drain the pipe first, and report "pipe empty and status ready" to
   the caller as this run's end of file. */
static ssize_t forksrv_pipe_read_event(void *buf, size_t size,
                                       unsigned int timeout) {
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
      return forksrv_kill_run();
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

  if (g_config.ring != NULL) {
    return forksrv_ring_read_event(buf, size, timeout);
  }
  return forksrv_pipe_read_event(buf, size, timeout);
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

  // Same idea, and the same one-call-per-input property, for the event ring:
  // rewind both cursors rather than letting them run for the life of the
  // campaign.  What that buys is that a caller who abandons a trace half-read
  // -- on a timeout, or because it found what it wanted -- cannot leave the
  // leftovers at the head of the next run's stream.  It is the ring's version
  // of the pipe drain forksrv_reap() already does, and it has the same
  // precondition as the memset above: the previous child is finished with.
  if (g_config.ring != NULL) {
    symsan_ring_reset(g_config.ring);
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
    //
    // 1, not 0, and the difference is not cosmetic: the kernel only compares
    // RLIMIT_CORE against the dump size when core_pattern names a *file*.  When
    // it starts with '|' -- Ubuntu ships `|/usr/share/apport/apport ...` -- that
    // check is skipped and a limit of 0 dumps anyway; 1 is the value do_coredump
    // treats as "abort the core" for pipes (its recursive-crash guard).  With 0,
    // a target that abort()s walks its ~114 TB of shadow VMAs inside
    // do_coredump, at 100% system time, and SIGKILL does not land while
    // PF_DUMPCORE is set -- so the launcher's timeout kill cannot reclaim it.
    struct rlimit limit;
    limit.rlim_cur = limit.rlim_max = 1;
    setrlimit(RLIMIT_CORE, &limit);

    child_disable_aslr();

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

/* Close out an exec-path run: reap the child and close the read end, so that
   the next call short-circuits on pipefds[0] < 0.  Lifted out of the tail of
   symsan_read_event() so the ring path below can end a run the same way rather
   than growing a second version of it. */
static void exec_run_teardown(void) {
  if (g_config.symsan_pid > 0) {
    waitpid(g_config.symsan_pid, &g_config.exit_status, 0);
    g_config.symsan_pid = -1;
  }
  if (g_config.pipefds[0] >= 0) {
    close(g_config.pipefds[0]); // close the read fd
    g_config.pipefds[0] = -1;
  }
}

/* One event on the exec-per-run path, with the ring up.

   Here the pipe's write end really is in the traced child, so its EOF still
   means "the child is gone" -- which is the one control signal this path has
   and the reason we keep select()ing on it.  Everything the child wrote is
   committed to the ring by the time we see that EOF, so the ring is drained
   after it and not before.

   So this is the one path that still wakes on the pipe: a futex cannot wait on
   a file descriptor, and here the end of a run *is* a file descriptor event.
   The producer sees that in flags().forksrv and sends a doorbell byte instead
   of a FUTEX_WAKE -- but it still only sends one when the head cursor says we
   are waiting, so arming is what we do before the select() either way. */
static ssize_t ring_read_event(void *buf, size_t size, unsigned int timeout) {
  while (1) {
    if (ring_spin(buf, size)) {
      return (ssize_t)size;
    }

    uint64_t head = ring_arm_head();
    if (symsan_ring_used(head, symsan_ring_load_own(&g_config.ring->tail)) >=
        size) {
      ring_disarm_head();
      continue; // it arrived while we were arming; take it on the next pass
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(g_config.pipefds[0], &rfds);

    struct timeval tv;
    struct timeval *ptv = NULL;
    if (timeout) {
      tv.tv_sec = (timeout / 1000);
      tv.tv_usec = (timeout % 1000) * 1000;
      ptv = &tv;
    }

    // Unlike the pipe path, timeout == 0 blocks here rather than falling
    // straight into read(): the blocking used to be the read()'s job and now
    // there is nothing else to do it.
    int ret = select(g_config.pipefds[0] + 1, &rfds, NULL, NULL, ptv);
    ring_disarm_head();

    if (ret < 0 && errno == EINTR) {
      continue;
    }

    if (ret <= 0) {
      // Timed out, or select() failed.  Same handling as the pipe path: kill
      // the run, mark it, and close it out.
      if (g_config.symsan_pid > 0) {
        kill(g_config.symsan_pid, SIGKILL);
      }
      g_config.is_killed = 1;
      exec_run_teardown();
      return -1;
    }

    ssize_t n = ring_drain_doorbell();
    if (n > 0) {
      continue; // a doorbell; the payload is in the ring
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      exec_run_teardown();
      return -1;
    }

    // EOF: the child has exited, so no further commit is coming.  Take what is
    // there before ending the run -- events can land between the check at the
    // top of this iteration and select() returning.
    if (ring_take(buf, size)) {
      return (ssize_t)size; // more may follow; the EOF is still there next call
    }
    size_t partial = ring_take_partial(buf, size);
    if (partial == 0) {
      ring_check_target();
    }
    exec_run_teardown();
    return (ssize_t)partial; // 0 is end of trace, short is a truncated record
  }
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

  if (g_config.ring != NULL) {
    return ring_read_event(buf, size, timeout);
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

  // Likewise for the event ring.  Nothing to unlink -- ring_create() did that
  // as soon as it had the mapping.
  if (g_config.ring != NULL) {
    munmap(g_config.ring, g_config.ring_size);
    g_config.ring = NULL;
    g_config.ring_size = 0;
  }
  if (g_config.ring_fd != -1) {
    close(g_config.ring_fd);
    g_config.ring_fd = -1;
  }

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
