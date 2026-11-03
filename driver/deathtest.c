/*
  The event channel's death paths, which nothing else reaches.

   ------------------------------------------------

   Copyright 2021-2026 UC Riverside. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

/*
  Every one of these used to be a file-descriptor event, and a file descriptor
  reports a dead peer whether or not the peer meant to say anything: the child
  exits and the pipe hits EOF, the fork server dies and fd 199 goes readable.
  With the ring, the consumer sleeps on a word in shared memory that a dead
  process cannot touch, so each of those has to be arranged for by hand -- and
  every one that is not arranged for is an indefinite hang rather than an error,
  which is why they are worth a test of their own.

  The three, and what is supposed to happen:

    child   The traced child stops emitting and never exits.  The caller's
            timeout has to be enforced by the consumer itself now, because there
            is no select() left to enforce it.  Expect -1 within the timeout,
            the child killed, and the launcher still usable for the next run --
            the point of killing the run rather than the server.

    server  The fork server is killed while the consumer is blocked with no
            timeout at all.  Nothing will ever set the end-of-run bit, so the
            only thing that can end this wait is the consumer noticing by
            itself.  Expect end of trace within a couple of seconds, from the
            bounded futex slice and its look at fd 199.

    stuck   The consumer stops reading while the ring is far too small for the
            run, so the producer blocks on a full ring with nobody draining it.
            A pipe would have given it EPIPE the moment we died; here it has to
            give up on its own.  Expect the run to end rather than wedge the
            fork server, and the launcher to be usable afterwards.
            Now: a consumer that stops reading but lives is only slow, and the
            producer waits for it as a pipe would.  Expect the whole run once
            it reads again, ended by its own timeout.

    dead    The consumer is killed while the producer is blocked on a full
            ring.  Expect the traced child to end within a few seconds: the
            event pipe's read end died with the consumer, and the producer
            asks it on every slice of its wait.

  Each case runs under an alarm, so a regression shows up as HUNG with the case
  named rather than as whatever the harness does when a test never finishes.
*/

#include "launch.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The size of one pipe_msg (runtime/dfsan/dfsan.h), which is the unit every
   front-end asks for first.  Spelled out rather than included, because none of
   these cases look at a field: what is under test is whether the call comes
   back at all, and the payload of a record with one is left in the channel on
   purpose -- a desynchronized stream is fine when the run is about to end. */
#define EVENT_SIZE 36

#define UNION_TABLE_SIZE (0xc00000000ULL)

static const char *g_case = "?";

static void on_alarm(int sig) {
  (void)sig;
  static const char msg[] = "HUNG\n";
  ssize_t ignored = write(2, msg, sizeof(msg) - 1);
  (void)ignored;
  _exit(3);
}

static void arm_alarm(unsigned int secs) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_alarm;
  // No SA_RESTART: the whole question here is whether a blocked consumer can be
  // got out of, and a restarting alarm would answer it for us.
  sigaction(SIGALRM, &sa, NULL);
  alarm(secs);
}

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static int fail(const char *what) {
  fprintf(stderr, "FAIL %s: %s\n", g_case, what);
  return 1;
}

/* Our only direct child at this point is the fork server; the traced child is
   its child, not ours.  The launcher does not hand out that pid and has no
   reason to, so read it back off /proc rather than widening the API for a
   test. */
static pid_t find_child_of(pid_t me) {
  DIR *proc = opendir("/proc");
  if (proc == NULL) return -1;

  pid_t found = -1;
  struct dirent *e;

  while ((e = readdir(proc)) != NULL) {
    char *end = NULL;
    long pid = strtol(e->d_name, &end, 10);
    if (end == NULL || *end != '\0' || pid <= 0) continue;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
    FILE *f = fopen(path, "r");
    if (f == NULL) continue;

    // comm can contain spaces and parentheses, so ppid is found from the last
    // ')' rather than by counting fields from the front.
    char line[512];
    char *got = fgets(line, sizeof(line), f);
    fclose(f);
    if (got == NULL) continue;

    char *close = strrchr(line, ')');
    if (close == NULL) continue;
    char state;
    int ppid = 0;
    if (sscanf(close + 1, " %c %d", &state, &ppid) != 2) continue;

    if ((pid_t)ppid == me) {
      found = (pid_t)pid;
      break;
    }
  }

  closedir(proc);
  return found;
}

static pid_t find_forkserver(void) { return find_child_of(getpid()); }

/* Whether a pid is gone: exited, or a zombie nobody has reaped yet (its parent,
   the fork server, may itself be on its way out). */
static int pid_gone(pid_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
  FILE *f = fopen(path, "r");
  if (f == NULL) return 1;
  char line[512];
  char *got = fgets(line, sizeof(line), f);
  fclose(f);
  if (got == NULL) return 1;
  char *close = strrchr(line, ')');
  char state = 0;
  if (close == NULL || sscanf(close + 1, " %c", &state) != 1) return 1;
  return state == 'Z' || state == 'X';
}

/* Set up the launcher the way every front-end does, plus the fork server, which
   is the configuration all three cases are about.  The fd stays open for the
   life of the process: symsan_run() wants one per run and none of these cases
   changes the input between runs. */
static int g_input_fd = -1;

static int launcher_start(const char *target, const char *input) {
  g_input_fd = open(input, O_RDONLY);
  if (g_input_fd < 0) {
    fprintf(stderr, "FAIL %s: open %s: %s\n", g_case, input, strerror(errno));
    return -1;
  }
  if (symsan_init(target, UNION_TABLE_SIZE) == (void *)-1) {
    fprintf(stderr, "FAIL %s: symsan_init: %s\n", g_case, strerror(errno));
    return -1;
  }
  symsan_set_input(input);
  symsan_set_bounds_check(1);
  symsan_set_forkserver(1);

  char *const argv[] = {(char *)target, (char *)input, NULL};
  symsan_set_args(2, argv);
  return 0;
}

static int launcher_run(void) { return symsan_run(g_input_fd); }

/* Drain a run to its end, or to `budget_ms`, whichever comes first.  Returns
   how many events came back; *last_ret is what ended it -- 0 for end of trace,
   -1 for a timeout or error, and a positive size when the budget ran out with
   the run still going, which is itself a failure for every case here. */
static long drain(unsigned int timeout, uint64_t budget_ms, int *last_ret) {
  unsigned char buf[EVENT_SIZE];
  uint64_t deadline = now_ms() + budget_ms;
  long events = 0;

  while (now_ms() < deadline) {
    ssize_t n = symsan_read_event(buf, sizeof(buf), timeout);
    *last_ret = (int)n;
    if (n <= 0) break;
    events++;
  }
  return events;
}

//===----------------------------------------------------------------------===//
// The cases
//===----------------------------------------------------------------------===//

/* A child that stops talking and does not exit.  The consumer's own deadline is
   the only thing that can end this, and if it does not, the fork server is
   wedged behind a waitpid() that never returns. */
static int case_child(const char *target, const char *input) {
  if (launcher_start(target, input) < 0) return 1;

  if (launcher_run() != 0) return fail("first run did not start");

  // Read until the target goes quiet.  Every call has the same 500ms budget, so
  // the one that lands after it has stopped emitting is the one under test.
  uint64_t began = now_ms();
  int last = 0;
  long events = drain(500, 15000, &last);
  uint64_t took = now_ms() - began;

  if (last == 0) {
    return fail("run ended by itself; the target is not hanging");
  }
  if (last != -1) {
    return fail("expected -1 on the timeout");
  }
  printf("child: %ld events then -1 after %llums\n", events,
         (unsigned long long)took);

  // The run was killed, not the server: the next one has to work.  This is the
  // half a bounded wait gets wrong most easily -- giving up on the wait but
  // leaving the protocol out of step, so that every later run reads the
  // previous one's status.
  if (launcher_run() != 0) return fail("second run did not start");
  events = drain(500, 15000, &last);
  if (last != -1) return fail("second run did not time out the same way");
  printf("child: launcher still usable, %ld events on the second run\n", events);

  symsan_terminate();
  symsan_destroy();
  printf("PASS child\n");
  return 0;
}

/* The fork server killed under a consumer that is blocked with no timeout.  Its
   end of fd 199 closes, but nobody is watching fd 199 any more -- the consumer
   is asleep on a word in shared memory that a dead process cannot write. */
static int case_server(const char *target, const char *input) {
  if (launcher_start(target, input) < 0) return 1;

  if (launcher_run() != 0) return fail("run did not start");

  pid_t server = find_forkserver();
  if (server <= 0) return fail("could not find the fork server pid");

  pid_t killer = fork();
  if (killer < 0) return fail("fork");
  if (killer == 0) {
    // Long enough that the consumer below is asleep rather than still spinning
    // through the events the target emits at the start of the run.
    usleep(1500 * 1000);
    kill(server, SIGKILL);
    _exit(0);
  }

  uint64_t began = now_ms();
  int last = 0;
  // timeout 0: no deadline of our own, so the only thing that can return is the
  // consumer noticing the server is gone.
  long events = drain(0, 20000, &last);
  uint64_t took = now_ms() - began;

  waitpid(killer, NULL, 0);

  if (last > 0) return fail("still reading events after the server died");
  printf("server: %ld events, then %d after %llums\n", events, last,
         (unsigned long long)took);

  if (took > 10000) {
    return fail("took too long to notice; the backstop is not firing");
  }

  symsan_terminate();
  symsan_destroy();
  printf("PASS server\n");
  return 0;
}

/* A consumer that stops reading with the ring far too small to hold the run.
   The producer blocks on a full ring and has to give up by itself: there is no
   EPIPE for shared memory, and a producer that waits forever takes the fork
   server down with it, since the server is inside waitpid().

   It no longer gives up on a consumer that is only slow.  thoroupy's manager
   solves in the thread that drains the ring, a v8 constraint took longer than
   the ~10s of patience, and the trace died (exit 1) under a live consumer.  So
   the producer asks the event pipe whether its consumer still holds the read
   end, and waits as long as it does, as a pipe write would have; case_dead is
   the consumer that does not. */
static int case_stuck(const char *target, const char *input) {
  if (launcher_start(target, input) < 0) return 1;

  if (launcher_run() != 0) return fail("run did not start");

  // Read nothing at all for long enough that the producer fills the ring and
  // exhausts its patience -- which is ~10s, kFullRingWaitNsec times
  // kFullRingMaxWaits in backend/solver_common.cpp.  From the target's side
  // this is indistinguishable from a consumer that has died.
  // (No longer: the read end of our pipe tells it we are alive.)
  sleep(13);

  // Then read again: the rest of the run comes through, and it ends the way
  // case_child's does, by our own timeout on a target gone quiet.  A producer
  // that had given up leaves only what the ring held, 4096 bytes, ~113 events.
  int last = 0;
  uint64_t began = now_ms();
  long events = drain(2000, 20000, &last);
  uint64_t took = now_ms() - began;

  if (last > 0) return fail("run never ended");
  printf("stuck: %ld events after the stall, then %d after %llums\n", events,
         last, (unsigned long long)took);
  if (events <= 4096 / EVENT_SIZE)
    return fail("the producer gave up on a consumer that was only slow");
  if (last != -1) return fail("expected -1 on the timeout");

  // Whatever happened to the run, the fork server must still be there.
  if (launcher_run() != 0) return fail("launcher unusable after the stall");
  printf("stuck: launcher still usable\n");

  symsan_terminate();
  symsan_destroy();
  printf("PASS stuck\n");
  return 0;
}

/* The consumer killed while the producer is blocked on a full ring.  Its read
   end of the event pipe closes with it, and the producer must notice that by
   itself and end the trace: the fork server it would otherwise hold up has
   nobody left to report to either.  The consumer here is a child of ours, so
   the pipe's read end dies with it and we hold none. */
static int case_dead(const char *target, const char *input) {
  int pids[2];
  if (pipe2(pids, O_CLOEXEC) != 0) return fail("pipe2");

  pid_t consumer = fork();
  if (consumer < 0) return fail("fork");
  if (consumer == 0) {
    close(pids[0]);
    if (launcher_start(target, input) < 0) _exit(1);
    if (launcher_run() != 0) _exit(1);
    pid_t server = find_forkserver(), traced = -1;
    for (int i = 0; i < 200 && server > 0 && traced <= 0; i++) {
      traced = find_child_of(server);
      if (traced <= 0) usleep(10 * 1000);
    }
    pid_t both[2] = {server, traced};
    if (write(pids[1], both, sizeof(both)) != sizeof(both)) _exit(1);
    // read nothing, ever
    for (;;) pause();
  }

  close(pids[1]);
  pid_t both[2] = {-1, -1};
  if (read(pids[0], both, sizeof(both)) != sizeof(both) || both[1] <= 0) {
    kill(consumer, SIGKILL);
    waitpid(consumer, NULL, 0);
    return fail("could not find the traced child");
  }
  pid_t server = both[0], traced = both[1];

  // Long enough that the producer has filled the ring and is asleep on it.
  usleep(1500 * 1000);
  kill(consumer, SIGKILL);
  waitpid(consumer, NULL, 0);

  // Well under the ~10s budget a producer with no pipe to ask still has.
  uint64_t began = now_ms();
  while (!pid_gone(traced) && now_ms() - began < 5000) usleep(50 * 1000);
  uint64_t took = now_ms() - began;
  int gone = pid_gone(traced);
  kill(traced, SIGKILL);
  kill(server, SIGKILL);

  if (!gone) return fail("the producer is still waiting on a dead consumer");
  printf("dead: the traced child ended %llums after its consumer\n",
         (unsigned long long)took);
  printf("PASS dead\n");
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <child|server|stuck|dead> target input\n", argv[0]);
    return 2;
  }

  g_case = argv[1];
  const char *target = argv[2];
  const char *input = argv[3];

  // Every case has its own budget below this; the alarm is the backstop for a
  // blocking call that never comes back at all.
  arm_alarm(60);

  if (!strcmp(g_case, "child")) return case_child(target, input);
  if (!strcmp(g_case, "server")) return case_server(target, input);
  if (!strcmp(g_case, "stuck")) return case_stuck(target, input);
  if (!strcmp(g_case, "dead")) return case_dead(target, input);

  fprintf(stderr, "unknown case %s\n", g_case);
  return 2;
}
