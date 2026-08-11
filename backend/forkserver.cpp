/*
  An AFL-style fork server for the fastgen backend.

   ------------------------------------------------

   Copyright 2021-2026 UC Riverside. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

/*
  Without this, the driver pays a full execv, dynamic link, shadow/union
  mapping and interceptor setup for every single input it traces.  All of that
  is input-independent, so we do it once and fork per input instead.

  The protocol is AFL's, deliberately -- fd 198 carries "run now", fd 199
  carries the child pid and then its wait status.  Following it exactly means a
  SymSan-instrumented binary can also be driven by AFL++ or LibAFL's forkserver
  executor unchanged, which matters once the coverage backend lands.  It is not
  thoroupy's control-pipe ticket protocol: that carries an under-constrained
  execution's input as a payload, and here the input is a file the driver has
  already written.

  Where this differs from a plain AFL target: the driver is also reading a
  stream of trace events from the solver pipe, and on the exec path it learns
  that a run has finished by seeing EOF when the traced process exits.  Here the
  write end of that pipe stays open in this process, so EOF never comes.  The
  status word on fd 199 takes its place -- and because it is only written after
  waitpid() has reaped the child, every event that child produced is already in
  the pipe by the time the driver sees it.  So the driver watches both fds,
  drains events first, and treats "pipe empty, status ready" as end of trace.
  Nothing extra goes into the event stream, which keeps this protocol exactly
  AFL's.

  With the event ring up (include/symsan_ring.h) the driver no longer watches
  fds at all while a run is in flight -- it sleeps on the ring's head cursor,
  because that is where the events are and a syscall per event is what the ring
  exists to remove.  A futex cannot wait on a file descriptor, so a run that
  ends without another event would leave it asleep with the status sitting
  unread on 199.  __taint_ring_end_of_run() is the one extra thing this file
  does about that: it sets a bit in that same cursor, which is an edge and not a
  message.  fd 199 still carries the status, the driver still reaps it there,
  and the protocol on the wire is still exactly AFL's.
*/

#include "solver_common.h"

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace __dfsan;

// AFL's fork server file descriptors; see FORKSRV_FD in AFL++'s config.h.
// The fuzzer (here, the SymSan driver) dup2()s its ends onto these numbers
// before exec, so they are fixed rather than configurable.
static const int kForksrvFd = 198;
static const int kForksrvStatusFd = kForksrvFd + 1;

extern "C" void InitializeSymSanForkServer() {
  if (!flags().forksrv) return;

  // Handshake: four bytes tell the driver the fork server is live.  If this
  // fails, nobody is listening on 199 -- the binary was run standalone with
  // forksrv=1 by mistake -- so fall through and behave like a one-shot run
  // rather than dying.
  uint32_t hello = 0;
  if (internal_write(kForksrvStatusFd, &hello, sizeof(hello)) !=
      sizeof(hello)) {
    Report("WARNING: forksrv=1 but no fork server pipe on fd %d, "
           "running once\n", kForksrvStatusFd);
    return;
  }

  while (true) {
    // Wait for the driver to say it has staged the next input.  A short read
    // means the driver closed the control pipe, i.e. it is finished with us.
    uint32_t go = 0;
    if (internal_read(kForksrvFd, &go, sizeof(go)) != sizeof(go))
      internal__exit(0);

    int pid = fork();
    if (pid < 0) {
      Report("FATAL: fork server could not fork: %d\n", pid);
      internal__exit(1);
    }

    if (pid == 0) {
      // Child: drop the fork server's fds so that only the parent speaks the
      // protocol, then return into dfsan_init(), which goes on to load the
      // input and hand control to the target's main().  The solver pipe stays
      // open -- that is what the child is here to write to.
      internal_close(kForksrvFd);
      internal_close(kForksrvStatusFd);
      return;
    }

    // Parent: AFL's protocol wants the pid first, so that the driver can kill
    // the child on timeout without waiting for it to finish.
    if (internal_write(kForksrvStatusFd, &pid, sizeof(pid)) != sizeof(pid))
      internal__exit(0);

    int status = 0;
    // The driver may kill the child on a timeout, so an interrupted wait is
    // normal; only a real error is fatal.
    while (waitpid(pid, &status, 0) < 0) {
      if (errno == EINTR) continue;
      Report("FATAL: fork server could not wait for %d\n", pid);
      internal__exit(1);
    }

    // Order matters: the child is reaped, so its trace events are all in the
    // solver pipe ahead of this.  The driver can safely read this as "that was
    // the whole trace".
    //
    // The ring's end-of-run bit goes first, and that order is the whole reason
    // it is a separate call rather than something the driver infers from the
    // status.  Set it afterwards instead and the driver could read the status,
    // reap, and start the next run -- resetting the ring on its way -- before
    // this process got there, and the bit would land on the following run's
    // cursor and end that trace at zero events.  Ahead of the write there is no
    // such window: the driver has nothing to act on until the status arrives.
    __taint_ring_end_of_run();

    if (internal_write(kForksrvStatusFd, &status, sizeof(status)) !=
        sizeof(status))
      internal__exit(0);
  }
}
