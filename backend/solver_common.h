/*
  Common code shared between fastgen and thoroupy solvers.

   ------------------------------------------------

   Written by Chengyu Song <csong@cs.ucr.edu> and
              Ju Chen <jchen757@ucr.edu>

   Copyright 2021-2025 UC Riverside. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef SOLVER_COMMON_H
#define SOLVER_COMMON_H

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "dfsan/dfsan.h"

using namespace __dfsan;

//===----------------------------------------------------------------------===//
// Shared Global State
//===----------------------------------------------------------------------===//

extern uint32_t __instance_id;
extern uint32_t __session_id;
extern int __pipe_fd;
extern int __control_pipe_fd;

// filter, defined in dfsan.cpp
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uint32_t __taint_trace_callstack;

//===----------------------------------------------------------------------===//
// Shared Helper Functions
//===----------------------------------------------------------------------===//

// Note: get_const_result() is defined in dfsan.h

// Map the shared-memory event ring, if the driver gave us one (ring_fd).  Must
// be called from dfsan_init *above* the fork point, so that every child
// inherits the one MAP_SHARED mapping instead of making its own -- see
// include/symsan_ring.h.  A no-op when ring_fd is -1, which is how every
// pipe-only path (ucsan, the tests, an A/B run) keeps working unchanged.
extern "C" void InitializeSymSanEventRing();

// Hand one event to the driver.  Goes on the ring when one is mapped and down
// __pipe_fd when it is not; the two are byte-for-byte the same stream, which is
// the whole point of the ring being a byte ring.  Callers keep their existing
// `if (__pipe_fd < 0) return;` guard -- __pipe_fd is still open either way,
// since the exec-per-run path uses it as the wake-up doorbell.
void __taint_emit(const void *buf, size_t size);

// Set the end-of-run bit in the ring's head cursor and wake a consumer that is
// asleep on it.  Called by the fork server from the parent, after waitpid() and
// before the wait status goes out on fd 199.
//
// This is what lets the consumer block on the ring alone.  It is not a second
// end-of-trace protocol: fd 199 still carries the status and is still what the
// launcher reaps: this only tells a sleeping consumer to go and look.  A no-op
// when there is no ring, where select() on fd 199 does the same job.
//
// The ordering is load-bearing in both directions.  After waitpid(), so every
// event the child produced is already committed -- the same argument the status
// write has always rested on.  *Before* the status write, so that the launcher
// cannot reap, start the next run, and reset the ring in the window before we
// get here -- which would drop this bit onto the following run's cursor and end
// that trace at zero events.
void __taint_ring_end_of_run();

// Send conditional branch info to solver
void __taint_send_cond(dfsan_label label, uint8_t result,
                       uint8_t add_nested, uint8_t loop_flag,
                       uint32_t cid, void *addr);

#endif // SOLVER_COMMON_H
