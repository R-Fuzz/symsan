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

#include "solver_common.h"

#include "symsan_ring.h"

#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

//===----------------------------------------------------------------------===//
// Shared Global State
//===----------------------------------------------------------------------===//

uint32_t __instance_id;
uint32_t __session_id;
int __pipe_fd;
int __control_pipe_fd;

//===----------------------------------------------------------------------===//
// The event ring
//
// See include/symsan_ring.h for the layout and the reason this replaced a
// write() per event.  Null means "no ring was handed to us", and every emit
// falls back to the pipe -- that is how ucsan, the lit suite and an A/B run all
// keep working with no other change.
//
// Mapped in InitializeSymSanEventRing() from dfsan_init, above the fork point,
// so this pointer is inherited by every child rather than re-established.
//===----------------------------------------------------------------------===//

static struct symsan_ring_hdr *__event_ring = nullptr;

// How long we are willing to sit on a full ring before deciding the consumer is
// gone.  A full ring means the driver is behind, which is legitimate and common
// under a slow solver, so the slice is generous and we only give up after
// enough of them to rule out a live-but-slow consumer.  What we must not do is
// wait forever: with a pipe a dead consumer gives the producer EPIPE, and the
// fork server hanging on a dead driver is far worse than one lost trace.
static const long kFullRingWaitNsec = 250 * 1000 * 1000;  // 250ms
static const int kFullRingMaxWaits = 40;                  // ~10s in total

// Spin before flagging ourselves as waiting; see SYMSAN_RING_PAUSE.
static const int kFullRingSpins = 256;

struct symsan_timespec { long tv_sec; long tv_nsec; };

static inline void ring_futex_wait(uint32_t *word, uint32_t expect) {
  struct symsan_timespec ts = { 0, kFullRingWaitNsec };
  // Bare syscall on purpose: the sanitizer's own FutexWait()
  // (sanitizer_mutex.h:362) takes no timeout, and internal_syscall is static
  // inside an .inc we cannot reach from here.  forkserver.cpp already calls
  // libc fork()/waitpid(), so libc is fair game in this directory.
  syscall(SYS_futex, word, SYMSAN_FUTEX_WAIT, expect, &ts, nullptr, 0);
}

// Block until the ring has room for `size` bytes.  Returns false if the
// consumer never took anything, which the caller treats the way it treats a
// failed write().
static bool ring_wait_for_room(struct symsan_ring_hdr *ring, uint64_t head,
                               size_t size) {
  for (int spin = 0; spin < kFullRingSpins; ++spin) {
    uint64_t tail = symsan_ring_load_tail_acq(ring);
    if (ring->capacity - symsan_ring_used(head, tail) >= size)
      return true;
    SYMSAN_RING_PAUSE();
  }

  // The budget below counts stalls, not attempts, and it has to: the consumer
  // drains a record at a time, so a large payload can watch tail move a dozen
  // times before enough of it frees up.  Every one of those is a wake-up that
  // returns here with no room yet, and counting them as strikes would kill a
  // run whose consumer is plainly alive.  Progress on tail is the liveness
  // signal, so seeing it resets the count and "no progress at all for the whole
  // budget" is what we actually mean by a dead consumer.
  uint64_t last_tail = symsan_ring_bytes(symsan_ring_load_tail_acq(ring));
  int stalls = 0;

  while (stalls < kFullRingMaxWaits) {
    // Claim the waiting bit *in the tail cursor itself* and re-check against
    // the word that claim returned.  There is no separate flag to keep in step
    // with the cursor any more, and no store-load ordering rule to get right:
    // the consumer's own advance is the read-modify-write that observes this
    // bit, so it cannot advance without seeing it.
    uint64_t tail = symsan_ring_arm(&ring->tail) | SYMSAN_RING_WAITING;
    if (ring->capacity - symsan_ring_used(head, tail) >= size) {
      symsan_ring_disarm(&ring->tail);
      return true;
    }
    // And if the consumer advances between here and the syscall, the kernel's
    // own compare against `tail` fails and we come straight back with EAGAIN
    // rather than sleeping out the slice on a condition that is already true.
    ring_futex_wait(symsan_ring_futex_word(&ring->tail),
                    symsan_ring_futex_expect(tail));
    symsan_ring_disarm(&ring->tail);

    uint64_t now = symsan_ring_bytes(symsan_ring_load_tail_acq(ring));
    if (now != last_tail) {
      last_tail = now;
      stalls = 0;
    } else {
      ++stalls;
    }
  }

  return false;
}

// Wake a consumer that is asleep waiting for events.
//
// Two mechanisms, because the consumer has two ways of blocking and they are
// not interchangeable.  Under the fork server it sleeps on the head cursor, so
// a futex reaches it.  On the exec-per-run path it cannot: end of run there is
// the child's exit closing the pipe, that EOF is the only signal it gets, and a
// futex cannot wait on a file descriptor -- FUTEX_FD was removed from Linux in
// 2.6.26 and nothing replaced it.  So that path stays on select(), and what we
// send it is a content-free doorbell byte down the pipe that used to carry the
// payload.
//
// flags().forksrv is the right discriminator and not a guess: the launcher puts
// it in TAINT_OPTIONS alongside the ring fd, from the same variable that
// decides which consumer loop it will run, and rebuilds the string if it ever
// falls back to exec (driver/launcher/launch.c, build_symsan_env).
static void ring_wake_consumer(struct symsan_ring_hdr *ring) {
  // Clear before waking, not after: FUTEX_WAIT only sleeps while the word still
  // matches what the waiter expected, so leaving the bit set would let a waiter
  // that is a moment behind us sleep on a condition we have already satisfied.
  // The advance changed the word too, so this is belt and braces there -- what
  // it is really for is the next advance, which would otherwise keep finding a
  // stale bit and paying a syscall for a consumer that is long since awake.
  symsan_ring_disarm(&ring->head);

  if (flags().forksrv) {
    syscall(SYS_futex, symsan_ring_futex_word(&ring->head), SYMSAN_FUTEX_WAKE,
            1, nullptr, nullptr, 0);
    return;
  }

  uint8_t doorbell = 0;
  internal_write(__pipe_fd, &doorbell, 1);
}

//===----------------------------------------------------------------------===//
// Shared Helper Functions
//===----------------------------------------------------------------------===//

extern "C" void InitializeSymSanEventRing() {
  if (flags().ring_fd < 0)
    return;

  uint64_t capacity = flags().ring_size ? (uint64_t)flags().ring_size
                                        : (uint64_t)SYMSAN_RING_DEFAULT_CAPACITY;
  if (!symsan_ring_size_ok(capacity)) {
    Printf("FATAL: bad event ring size %zu (want a power of two >= 4096)\n",
           (size_t)capacity);
    Die();
  }

  uptr ret = internal_mmap(nullptr, symsan_ring_total_size(capacity),
                           PROT_READ | PROT_WRITE, MAP_SHARED,
                           flags().ring_fd, 0);
  int err;
  if (internal_iserror(ret, &err)) {
    Printf("FATAL: error mapping event ring, errno %d\n", err);
    Die();
  }

  struct symsan_ring_hdr *ring = (struct symsan_ring_hdr *)ret;
  if (ring->magic != SYMSAN_RING_MAGIC ||
      ring->version != SYMSAN_RING_VERSION ||
      ring->capacity != capacity) {
    // Not a "fall back to the pipe" case, even though the pipe still works:
    // the driver that passed ring_fd is reading the ring, so falling back
    // would give it an empty trace and no error, which is the one failure mode
    // worth spending a hard stop to avoid.
    Printf("FATAL: event ring header mismatch: got magic %x version %u cap %zu,"
           " this binary wants magic %x version %u cap %zu. A version"
           " difference means the target and the driver were built from"
           " different trees; rebuild the target.\n",
           ring->magic, ring->version, (size_t)ring->capacity,
           SYMSAN_RING_MAGIC, SYMSAN_RING_VERSION, (size_t)capacity);
    Die();
  }

  __event_ring = ring;
  AOUT("event ring %d, %zu bytes\n", flags().ring_fd, (size_t)capacity);
}

void __taint_ring_end_of_run() {
  struct symsan_ring_hdr *ring = __event_ring;
  if (ring == nullptr)
    return;

  // Same shape as a commit, and for the same reason: the bit that says whether
  // anyone is listening comes back from the operation that changes the word, so
  // there is no window between setting EOR and reading WAITING.
  uint64_t prev = symsan_ring_set_eor(&ring->head);
  if (prev & SYMSAN_RING_WAITING) {
    ring_wake_consumer(ring);
  }
}

void __taint_emit(const void *buf, size_t size) {
  struct symsan_ring_hdr *ring = __event_ring;
  if (ring == nullptr) {
    if (internal_write(__pipe_fd, buf, size) < 0) {
      Die();
    }
    return;
  }

  // A record bigger than the whole ring can never fit, no matter how patient
  // the consumer is, because the consumer waits for the entire record to be
  // queued before it copies any of it out.  So say so now rather than after ten
  // seconds of a "consumer is gone" wait that would name the wrong cause: the
  // consumer is fine and the ring is too small.  Only reachable with a ring
  // sized well below the default against a target doing an enormous memcmp --
  // the memcmp and table payloads (fastgen.cpp:317, :473) are the only records
  // whose length the target controls.
  if (size > ring->capacity) {
    Printf("FATAL: event ring too small for a %zu-byte record (capacity %zu); "
           "raise SYMSAN_RING_SIZE\n", size, (size_t)ring->capacity);
    Die();
  }

  // We are the only writer of head's *count*, so a relaxed load is enough to
  // place the record; the consumer can set WAITING under us at any moment, but
  // nothing here reads that bit -- the only reader is the return value of the
  // advance below, which is an atomic RMW and therefore current by construction.
  uint64_t head = symsan_ring_load_own(&ring->head);
  uint64_t tail = symsan_ring_load_tail_acq(ring);
  if (ring->capacity - symsan_ring_used(head, tail) < size) {
    // Block, never drop: a dropped record desynchronizes the consumer's byte
    // stream for the rest of the run, which is exactly what a pipe's own
    // back-pressure protects us from today.
    if (!ring_wait_for_room(ring, head, size)) {
      Printf("FATAL: event ring full for %d seconds, consumer is gone\n",
             (int)((kFullRingWaitNsec / 1000000000.0) * kFullRingMaxWaits));
      Die();
    }
  }

  symsan_ring_put(ring, head, buf, size);

  // Publish, and find out in the same instruction whether anyone was waiting on
  // it.  That is the whole steady-state cost of an event now: a memcpy and one
  // `lock xadd`.  The consumer only sets that bit when it finds the ring empty,
  // so the branch below is O(times the queue drains) and not O(events) -- 151
  // times against 150,149 events on the libpng corpus.
  uint64_t prev = symsan_ring_advance(&ring->head, size);
  if (prev & SYMSAN_RING_WAITING) {
    ring_wake_consumer(ring);
  }
}

void __taint_send_cond(dfsan_label label, uint8_t result,
                       uint8_t add_nested, uint8_t loop_flag,
                       uint32_t cid, void *addr) {

  if (__pipe_fd < 0)
    return;

  uint16_t flags = 0;
  if (add_nested) flags |= F_ADD_CONS;

  // set the loop flags according to branching results
  switch (loop_flag) {
    case TrueBranchLoopExit:
      flags |= result ? F_LOOP_EXIT : F_LOOP_LATCH;
      break;
    case TrueBranchLoopLatch:
      flags |= result ? F_LOOP_LATCH : F_LOOP_EXIT;
      break;
    case FalseBranchLoopExit:
      flags |= result ? F_LOOP_LATCH : F_LOOP_EXIT;
      break;
    case FalseBranchLoopLatch:
      flags |= result ? F_LOOP_EXIT : F_LOOP_LATCH;
      break;
    default:
      // No loop flag or unrecognized flag, do nothing
      break;
  }

  // send info
  pipe_msg msg = {
    .msg_type = cond_type,
    .flags = flags,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .id = cid,
    .label = label,
    .result = result
  };

  __taint_emit(&msg, sizeof(msg));
}
