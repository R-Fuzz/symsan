/*
  Single-producer / single-consumer shared-memory ring for the trace event
  stream.

   ------------------------------------------------

   Copyright 2021-2026 UC Riverside. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

/*
  Why this exists.  The traced process used to write() one ~36-byte message per
  symbolic condition and the driver used to select() + read() one message back,
  three syscalls per event.  Profiled over 682 libpng inputs / 2.886M events
  that was ~56% of a parse-only run and ~27% of a run with solving on -- against
  ~4% for the RGD parser everyone assumed was the cost -- and 984k voluntary
  context switches, one sleep every three events, for two processes that should
  have been pipelining.  The pipe's own buffering bought nothing because the
  consumer read exactly one message per select().

  What replaces it is a byte ring in shared memory.  It is a *byte* ring and not
  a message ring on purpose: symsan_read_event(buf, size, timeout) is already a
  byte-stream API and every caller asks for a size it computed itself, so there
  is nothing for per-message framing to tell them that they do not already know.
  That also makes this a drop-in -- no caller changes, and the variable-length
  memcmp/table payloads stop being a special case.

  Only event bytes travel here.  Control does not: the fork server protocol
  stays on fd 198/199, and the child's wait status on 199 is still the only
  thing that ends a run.  What this file adds is the *edge* that says "go look
  at 199" -- one bit in the head cursor -- because a futex cannot wait on a file
  descriptor and the consumer has to be woken by something.  Getting any of that
  wrong stalls a run rather than corrupting it.

  Layout: this header in the first page, then a power-of-two data region.  Both
  cursors are monotonic and never wrapped -- the data index is cursor & mask --
  which is what lets used/free be plain subtraction with no full-vs-empty
  ambiguity and no wasted slot.  Modelled on LibAFL's LLMP
  (crates/ll_mp/src/lib.rs), minus the page-growth and multi-receiver
  machinery, which exists there because it is a broadcast bus with peers of
  unknown lifetime and we are one process talking to one process.

  Plain C and C++ compatible on purpose: the producer is the sanitizer runtime
  (backend/solver_common.cpp) and the consumer is the launcher
  (driver/launcher/launch.c), and if the two ends ever get separate definitions
  of this layout they will disagree silently.
*/

#ifndef SYMSAN_RING_H
#define SYMSAN_RING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// "SMRG".  Checked by the consumer after mapping; a mismatch means the target
// was built against a different layout, which is worth failing loudly over
// rather than reading someone else's cursors.
//
// Bump the version on any change to what the words below mean, not just to
// where they sit.  This is a real ABI: the runtime is linked into the target
// binary, so a target built an hour ago and a launcher built now are a pairing
// that happens routinely.  Version 2 packs the waiting and end-of-run bits into
// the low bits of the cursors, which a version 1 peer reads as a byte count off
// by a factor of four -- garbage that parses as bad labels at unrelated
// branches, with nothing anywhere naming the cause.
#define SYMSAN_RING_MAGIC 0x534d5247u
#define SYMSAN_RING_VERSION 2u

// The header gets a page to itself so that the data region starts page-aligned
// and no cursor ever shares a cache line with payload bytes.
#define SYMSAN_RING_HDR_SIZE 4096u

// 4 MB.  libpng averages 4231 events/run and peaks around 29k at ~40 bytes
// each, i.e. ~1.2 MB worst case, so on a real target the producer never blocks
// and the two processes genuinely pipeline.  Next to the union table this is
// noise.  Override with the ring_size flag.
#define SYMSAN_RING_DEFAULT_CAPACITY (4u << 20)

#define SYMSAN_RING_CACHELINE 64

// Spin before you sleep, on both sides: a commit on the other end is a memcpy
// and a store, so when the peer is running at all the thing we are waiting for
// is a few hundred nanoseconds away and any syscall to wait for it costs more
// than the wait.  (LLMP spins and never sleeps at all -- lib.rs:1481, :1921 --
// which it can afford because its peers are always live; we idle between runs
// and must not burn a core.)
#if defined(__x86_64__) || defined(__i386__)
#define SYMSAN_RING_PAUSE() __builtin_ia32_pause()
#elif defined(__aarch64__)
#define SYMSAN_RING_PAUSE() __asm__ __volatile__("yield" ::: "memory")
#else
#define SYMSAN_RING_PAUSE() do { } while (0)
#endif

//===----------------------------------------------------------------------===//
// What a cursor word holds.
//
// Not just a byte count: the low two bits carry the wake-up state, and the byte
// count lives above them.  There used to be a separate flag word per direction
// plus a Dekker handshake around it -- store your flag, re-read the peer's
// cursor, both seq_cst, in opposite orders on the two sides.  That is three
// shared words and an argument that has to be re-derived every time someone
// reads it, and it is all in service of one question: does the side that just
// published have to make a syscall to wake the other one?
//
// Packing the answer into the cursor itself makes that question atomic with the
// publish.  Advancing is `lock xadd` of an even value: the carry can never
// reach bit 0, so the peer's bit survives, and the instruction *returns* the
// word it replaced -- so the publisher learns whether anyone was waiting in the
// same operation that made the data visible.  There is no window between the
// two to lose a wake-up in, so there is no handshake to get wrong.  The waiter,
// for its part, sets its bit with `lock or` and then passes the resulting word
// to FUTEX_WAIT as the expected value; the kernel's own compare is what closes
// the race, which is the whole point of the futex ABI and is strictly more
// reliable than reproducing it by hand.
//
// This is free.  Both sides already published with a seq_cst store, which is a
// locked instruction on x86-64, and both then did a seq_cst load of the peer's
// flag.  One `lock xadd` replaces both.
//
//   bit 0  WAITING  the *peer* is blocked on this cursor and wants a wake-up.
//                   On head that is the consumer waiting for events; on tail it
//                   is the producer waiting for room.
//   bit 1  EOR      end of run.  head only, set by the fork server after
//                   waitpid() (see backend/forkserver.cpp) so that a consumer
//                   asleep on head has something to wake it that is not an fd.
//                   It is an edge, not the answer: the wait status on fd 199 is
//                   still what the run actually ended with.
//   bits 2+         the byte count, monotonic, never wrapped.
//
// Sixty-two bits of byte count is not a limit anything can reach.  The futex
// only ever compares the low 32 bits of the word, i.e. 30 bits of count, so a
// waiter could in principle be fooled by a peer that advanced exactly 1 GiB
// between its `lock or` and its FUTEX_WAIT -- a window of a few hundred
// nanoseconds against a target whose worst run to date is 29k events of ~40
// bytes.
//===----------------------------------------------------------------------===//

#define SYMSAN_RING_WAITING 1u
#define SYMSAN_RING_EOR 2u
#define SYMSAN_RING_SHIFT 2

// The two futex ops the blocking paths use, spelled out rather than pulled in
// from <linux/futex.h>: one end of this is the sanitizer runtime, which is a
// bad place to start including kernel headers, and these have been ABI since
// 2.6.
//
// Not the _PRIVATE variants, and that is not a micro-optimisation left on the
// table.  FUTEX_PRIVATE_FLAG tells the kernel to key the futex on (mm, virtual
// address) instead of resolving the address to the page behind it -- correct
// when every waiter shares an address space, wrong here, because our two ends
// are separate processes that share only this mmap and map it at different
// addresses.  The private key then never matches and every wake goes to a queue
// nobody is on.  Measured: the launcher's FUTEX_WAKE returned 0 while the target
// was provably asleep in a 250ms FUTEX_WAIT on the same word (which was then a
// separate prod_waiting flag at header offset 0xc4, and is now the tail cursor)
// -- 25 waits, 25 timeouts, not one EAGAIN.  That one flag was the whole of the
// small-ring slowdown; nothing else about the handshake was wrong.
//
// It hides well: with the 4MB default the producer never fills the ring, so the
// producer's blocking path never runs on a real target.  Only a forced-small
// SYMSAN_RING_SIZE reaches it.
#define SYMSAN_FUTEX_WAIT 0
#define SYMSAN_FUTEX_WAKE 1

struct symsan_ring_hdr {
  uint32_t magic;
  uint32_t version;
  uint64_t capacity;  // power of two, bytes, of the data region

  // head and tail get a cache line each: they are written by different
  // processes on every event, and sharing a line would put the two of them in
  // a ping-pong that costs more than the syscalls this replaces.
  //
  // Each is also the futex word for the side that waits on it -- the consumer
  // sleeps on head, the producer sleeps on tail -- so a cache line each is now
  // load-bearing for a second reason: the kernel hashes the futex key by
  // physical page, and two words a line apart cannot collide in a way that
  // matters.  See the packing note above for what the low two bits mean.
  __attribute__((aligned(SYMSAN_RING_CACHELINE))) uint64_t head;  // producer
  __attribute__((aligned(SYMSAN_RING_CACHELINE))) uint64_t tail;  // consumer
};

// The data region follows the header page.
static inline uint8_t *symsan_ring_data(struct symsan_ring_hdr *h) {
  return (uint8_t *)h + SYMSAN_RING_HDR_SIZE;
}

static inline size_t symsan_ring_total_size(uint64_t capacity) {
  return (size_t)SYMSAN_RING_HDR_SIZE + (size_t)capacity;
}

static inline int symsan_ring_size_ok(uint64_t capacity) {
  // power of two, and big enough that a single record can never exceed it
  return capacity >= 4096 && (capacity & (capacity - 1)) == 0;
}

//===----------------------------------------------------------------------===//
// Cursor access.  Every function here takes and returns the *packed* word, not
// a byte count, so that no caller can advance one without carrying the peer's
// wake-up bit along with it.  Unpack with symsan_ring_bytes() at the two places
// that genuinely want a number.
//
// Each side loads its own cursor relaxed (it is the only writer of the count)
// and the other side's with acquire, which is what pairs with the release edge
// in the commit below.
//===----------------------------------------------------------------------===//

static inline uint64_t symsan_ring_bytes(uint64_t cursor) {
  return cursor >> SYMSAN_RING_SHIFT;
}

static inline uint64_t symsan_ring_load_head_acq(const struct symsan_ring_hdr *h) {
  return __atomic_load_n(&h->head, __ATOMIC_ACQUIRE);
}

static inline uint64_t symsan_ring_load_tail_acq(const struct symsan_ring_hdr *h) {
  return __atomic_load_n(&h->tail, __ATOMIC_ACQUIRE);
}

// Relaxed is enough for one's own cursor only as far as the count goes: the
// peer can still set WAITING under us at any moment.  Nothing reads the bit off
// this load -- the bit is only ever read from what the RMWs below return.
static inline uint64_t symsan_ring_load_own(const uint64_t *cursor) {
  return __atomic_load_n(cursor, __ATOMIC_RELAXED);
}

// Publish `nbytes` and report the word that was there before.  Everything
// written to the data region above must be visible to the other side before the
// cursor that exposes it, which is the release half; the acquire half is what
// makes the WAITING bit in the return value current rather than something we
// might have cached.  seq_cst because the price is the same on x86-64 (the
// `lock` prefix is the whole cost) and because a weaker order here would be one
// more thing to re-derive.
//
// The addend is even, so the carry chain stops at bit 1 and both the peer's
// WAITING bit and EOR come through untouched.  That is the property the whole
// scheme rests on.
static inline uint64_t symsan_ring_advance(uint64_t *cursor, uint64_t nbytes) {
  return __atomic_fetch_add(cursor, nbytes << SYMSAN_RING_SHIFT,
                            __ATOMIC_SEQ_CST);
}

// Announce that we are about to block on this cursor, and return the word as it
// was.  The caller re-checks its condition against that word and, if it still
// wants to sleep, hands `old | WAITING` to FUTEX_WAIT as the expected value.
// From there the kernel does the work: it takes the futex bucket lock, compares,
// and only sleeps if the word still matches, so a peer that advances in the gap
// gets EAGAIN rather than a lost wake-up.
static inline uint64_t symsan_ring_arm(uint64_t *cursor) {
  return __atomic_fetch_or(cursor, (uint64_t)SYMSAN_RING_WAITING,
                           __ATOMIC_SEQ_CST);
}

// Drop the WAITING bit.  Called by the waiter on every path out of a wait, and
// by the waker just before FUTEX_WAKE.  Both, on purpose: the waiter's clear is
// what stops a stale bit costing the peer a syscall per event forever after,
// and the waker's is what keeps that bit from surviving the wake it caused.
// They are idempotent and they commute with symsan_ring_advance(), which only
// ever touches bits 2 and up.
static inline void symsan_ring_disarm(uint64_t *cursor) {
  __atomic_fetch_and(cursor, ~(uint64_t)SYMSAN_RING_WAITING, __ATOMIC_SEQ_CST);
}

// Mark the run finished.  Returns the old word so the caller can see whether a
// consumer is asleep on this cursor and needs waking.  head only; see EOR.
static inline uint64_t symsan_ring_set_eor(uint64_t *cursor) {
  return __atomic_fetch_or(cursor, (uint64_t)SYMSAN_RING_EOR, __ATOMIC_SEQ_CST);
}

// The futex word is the low half of the cursor, which on a little-endian target
// is the low-order bits -- so WAITING and EOR are both inside it, and so are 30
// bits of the byte count.  Both of our targets (x86-64, aarch64) are
// little-endian; a big-endian port would have to point this at the other half
// and would find every other assumption in this file intact.
static inline uint32_t *symsan_ring_futex_word(uint64_t *cursor) {
  return (uint32_t *)(void *)cursor;
}

static inline uint32_t symsan_ring_futex_expect(uint64_t cursor) {
  return (uint32_t)cursor;
}

static inline uint64_t symsan_ring_used(uint64_t head, uint64_t tail) {
  // Monotonic counts, so this is correct across wrap.  Masking the low bits off
  // rather than subtracting the raw words matters: head can carry EOR while
  // tail cannot, and that bit would otherwise read as a byte of data.
  return symsan_ring_bytes(head) - symsan_ring_bytes(tail);
}

//===----------------------------------------------------------------------===//
// Copy in and out.  A record that straddles the wrap point is copied in two
// pieces; the branch is well predicted and costs nothing against the syscall
// it replaces.
//
// Deliberately not the "magic" double mapping (the segment mapped twice back to
// back so every copy is contiguous): on the producer side that means a
// fixed-address mapping inside dfsan's shadow layout, right next to
// MmapFixedNoAccess(UnusedAddr(), AppAddr() - UnusedAddr()), which is not a
// place to spend risk on a micro-optimization on top of a ~100x win.
//===----------------------------------------------------------------------===//

// `at` is the packed cursor, not a byte count, for the same reason the
// accessors above are: one unpack, in one place, rather than a shift every
// caller has to remember.
static inline void symsan_ring_put(struct symsan_ring_hdr *h, uint64_t at,
                                   const void *src, size_t n) {
  uint8_t *data = symsan_ring_data(h);
  uint64_t mask = h->capacity - 1;
  size_t off = (size_t)(symsan_ring_bytes(at) & mask);
  size_t first = (size_t)(h->capacity - off);
  if (first >= n) {
    __builtin_memcpy(data + off, src, n);
  } else {
    __builtin_memcpy(data + off, src, first);
    __builtin_memcpy(data, (const uint8_t *)src + first, n - first);
  }
}

static inline void symsan_ring_get(struct symsan_ring_hdr *h, uint64_t at,
                                   void *dst, size_t n) {
  const uint8_t *data = symsan_ring_data(h);
  uint64_t mask = h->capacity - 1;
  size_t off = (size_t)(symsan_ring_bytes(at) & mask);
  size_t first = (size_t)(h->capacity - off);
  if (first >= n) {
    __builtin_memcpy(dst, data + off, n);
  } else {
    __builtin_memcpy(dst, data + off, first);
    __builtin_memcpy((uint8_t *)dst + first, data, n - first);
  }
}

// Called by the consumer at the start of every run, once the previous child is
// known to be dead.  Resetting rather than letting the cursors run forever is
// what keeps a trace that the caller abandoned on a timeout from poisoning the
// next one -- and it is also what clears EOR, so "is this run over" is a
// question about this run only.
//
// Safe to write non-atomically as far as WAITING goes, because there is nobody
// to be waiting: the previous child is reaped and the next one has not been
// asked for.  On the fork-server path that ordering is not incidental, it is
// enforced -- the server sets EOR *before* it writes the status to fd 199, so
// by the time the launcher has read that status and reached here, the server is
// already blocked reading fd 198 and will not touch this header again until we
// poke it.
static inline void symsan_ring_reset(struct symsan_ring_hdr *h) {
  __atomic_store_n(&h->tail, (uint64_t)0, __ATOMIC_RELAXED);
  // head last, with release, so a producer that is somehow still looking sees
  // a consistent header rather than a fresh head over a stale tail.
  __atomic_store_n(&h->head, (uint64_t)0, __ATOMIC_RELEASE);
}

static inline void symsan_ring_init(struct symsan_ring_hdr *h, uint64_t capacity) {
  h->magic = SYMSAN_RING_MAGIC;
  h->version = SYMSAN_RING_VERSION;
  h->capacity = capacity;
  symsan_ring_reset(h);
}

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SYMSAN_RING_H
