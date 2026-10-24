#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "union_hashtable.h"
#include "union_util.h"

using namespace __taint;
using __sanitizer::Report;
using __sanitizer::Die;
using __sanitizer::atomic_store;
using __sanitizer::memory_order_relaxed;
using __sanitizer::memory_order_release;

// The slot's hash.  label_info.hash leaves out the concrete operands -- it is
// xxhash(l1's hash, l2's hash, op and size) -- so the infos that differ only
// in op1/op2 share it: the Extracts of one label at each byte offset, one
// operation with different constants.  On toucan.png that put ~14 entries in
// a chain on average with 13,717 entries in 2^20 buckets, and in a probing
// table those would all start at one slot.  The operands are mixed in here
// (splitmix64's finalizer) rather than in label_info.hash, which the parsers
// and solvers see.  So are the operand labels themselves: two labels can have
// one hash (the same expression built twice), and the infos over each then
// share theirs too -- 46k of 382k compares on toucan.png failed that way.
static inline uint32_t slot_hash(const dfsan_label_info &key) {
  uint64_t x = key.op1.i * 0x9e3779b97f4a7c15ULL ^ key.op2.i ^
               ((uint64_t)key.hash << 32) ^
               (((uint64_t)key.l1 << 32 | key.l2) * 0xc2b2ae3d27d4eb4fULL);
  x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
  x ^= x >> 27; x *= 0x94d049bb133111ebULL;
  x ^= x >> 31;
  return (uint32_t)x;
}

union_hashtable::table *union_hashtable::make_table(uint64_t n) {
  // both from the bump allocator, whose memory is fresh, hence zero: an
  // empty array.  nullptr if they do not fit.
  auto *slots = reinterpret_cast<atomic_uint64_t *>(
      allocator_try_alloc(n * sizeof(atomic_uint64_t)));
  if (!slots) return nullptr;
  auto *t = reinterpret_cast<table *>(allocator_try_alloc(sizeof(table)));
  if (!t) return nullptr;
  t->slots = slots;
  t->mask = n - 1;
  return t;
}

void union_hashtable::init(uint64_t n, const dfsan_label_info *label_infos) {
  infos = label_infos;
  count = 0;
  full = false;
  lock.Init();
  table *t = make_table(n);
  if (!t) {
    Report("FATAL: union table does not fit its allocator\n");
    Die();
  }
  atomic_store(&current, (uptr)t, memory_order_release);
  // The buckets are already zero: allocator_alloc is a bump pointer that never
  // hands the same bytes out twice, over an arena the runtime maps anonymously
  // (MmapFixedSuperNoReserve, kernel-zeroed) -- the shm-backed union table is a
  // separate mapping above it.  Zeroing anyway is not just belt and braces.
  // dfsan_init calls init() above the fork point, so these 2048 write faults are
  // paid once by the fork-server parent and every child inherits present PTEs;
  // skip them and a child faults on each bucket page it merely *reads*, measured
  // as 2149 extra faults over 200 runs.  Only the exec-per-run fallback pays per
  // run for it (3.7ms an exec, 6%), and that is not the path a campaign takes.
  // (now: the initial array, a few pages, is what is pre-faulted; the arrays
  // a run grows into are its own)
  reset();
}

void union_hashtable::reset() {
  table *t = reinterpret_cast<table *>(atomic_load(&current, memory_order_acquire));
  __sanitizer::internal_memset(t->slots, 0,
                               (t->mask + 1) * sizeof(atomic_uint64_t));
  count = 0;
}

// Reinsert t's entries into an array twice its size and publish it.  Under
// the lock.  False, leaving t current, if the new one does not fit.
bool union_hashtable::grow(table *t) {
  table *n = make_table((t->mask + 1) * 2);
  if (!n) return false;
  for (uint64_t i = 0; i <= t->mask; ++i) {
    uint64_t s = atomic_load(&t->slots[i], memory_order_relaxed);
    if (!s) continue;
    uint64_t j = (s >> 32) & n->mask;
    while (atomic_load(&n->slots[j], memory_order_relaxed))
      j = (j + 1) & n->mask;
    atomic_store(&n->slots[j], s, memory_order_relaxed);
  }
  atomic_store(&current, (uptr)n, memory_order_release);
  // Give the old array's pages back: the arrays a grow leaves behind were as
  // much again as the current one, all resident (8.9M entries: 840 MB RSS
  // against the chained table's 532 MB).  A lookup still reading it reads
  // zero pages, i.e. empty slots: a miss, which costs a duplicate label at
  // worst -- the race a lookup already has.  Only whole pages inside it.
  __sanitizer::ReleaseMemoryPagesToOS(
      (uptr)t->slots, (uptr)(t->slots + t->mask + 1));
  return true;
}

void
union_hashtable::insert(dfsan_label_info *key, dfsan_label entry) {
  __sanitizer::SpinMutexLock l(&lock);
  table *t = reinterpret_cast<table *>(atomic_load(&current, memory_order_relaxed));
  uint64_t size = t->mask + 1;
  if (!full && (count + 1) * 2 > size) {
    if (grow(t))
      t = reinterpret_cast<table *>(atomic_load(&current, memory_order_relaxed));
    else
      full = true;
  }
  // past what a grow could give, stop at 9/10 so a probe still ends: a lookup
  // then misses and the caller makes a label it would have found
  if (full && (count + 1) * 10 > (t->mask + 1) * 9)
    return;
  uint32_t h = slot_hash(*key);
  uint64_t s = ((uint64_t)h << 32) | entry;
  uint64_t i = h & t->mask;
  while (atomic_load(&t->slots[i], memory_order_relaxed))
    i = (i + 1) & t->mask;
  atomic_store(&t->slots[i], s, memory_order_release);
  ++count;
}

option
union_hashtable::lookup(const dfsan_label_info &key) {
  table *t = reinterpret_cast<table *>(atomic_load(&current, memory_order_acquire));
  uint32_t h = slot_hash(key);
  uint64_t i = h & t->mask;
  while (true) {
    uint64_t s = atomic_load(&t->slots[i], memory_order_acquire);
    if (!s) return none();
    if ((uint32_t)(s >> 32) == h) {
      dfsan_label label = (dfsan_label)s;
      if (infos[label] == key)
        return some_dfsan_label(label);
    }
    i = (i + 1) & t->mask;
  }
}
