#ifndef UNION_HASHTABLE_H
#define UNION_HASHTABLE_H

#include <stdint.h>
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "taint_allocator.h"
#include "union_util.h"
#include "dfsan.h"

using __sanitizer::atomic_uintptr_t;
using __sanitizer::atomic_uint64_t;
using __sanitizer::atomic_load;
using __sanitizer::atomic_compare_exchange_strong;
using __sanitizer::memory_order_acquire;
using __sanitizer::memory_order_seq_cst;

namespace __taint {

// Dedups the label infos (the ASTs) do_taint_union builds: a lookup before a
// label is created, an insert after.  Open addressing with linear probing.
//
// It used to chain, from a fixed 2^20 buckets (8 MB): a run with few labels
// paid a copy-on-write fault for nearly every insert -- the buckets are
// zeroed in the fork-server parent and an insert lands on a random page of
// them, ~48 faults a run in a small UCSan target -- and one with millions of
// labels walked chains of ~10 nodes, a cache miss and a key dereference each.
// Here a slot is 8 bytes, {hash, label}: the stored hash rejects a mismatch
// without touching the label's info, so a probe costs a compare in a cache
// line already loaded.  The table starts small and doubles when half full,
// so the pages a run touches follow the labels it creates, and a lookup that
// misses probes 2.5 slots on average.
//
// Inserts are serialized by a spinlock; they follow a missed lookup, i.e. a
// new label, so the lock is not contended in practice.  Lookups take no lock:
// a grow builds the new array, reinserts every entry and only then publishes
// it, and an old array is never freed (the allocator never frees), so a
// lookup still reading one reads valid memory.  A lookup racing an insert or
// a grow may miss the entry being added and the caller creates a duplicate
// label: dedup quality, not correctness, and the old table had the same race
// between its lookup and its insert.
class union_hashtable {
  struct table {
    atomic_uint64_t *slots;  // (hash << 32) | label; 0 is empty (label 0 is
                             // the constant label, never inserted)
    uint64_t mask;           // slot count - 1
  };
  atomic_uintptr_t current;  // table *
  uint64_t count;            // entries, under lock
  const dfsan_label_info *infos;
  __sanitizer::StaticSpinMutex lock;
  // a grow did not fit in the allocator's region: keep filling, to 9/10
  bool full;

  table *make_table(uint64_t n);
  bool grow(table *t);
public:
  // Deliberately no sized constructor: this class is instantiated as a static
  // object, and a static object with a nontrivial constructor gets an
  // .init_array entry.  .init_array runs *after* .preinit_array, which is where
  // dfsan_init lives and where the fork server's fork point sits -- so the
  // construction would happen separately in every forked child rather than once
  // in the parent, which is exactly what the fork server exists to avoid.  It
  // also means the table would not exist yet during the rest of dfsan_init.
  //
  // Leaving the default constructor implicit keeps the object in .bss with no
  // dynamic initializer at all.  dfsan_init calls init() above the fork point.
  //
  // n: the initial slot count, a power of two; infos: the label infos the
  // labels in the table index
  void init(uint64_t n, const dfsan_label_info *infos);
  // Zero every bucket, dropping all entries.  init() calls it; nothing else
  // does today, because every run either forks from a parent whose table is
  // empty or is a fresh exec.  It is what a persistent-mode child would need
  // between iterations, since the entries point at labels that a reset would
  // recycle.
  // (now: every slot of the current array, which keeps its size)
  void reset();
  void insert(dfsan_label_info *key, dfsan_label value);
  option lookup(const dfsan_label_info &key);
};

}

#endif
