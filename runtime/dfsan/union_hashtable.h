#ifndef UNION_HASHTABLE_H
#define UNION_HASHTABLE_H

#include <stdint.h>
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "taint_allocator.h"
#include "union_util.h"
#include "dfsan.h"

using __sanitizer::atomic_uintptr_t;
using __sanitizer::atomic_load;
using __sanitizer::atomic_compare_exchange_strong;
using __sanitizer::memory_order_acquire;
using __sanitizer::memory_order_seq_cst;

namespace __taint {

struct union_hashtable_entry {
  dfsan_label_info *key;
  dfsan_label entry;
  struct union_hashtable_entry *next;
};

class union_hashtable {
  atomic_uintptr_t *bucket;
  uint64_t bucket_size;
  uint32_t hash(const dfsan_label_info &key);
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
  void init(uint64_t n);
  // Zero every bucket, dropping all entries.  init() calls it; nothing else
  // does today, because every run either forks from a parent whose table is
  // empty or is a fresh exec.  It is what a persistent-mode child would need
  // between iterations, since the entries point at labels that a reset would
  // recycle.
  void reset();
  void insert(dfsan_label_info *key, dfsan_label value);
  option lookup(const dfsan_label_info &key);
};

}

#endif
