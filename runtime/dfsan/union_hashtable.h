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
  union_hashtable(uint64_t n);
  void insert(dfsan_label_info *key, dfsan_label value);
  option lookup(const dfsan_label_info &key);
};

}

#endif
