#include "sanitizer_common/sanitizer_libc.h"
#include "union_hashtable.h"
#include "union_util.h"

using namespace __taint;

union_hashtable::union_hashtable(uint64_t n) {
  bucket_size = n;
  bucket = reinterpret_cast<atomic_uintptr_t*>(
      allocator_alloc(n * sizeof(atomic_uintptr_t)));
  __sanitizer::internal_memset(bucket, 0, n * sizeof(atomic_uintptr_t));
}

uint32_t
union_hashtable::hash(const dfsan_label_info &key) {
  return key.hash & (bucket_size - 1);
}

void
union_hashtable::insert(dfsan_label_info *key, dfsan_label entry) {
  uint32_t index = hash(*key);
  auto curr = (struct union_hashtable_entry *)
      allocator_alloc(sizeof(struct union_hashtable_entry));
  curr->key = key; curr->entry = entry;
  uptr p = atomic_load(&bucket[index], memory_order_acquire);
  while (true) {
    curr->next = reinterpret_cast<struct union_hashtable_entry *>(p);
    if (atomic_compare_exchange_strong(&bucket[index], &p, (uptr)curr,
                                       memory_order_seq_cst))
      break; // spin until succeed, when fail, p will contain the current head
  }
}

option
union_hashtable::lookup(const dfsan_label_info &key) {
  uint64_t index = hash(key);
  uptr p = atomic_load(&bucket[index], memory_order_acquire);
  auto curr = reinterpret_cast<struct union_hashtable_entry *>(p);
  while (curr) {
    if (*(curr->key) == key) {
      return some_dfsan_label(curr->entry);
    }
    curr = curr->next; // no data race here
  }
  return none();
}
