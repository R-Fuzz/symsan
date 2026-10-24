#include "../sanitizer_common/sanitizer_atomic.h"
#include "../sanitizer_common/sanitizer_common.h"
#include "dfsan.h"
#include "taint_allocator.h"

using namespace __sanitizer;

namespace __taint {

static uptr begin_addr;
static atomic_uint64_t next_usable_byte;
static uptr end_addr;

/**
 * Initialize allocator memory,
 * begin: first usable byte
 * end: first unusable byte
 */

void allocator_init(uptr begin, uptr end) {
  begin_addr = begin;
  atomic_store_relaxed(&next_usable_byte, begin);
  end_addr = end;
}

void *allocator_alloc(uptr size) {
  if (begin_addr == 0) {
    Report("FATAL: Allocator not initialized\n");
    Die();
  }
  uptr retval = atomic_fetch_add(&next_usable_byte, size, memory_order_relaxed);
  if (retval + size >= end_addr) {
    Report("FATAL: Allocate size exceeded\n");
    Die();
  }
  return reinterpret_cast<void *>(retval);
}

void *allocator_try_alloc(uptr size) {
  if (begin_addr == 0) {
    Report("FATAL: Allocator not initialized\n");
    Die();
  }
  u64 cur = atomic_load(&next_usable_byte, memory_order_relaxed);
  do {
    if (cur + size >= end_addr) return nullptr;
  } while (!atomic_compare_exchange_weak(&next_usable_byte, &cur, cur + size,
                                         memory_order_relaxed));
  return reinterpret_cast<void *>(cur);
}

void
allocator_dealloc(uptr addr) {
  // do nothing for now
}

} // namespace
