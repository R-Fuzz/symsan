//===-- ucsan_containers.h - UCSan Container Types -------------*- C++ -*-===//
//
// Container implementations for UCSan runtime.
// Separated from ucsan.h to keep type definitions focused.
//
//===----------------------------------------------------------------------===//

#ifndef UCSAN_CONTAINERS_H
#define UCSAN_CONTAINERS_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_common.h"

#include <cstddef>
#include <cstdint>

namespace __ucsan {

//===----------------------------------------------------------------------===//
// AddrRangeMap - sorted array for address range → object ID lookup
//===----------------------------------------------------------------------===//
// Supports container_of/list_entry patterns where pointers point into
// the middle of objects. Uses binary search for O(log n) range queries.

using ucsan_label = uint16_t;

struct AddrRangeEntry {
  uintptr_t start;
  size_t size;
  uint32_t object_id;
  ucsan_label ptr_label;  // ucsan label of the pointer to this object
};

struct AddrRangeMap {
  AddrRangeEntry *entries;
  uint32_t len;
  uint32_t cap;

  void init(uint32_t initial_cap = 64) {
    cap = initial_cap;
    len = 0;
    uptr alloc_size = __sanitizer::RoundUpTo(
        cap * sizeof(AddrRangeEntry), __sanitizer::GetPageSizeCached());
    entries = (AddrRangeEntry *)__sanitizer::MmapOrDie(
        alloc_size, "AddrRangeMap");
  }

  void destroy() {
    if (entries) {
      uptr alloc_size = __sanitizer::RoundUpTo(
          cap * sizeof(AddrRangeEntry), __sanitizer::GetPageSizeCached());
      __sanitizer::UnmapOrDie(entries, alloc_size);
      entries = nullptr;
    }
    len = cap = 0;
  }

  // Insert maintaining sorted order by start address.
  void insert(void *addr, size_t size, uint32_t object_id,
              ucsan_label ptr_label) {
    if (len >= cap) grow();

    uintptr_t start = (uintptr_t)addr;

    // Binary search for insertion point
    uint32_t lo = 0, hi = len;
    while (lo < hi) {
      uint32_t mid = lo + (hi - lo) / 2;
      if (entries[mid].start < start)
        lo = mid + 1;
      else
        hi = mid;
    }

    // Shift elements to make room
    for (uint32_t i = len; i > lo; --i)
      entries[i] = entries[i - 1];

    entries[lo] = {start, size, object_id, ptr_label};
    len++;
  }

  // Find which registered object contains the given address.
  // Returns true if found; sets out_object_id, out_offset (within object),
  // and out_ptr_label.
  bool find(void *addr, uint32_t *out_object_id, uint32_t *out_offset,
            ucsan_label *out_ptr_label) const {
    if (len == 0) return false;

    uintptr_t target = (uintptr_t)addr;

    // Binary search: find largest start <= target
    uint32_t lo = 0, hi = len;
    while (lo < hi) {
      uint32_t mid = lo + (hi - lo) / 2;
      if (entries[mid].start <= target)
        lo = mid + 1;
      else
        hi = mid;
    }

    // lo is now one past the last entry with start <= target
    if (lo == 0) return false;

    const AddrRangeEntry &e = entries[lo - 1];
    if (target >= e.start && target < e.start + e.size) {
      if (out_object_id) *out_object_id = e.object_id;
      if (out_offset) *out_offset = (uint32_t)(target - e.start);
      if (out_ptr_label) *out_ptr_label = e.ptr_label;
      return true;
    }

    return false;
  }

private:
  void grow() {
    uint32_t old_cap = cap;
    AddrRangeEntry *old = entries;
    cap *= 2;
    uptr alloc_size = __sanitizer::RoundUpTo(
        cap * sizeof(AddrRangeEntry), __sanitizer::GetPageSizeCached());
    entries = (AddrRangeEntry *)__sanitizer::MmapOrDie(
        alloc_size, "AddrRangeMap");
    __sanitizer::internal_memcpy(entries, old, len * sizeof(AddrRangeEntry));
    uptr old_size = __sanitizer::RoundUpTo(
        old_cap * sizeof(AddrRangeEntry), __sanitizer::GetPageSizeCached());
    __sanitizer::UnmapOrDie(old, old_size);
  }
};

}  // namespace __ucsan

#endif  // UCSAN_CONTAINERS_H
