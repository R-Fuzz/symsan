// UCSan custom function wrappers for standalone mode
// Provides minimal malloc/free wrappers with bounds tracking

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_common.h"
#include "ucsan_platform.h"
#include "ucsan.h"

#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace __sanitizer;
using namespace __ucsan;

// External symbols for real libc functions
extern "C" {
  void *__libc_malloc(size_t size);
  void *__libc_calloc(size_t nmemb, size_t size);
  void __libc_free(void *ptr);
  // [[deprecated]] void *memalign(size_t alignment, size_t size);
  // [[deprecated]] void *valloc(size_t size);
  // [[deprecated]] void *pvalloc(size_t size);
  void *aligned_alloc(size_t alignment, size_t size);
  int posix_memalign(void **memptr, size_t alignment, size_t size);

  // SymSan bridge functions (weak stubs in ucsan.cpp, strong in dfsan.cpp)
  dfsan_label __taint_create_label(uint32_t object_id, uint64_t offset,
                                   uint32_t size_in_bytes);
  void __taint_copy_shadow(void *dst, void *src, u64 size);
  void __taint_move_shadow(void *dst, void *src, u64 size);
  void __taint_set_label(u32 label, void *addr, u64 size);
  dfsan_label __taint_get_ptr_bounds_label(void *ptr, u64 lower, u64 upper);
  void __taint_set_retval_tls(u32 index, dfsan_label label, u32 size_in_bits);
  dfsan_label __taint_extend_label(dfsan_label label, bool sign_extend,
                                   uint16_t new_size_in_bits);

  // event
  void __taint_trace_event_addr(__ucsan::ucsan_label label, uint32_t event_id,
                                uint64_t info, void* addr, uint32_t info2);
}

// Simple passthrough wrappers for malloc family
// In standalone UCSan mode, we don't track taint, just provide the symbols

extern "C" {

// Helper to create an alloca-style bounds label for heap allocations
// Also sets shadow memory to kUninitializedLabel for UBI detection
static ucsan_label create_alloca_label(void *ptr, size_t size, bool set_uninitialized) {
  if (ptr == nullptr) {
    // clear retval TLS for null pointer (no label, no bounds)
    __taint_set_retval_tls(0, 0, sizeof(void*) * 8);
    return UCSAN_CONST_LABEL;
  }

  ucsan_label label = allocate_label();
  check_label(label);

  ucsan_label_info *info = get_label_info(label);
  ucsan_obj_info *obj = to_obj_info(info);

  obj->op = OP_ALLOCA;
  obj->type_id = 0;
  obj->object_id = 0;  // Not tracked in objects array
  obj->real_ptr = ptr;
  obj->lower_bound = 0;           // No bytes before base
  obj->upper_bound = (u32)size;   // Size in bytes

  // Set shadow memory to kUninitializedLabel for UBI detection
  if (set_uninitialized) {
    ucsan_label *shadow = ucsan_shadow_for(ptr);
    for (size_t i = 0; i < size; i++) {
      shadow[i] = kUninitializedLabel;
    }
  }

  // Bridge to SymSan: create Alloca bounds label and set via retval TLS
  dfsan_label bounds = __taint_get_ptr_bounds_label(nullptr, (u64)ptr, (u64)ptr + size);
  __taint_set_retval_tls(0, bounds, sizeof(void*) * 8);

  return label;
}

__attribute__((visibility("default")))
void *__dfsw_malloc(size_t size, ucsan_label size_label, ucsan_label *ret_label) {
  void *ret = nullptr;
  if (size != 0 && size < UINT32_MAX) {
    ret = __libc_malloc(size);
  }
  UCSAN_OUT("__dfsw_malloc(%zu) = %p\n", size, ret);
  // Create bounds label (sets shadow to kUninitializedLabel for UBI)
  *ret_label = create_alloca_label(ret, size, true);
  return ret;
}

__attribute__((visibility("default")))
void *__dfsw_kmalloc_large(size_t size, unsigned int flags,
                           ucsan_label size_label, ucsan_label flags_label,
                           ucsan_label *ret_label) {
  return __dfsw_malloc(size, size_label, ret_label);
}

__attribute__((visibility("default")))
void *__dfsw___kmalloc(size_t size, unsigned int flags,
                       ucsan_label size_label, ucsan_label flags_label,
                       ucsan_label *ret_label) {
  return __dfsw_malloc(size, size_label, ret_label);
}

__attribute__((visibility("default")))
void *__dfsw_kmalloc(size_t size, unsigned int flags, ucsan_label size_label,
                     ucsan_label flags_label, ucsan_label *ret_label) {
  return __dfsw_malloc(size, size_label, ret_label);
}

__attribute__((visibility("default")))
void *__dfsw_calloc(size_t nmemb, size_t size, ucsan_label nmemb_label,
                    ucsan_label size_label, ucsan_label *ret_label) {
  void *ret = nullptr;
  size_t total_size = nmemb * size;
  if (total_size != 0 && total_size < UINT32_MAX) {
    ret = __libc_calloc(nmemb, size);
  }
  // Create bounds label (sets shadow to kUninitializedLabel for UBI)
  // (calloc zeros memory, but we still want to detect reads before writes)
  *ret_label = create_alloca_label(ret, total_size, false);
  return ret;
}

__attribute__((visibility("default")))
void *__dfsw_realloc(void *ptr, size_t size, ucsan_label ptr_label,
                     ucsan_label size_label, ucsan_label *ret_label) {
  // If ptr has an alloca label, mark it as freed
  size_t old_size = 0;
  if (ptr) {
    if (ptr_label > UCSAN_CONST_LABEL) {
      ucsan_label_info *old_info = get_label_info(ptr_label);
      if (old_info->common.op == OP_ALLOCA) {
        ucsan_obj_info *old_obj = to_obj_info(old_info);
        if (old_obj->op == OP_ALLOCA) {
          old_obj->op = OP_FREE;  // Mark old buffer as freed
        }
        old_size = old_obj->upper_bound - old_obj->lower_bound;
        if (ptr != old_obj->real_ptr) {
          UCSAN_OUT("WARNING: realloc ptr %p does not match real_ptr %p\n", ptr, old_obj->real_ptr);
        }
      } else if (old_info->common.op == OP_EXTERNAL) {
        ucsan_ptr_info *ptr_info = to_ptr_info(old_info);
        // If ptr is an external pointer, size is in obj
        if (ptr_info->status == PTR_INITIALIZED) {
          ucsan_obj_info *obj_info = to_obj_info(get_label_info(ptr_info->obj_label));
          old_size = obj_info->lower_bound + obj_info->upper_bound;
        } else {
          UCSAN_OUT("WARNING: realloc external ptr label %d is not initialized\n", ptr_label);
        }
      } else if (old_info->common.op == OP_FREE) {
        UCSAN_OUT("WARNING: realloc ptr_label %d is already freed\n", ptr_label);
      } else {
        UCSAN_OUT("WARNING: realloc ptr_label %d is not alloca, op %d\n", ptr_label, old_info->common.op);
      }
    } else {
      old_size = malloc_usable_size(ptr);
    }
  }

  // don't actually free the buffer
  void *ret = nullptr;
  if (size != 0 && size < UINT32_MAX) {
    ret = __libc_malloc(size);
  }
  // Create bounds label (sets shadow to kUninitializedLabel for UBI)
  *ret_label = create_alloca_label(ret, size, true);

  UCSAN_OUT("__dfsw_realloc(%p, %zu) = %p, old_size: %zu", ptr, size, ret, old_size);
  if (ret) {
    // Copy data from old buffer to new buffer (up to min of old/new size)
    size_t copy_size = old_size < size ? old_size : size;
    internal_memcpy(ret, ptr, copy_size);
    // Copy UCSan shadow memory from old to new
    ucsan_label *sdest = ucsan_shadow_for(ret);
    const ucsan_label *ssrc = ucsan_shadow_for(ptr);
    internal_memcpy((void *)sdest, (const void *)ssrc, copy_size * sizeof(ucsan_label));
    // Bridge to SymSan: copy SymSan shadow memory
    __taint_copy_shadow(ret, (void *)ptr, copy_size);
  }
  return ret;
}

__attribute__((visibility("default")))
void *__dfsw_reallocarray(void *ptr, size_t nmemb, size_t size,
                          ucsan_label ptr_label, ucsan_label nmemb_label,
                          ucsan_label size_label, ucsan_label *ret_label) {
  size_t total_size = nmemb * size;

  return __dfsw_realloc(ptr, total_size, ptr_label, size_label, ret_label);
}

__attribute__((visibility("default")))
void __dfsw_free(void *ptr, ucsan_label ptr_label) {
  // Mark buffer as freed for UAF detection
  if (ptr && ptr_label > UCSAN_CONST_LABEL) {
    ucsan_label_info *info = get_label_info(ptr_label);
    if (info->common.op == OP_ALLOCA) {
      info->common.op = OP_FREE;
    }
  }
  // don't actually free the buffer, to capture UAFs
  // __libc_free(ptr);
}

__attribute__((visibility("default")))
void *__dfsw_memalign(size_t alignment, size_t size,
                      ucsan_label alignment_label, ucsan_label size_label,
                      ucsan_label *ret_label) {
  void *ret = nullptr;
  if (size > 0 && size < UINT32_MAX) {
    ret = aligned_alloc(alignment, size);
  }
  // Create bounds label (sets shadow to kUninitializedLabel for UBI)
  *ret_label = create_alloca_label(ret, size, true);
  return ret;
}

__attribute__((visibility("default")))
void *__dfsw_aligned_alloc(size_t alignment, size_t size,
                           ucsan_label alignment_label, ucsan_label size_label,
                           ucsan_label *ret_label) {
  void *ret = nullptr;
  if (size > 0 && size < UINT32_MAX) {
    ret = aligned_alloc(alignment, size);
  }
  // Create bounds label (sets shadow to kUninitializedLabel for UBI)
  *ret_label = create_alloca_label(ret, size, true);
  return ret;
}

#define PAGE_SIZE 4096

__attribute__((visibility("default")))
void *__dfsw_valloc(size_t size, ucsan_label size_label, ucsan_label *ret_label) {
  void *ret = nullptr;
  if (size > 0 && size < UINT32_MAX) {
    ret = aligned_alloc(PAGE_SIZE, size);
  }
  // Create bounds label (sets shadow to kUninitializedLabel for UBI)
  *ret_label = create_alloca_label(ret, size, true);
  return ret;
}

__attribute__((visibility("default")))
void *__dfsw_pvalloc(size_t size, ucsan_label size_label, ucsan_label *ret_label) {
  void *ret = nullptr;
  if (size > 0 && size < UINT32_MAX) {
    ret = aligned_alloc(PAGE_SIZE, size);
  }
  // Create bounds label (sets shadow to kUninitializedLabel for UBI)
  *ret_label = create_alloca_label(ret, size, true);
  return ret;
}

__attribute__((visibility("default")))
int __dfsw_posix_memalign(void **memptr, size_t alignment, size_t size,
                          ucsan_label memptr_label, ucsan_label alignment_label,
                          ucsan_label size_label, ucsan_label *ret_label) {
  int result = posix_memalign(memptr, alignment, size);
  if (result == 0) {
    *ret_label = UCSAN_CONST_LABEL;  // Return value is int, no pointer label
    // Create bounds label (sets shadow to kUninitializedLabel for UBI)
    ucsan_label alloca_label = create_alloca_label(*memptr, size, true);
    ucsan_label *shadow = ucsan_shadow_for(memptr);
    *shadow = alloca_label;  // Label for the pointer itself
  } else {
    *ret_label = UCSAN_CONST_LABEL;
  }
  return result;
}

// Wrappers for __libc versions - delegate to main wrappers for bounds tracking

__attribute__((visibility("default")))
void *__dfsw___libc_malloc(size_t size, ucsan_label size_label, ucsan_label *ret_label) {
  return __dfsw_malloc(size, size_label, ret_label);
}

__attribute__((visibility("default")))
void *__dfsw___libc_calloc(size_t nmemb, size_t size, ucsan_label nmemb_label,
                           ucsan_label size_label, ucsan_label *ret_label) {
  return __dfsw_calloc(nmemb, size, nmemb_label, size_label, ret_label);
}

__attribute__((visibility("default")))
void *__dfsw___libc_realloc(void *ptr, size_t size, ucsan_label ptr_label,
                            ucsan_label size_label, ucsan_label *ret_label) {
  return __dfsw_realloc(ptr, size, ptr_label, size_label, ret_label);
}

__attribute__((visibility("default")))
void *__dfsw___libc_reallocarray(void *ptr, size_t nmemb, size_t size,
                                 ucsan_label ptr_label, ucsan_label nmemb_label,
                                 ucsan_label size_label, ucsan_label *ret_label) {
  return __dfsw_reallocarray(ptr, nmemb, size, ptr_label, nmemb_label, size_label, ret_label);
}

__attribute__((visibility("default")))
void __dfsw___libc_free(void *ptr, ucsan_label ptr_label) {
  __dfsw_free(ptr, ptr_label);
}

__attribute__((visibility("default")))
void *__dfsw___libc_memalign(size_t alignment, size_t size,
                             ucsan_label alignment_label, ucsan_label size_label,
                             ucsan_label *ret_label) {
  return __dfsw_memalign(alignment, size, alignment_label, size_label, ret_label);
}

__attribute__((visibility("default")))
void *__dfsw___libc_valloc(size_t size, ucsan_label size_label, ucsan_label *ret_label) {
  return __dfsw_valloc(size, size_label, ret_label);
}

__attribute__((visibility("default")))
void *__dfsw___libc_pvalloc(size_t size, ucsan_label size_label, ucsan_label *ret_label) {
  return __dfsw_pvalloc(size, size_label, ret_label);
}

__attribute__((visibility("default")))
void *__dfsw_memcpy(void *dest, const void *src, size_t n,
                    ucsan_label dest_label, ucsan_label src_label,
                    ucsan_label n_label, ucsan_label *ret_label) {
  *ret_label = dest_label;
  // Copy UCSan shadow memory from src to dest
  ucsan_label *sdest = ucsan_shadow_for(dest);
  const ucsan_label *ssrc = ucsan_shadow_for(src);
  internal_memcpy((void *)sdest, (const void *)ssrc, n * sizeof(ucsan_label));
  // Bridge to SymSan: copy SymSan shadow memory
  __taint_copy_shadow(dest, (void *)src, n);
  // Copy actual data
  return internal_memcpy(dest, src, n);
}

__attribute__((visibility("default")))
void *__dfsw_memmove(void *dest, const void *src, size_t n,
                     ucsan_label dest_label, ucsan_label src_label,
                     ucsan_label n_label, ucsan_label *ret_label) {
  *ret_label = dest_label;
  ucsan_label *sdest = ucsan_shadow_for(dest);
  const ucsan_label *ssrc = ucsan_shadow_for(src);
  internal_memmove((void *)sdest, (const void *)ssrc, n * sizeof(ucsan_label));
  // Bridge to SymSan: move SymSan shadow memory (handles overlapping regions)
  __taint_move_shadow(dest, (void *)src, n);
  void *ret = internal_memmove(dest, src, n);
  return ret;
}

__attribute__((visibility("default")))
void *__dfsw_memset(void *s, int c, size_t n,
                    ucsan_label s_label, ucsan_label c_label,
                    ucsan_label n_label, ucsan_label *ret_label) {
  *ret_label = s_label;
  // Set actual memory
  internal_memset(s, c, n);
  // Set UCSan shadow memory - propagate c_label to all bytes
  ucsan_label *shadow = ucsan_shadow_for(s);
  for (size_t i = 0; i < n; i++) {
    shadow[i] = c_label;
  }
  // Bridge to SymSan: set SymSan shadow memory
  __taint_set_label(c_label, s, n);
  return s;
}

// Kernel-specific stubs for __get_user and __put_user inline asm helpers
SANITIZER_INTERFACE_WEAK_DEF(int, __get_user_1, void) { return 0; }
SANITIZER_INTERFACE_WEAK_DEF(int, __get_user_2, void) { return 0; }
SANITIZER_INTERFACE_WEAK_DEF(int, __get_user_4, void) { return 0; }
SANITIZER_INTERFACE_WEAK_DEF(int, __get_user_8, void) { return 0; }
SANITIZER_INTERFACE_WEAK_DEF(void, __put_user_1, void) { }
SANITIZER_INTERFACE_WEAK_DEF(void, __put_user_2, void) { }
SANITIZER_INTERFACE_WEAK_DEF(void, __put_user_4, void) { }
SANITIZER_INTERFACE_WEAK_DEF(void, __put_user_8, void) { }

// _copy_from_user: copy n bytes from user-space pointer to kernel buffer
// Propagates shadow/labels from source to destination
__attribute__((visibility("default")))
unsigned long __dfsw__copy_from_user(void *to, const void *from, unsigned long n,
                                     ucsan_label to_label, ucsan_label from_label,
                                     ucsan_label n_label, ucsan_label *ret_label) {
  UCSAN_OUT("copy_from_user(%u(%p), %u(%p), %lu)\n", to_label, to, from_label, from, n);
  if (from_label) {
    // assume from ptr has been checked/initialized before calling
    ucsan_ptr_info *ptr_info = to_ptr_info(get_label_info(from_label));
    if (ptr_info->op != OP_EXTERNAL) {
      UCSAN_OUT("WARNING: copy_from_user: from_label %d is not external, op %d\n", from_label, ptr_info->op);
    }
    ucsan_label *sdest = ucsan_shadow_for(to);
    const ucsan_label *ssrc = ucsan_shadow_for(from);
    internal_memcpy((void *)sdest, (const void *)ssrc, n * sizeof(ucsan_label));
    // Bridge to SymSan
    __taint_copy_shadow(to, (void *)from, n);
  }
  // Copy actual data
  internal_memcpy(to, from, n);
  *ret_label = 0;
  return 0;
}

/// assertion and assumption interfaces

SANITIZER_INTERFACE_ATTRIBUTE void
__dfsw_assert_allocated(void *ptr, size_t size, uint64_t id, ucsan_label ptr_label,
                        ucsan_label size_label, ucsan_label id_label) {
  if (ptr_label == 0) {
    if (ptr == nullptr) {
      UCSAN_OUT("ERROR: assertion %lu failure null pointer\n", id);
      __taint_trace_event_addr(0, EVENT_ASSERTION, id, ptr, ASSERTION_ALLOCATED_FAILED);
    } else {
      UCSAN_OUT("WARNING: assertion %lu non-symbolic label: ptr %p, label %d\n", id, ptr, ptr_label);
      __taint_trace_event_addr(0, EVENT_ASSERTION, id, ptr, ASSERTION_ALLOCATED_SUCCESS);
    }
    return;
  }
  ucsan_label_info *info = get_label_info(ptr_label);
  ucsan_obj_info *obj = to_obj_info(info);
  if (obj->op != OP_ALLOCA) {
    UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, label %d, op %d\n", id, ptr, ptr_label, obj->op);
    __taint_trace_event_addr(ptr_label, EVENT_ASSERTION, id, ptr, ASSERTION_ALLOCATED_FAILED);
    return;
  }
  if (ptr != obj->real_ptr) {
    UCSAN_OUT("ERROR: assertion %lu failure: ptr %p does not match real_ptr %p\n", id, ptr, obj->real_ptr);
    __taint_trace_event_addr(ptr_label, EVENT_ASSERTION, id, ptr, ASSERTION_ALLOCATED_FAILED);
    return;
  }
  if (size > obj->upper_bound) {
    UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, label %d, size %lu exceeds upper bound %u\n",
              id, ptr, ptr_label, size, obj->upper_bound);
    __taint_trace_event_addr(ptr_label, EVENT_ASSERTION, id, ptr, ASSERTION_ALLOCATED_FAILED);
  }
  __taint_trace_event_addr(ptr_label, EVENT_ASSERTION, id, ptr, ASSERTION_ALLOCATED_SUCCESS);
}

SANITIZER_INTERFACE_ATTRIBUTE void
__dfsw_assert_freed(void *ptr, uint64_t id, ucsan_label ptr_label, ucsan_label id_label) {
  if (ptr_label == 0) {
    if (ptr != nullptr) {
      UCSAN_OUT("ERROR: assertion %lu failure non-symbolic label: ptr %p, label %d\n", id, ptr, ptr_label);
      __taint_trace_event_addr(0, EVENT_ASSERTION, id, ptr, ASSERTION_NONE_SYMBOLIC);
    } else {
      __taint_trace_event_addr(0, EVENT_ASSERTION, id, ptr, ASSERTION_FREED_SUCCESS);
    }
    return;
  }
  ucsan_label_info *info = get_label_info(ptr_label);
  ucsan_obj_info *obj = to_obj_info(info);
  if (obj->op != OP_FREE) {
    UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, label %d, op %d\n", id, ptr, ptr_label, obj->op);
    __taint_trace_event_addr(ptr_label, EVENT_ASSERTION, id, ptr, ASSERTION_FREED_FAILED);
    return;
  }
  __taint_trace_event_addr(ptr_label, EVENT_ASSERTION, id, ptr, ASSERTION_FREED_SUCCESS);
}

SANITIZER_INTERFACE_ATTRIBUTE void
__dfsw_assert_init(void *ptr, size_t size, uint64_t id, ucsan_label ptr_label,
                   ucsan_label size_label, ucsan_label id_label) {
  // check ptr is allocated and the size is in bound
  if (ptr_label == 0) {
    if (ptr == nullptr) {
      UCSAN_OUT("ERROR: assertion %lu failure null pointer\n", id);
      __taint_trace_event_addr(0, EVENT_ASSERTION, id, ptr, ASSERTION_INIT_FAILED);
      return;
    } else {
      UCSAN_OUT("WARNING: assertion %lu non-symbolic label: ptr %p, label %d\n", id, ptr, ptr_label);
    }
  } else {
    ucsan_label_info *info = get_label_info(ptr_label);
    ucsan_obj_info *obj = to_obj_info(info);
    if (obj->op != OP_ALLOCA) {
      UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, label %d, op %d\n", id, ptr, ptr_label, obj->op);
      __taint_trace_event_addr(ptr_label, EVENT_ASSERTION, id, ptr, ASSERTION_INIT_FAILED);
      return;
    }
    if (size > obj->upper_bound) {
      UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, label %d, size %lu exceeds upper bound %u\n",
                id, ptr, ptr_label, size, obj->upper_bound);
      __taint_trace_event_addr(ptr_label, EVENT_ASSERTION, id, ptr, ASSERTION_INIT_FAILED);
      return;
    }
  }
  // fall through to scan shadow
  bool success = true;
  ucsan_label *shadow = ucsan_shadow_for(ptr);
  for (size_t i = 0; i < size; i++) {
    if (shadow[i] == kUninitializedLabel) {
      UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, index %lu, label %d\n", id, ptr, i, shadow[i]);
      __taint_trace_event_addr(ptr_label, EVENT_ASSERTION, id, (char *)ptr + i, ASSERTION_INIT_FAILED);
      success = false;
    }
  }
  if (success) {
    __taint_trace_event_addr(ptr_label, EVENT_ASSERTION, id, ptr, ASSERTION_INIT_SUCCESS);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void
__dfsw_assume_init(void *ptr, size_t size, uint64_t id, ucsan_label ptr_label,
                   ucsan_label size_label, uint64_t id_label) {
  if (ptr_label == 0) {
    UCSAN_OUT("WARNING: assumption %lu non-symbolic label: ptr %p\n", id, ptr);
    return;
  }
  ucsan_label_info *info = get_label_info(ptr_label);
  ucsan_obj_info *obj = to_obj_info(info);
  if (obj->op != OP_ALLOCA) {
    UCSAN_OUT("WARNING: assumption %lu failure: ptr %p, label %d, op %d\n", id, ptr, ptr_label, obj->op);
    return;
  }
  if (size > obj->upper_bound) {
    UCSAN_OUT("WARNING: assumption %lu failure: ptr %p, label %d, size %lu exceeds upper bound %u\n",
              id, ptr, ptr_label, size, obj->upper_bound);
    return;
  }
  if (size > ucsan_object_size_limit()) {
    UCSAN_OUT("WARNING: alloca resign size %lu exceeds limit %lu, capping\n",
              size, ucsan_object_size_limit());
    size = ucsan_object_size_limit();
  }
  ucsan_label *shadow = ucsan_shadow_for(ptr);
  char *obj_ptr = (char *)ptr;
  for (size_t i = 0; i < size; i++) {
    // do the same as ucsan_resign_shadow
    if (shadow[i] == kUninitializedLabel) {
      // Allocate a byte from super object
      auto ret = create_label_from_super_object(1, false);
      UCSAN_OUT("resign alloca ret: %u %lu\n", ret.label, ret.offset);
      shadow[i] = ret.label;

      // Bridge to SymSan: create symbolic label for this byte
      dfsan_label symsan_label = __taint_create_label(0, ret.offset, 1);
      __taint_set_label(symsan_label, obj_ptr + i, 1);

      if (ucsan_tainted.objects->size() && ret.offset < ucsan_tainted.objects->at(0).data.size()) {
        UCSAN_OUT("resign alloca super object: %u\n", ucsan_tainted.objects->at(0).data.at(ret.offset));
        obj_ptr[i] = ucsan_tainted.objects->at(0).data.at(ret.offset);
      } else {
        obj_ptr[i] = 0;
      }
    }
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void*
__dfsw_assume_allocated(void *ptr, size_t size, uint64_t id, ucsan_label ptr_label,
                        ucsan_label size_label, ucsan_label id_label,
                        ucsan_label *ret_label) {
  if (ptr_label == 0) {
    // allocate a new buffer
    char *new_ptr = (char *)__dfsw_malloc(size, size_label, ret_label);
    // symbolize the new buffer
    if (new_ptr) {
      ucsan_label *shadow = ucsan_shadow_for(new_ptr);
      for (size_t i = 0; i < size; i++) {
        auto ret = create_label_from_super_object(1, false);
        shadow[i] = ret.label;
        dfsan_label symsan_label = __taint_create_label(0, ret.offset, 1);
        __taint_set_label(symsan_label, (char *)new_ptr + i, 1);

        // Initialize from seed data if available
        if (ucsan_tainted.objects->size() && ret.offset < ucsan_tainted.objects->at(0).data.size()) {
          new_ptr[i] = ucsan_tainted.objects->at(0).data.at(ret.offset);
        } else {
          new_ptr[i] = 0;
        }
      }
    }
    return new_ptr;
  }
  // ptr has a label, just make sure size is right
  ucsan_label_info *info = get_label_info(ptr_label);
  if (info->common.op == OP_ALLOCA || info->common.op == OP_FREE) {
    ucsan_obj_info *obj = to_obj_info(info);
    if (size > obj->upper_bound) {
      void *new_ptr = __dfsw_realloc(ptr, size, ptr_label, size_label, ret_label);
      return new_ptr;
    }
    *ret_label = ptr_label;
  } else {
    // external ptr
    ucsan_label_info *info = get_label_info(ptr_label);
    ucsan_ptr_info *ptr_info = to_ptr_info(info);
    // for external ptr, we need to convert it back to pseudo ptr
    ptr = ptr_info->pseudo_base;
    if (size_label == 0) {
      // size is concrete, we set a concrete bound by malloc
      void *new_ptr = __dfsw_malloc(size, size_label, ret_label);
      if (new_ptr) {
        void *old_ptr = ucsan_check_pointer(ptr, ptr_label, size, true, 0);
        ucsan_label dummy;
        __dfsw_memcpy(new_ptr, old_ptr, size, *ret_label, ptr_label, size_label, &dummy);
        return new_ptr;
      }
    } else {
      // symbolic size, keep it unbounded?
      *ret_label = ptr_label;
    }
  }

  return ptr;
}

SANITIZER_INTERFACE_ATTRIBUTE void
__dfsw_panic(char *reason, ucsan_label reason_label) {
  UCSAN_OUT("PANIC: %s\n", reason);
  _exit(EVENT_PANIC);
}

SANITIZER_INTERFACE_ATTRIBUTE __attribute__((noreturn)) void
__dfsw_abort(void) {
  UCSAN_OUT("ABORT\n");
  _exit(EVENT_PANIC);
}

SANITIZER_INTERFACE_ATTRIBUTE __attribute__((noreturn)) void
__dfsw___assert_fail(const char *assertion, const char *file,
                     unsigned int line, const char *function,
                     ucsan_label assertion_label, ucsan_label file_label,
                     ucsan_label line_label, ucsan_label function_label) {
  UCSAN_OUT("ASSERT FAILED: %s at %s:%u (%s)\n", assertion, file, line, function);
  _exit(EVENT_PANIC);
}

SANITIZER_INTERFACE_ATTRIBUTE void*
__dfsw_assume_freed(void *ptr, uint64_t id, ucsan_label ptr_label,
                    ucsan_label id_label, ucsan_label *ret_label) {
  if (ptr_label == 0) {
    ptr_label = allocate_label();
    check_label(ptr_label);
  }
  ucsan_label_info *info = get_label_info(ptr_label);
  internal_memset(info, 0, sizeof(*info));
  info->common.op = OP_FREE;
  *ret_label = ptr_label;
  return ptr;
}

//===----------------------------------------------------------------------===//
// File Simulator
//
// open()/fopen() are not forwarded to libc — we return a unique opaque
// handle and label it via create_label_from_super_object so the handle's
// label points to (super_obj=0, super_offset). The first read on that
// handle materializes a UC object via lookup_object(handle_label), which
// registers the (parent=0, offset=super_offset) -> file_obj_id mapping in
// obj_map. Re-runs see the same super_offset and resolve to the same
// file_obj_id — so the solver can feed back file content by populating
// obj.data for that id in the seed.
//
// Reads grow the file UCSanObject's data on demand (similar to how
// check_pointer extends an under-constrained object), and tag each
// byte's shadow with an OP_NONE label pointing to (file_obj_id, offset+i).
//===----------------------------------------------------------------------===//

// UCSan tests one file at a time (SymSan likewise only symbolizes a single
// input file), so we keep one global state for "the file" instead of a
// per-handle table. open/fopen return distinct fake handles purely so
// callers' null-checks behave; all reads route to this single state.
struct ucsan_file_state {
  ucsan_label label;      // label rooting the file object in the super obj
  uint32_t object_id;     // cached file UC object id (0 = not yet resolved)
  off_t offset;           // current sequential read position
  off_t size;             // concrete backing-file size, or -1 if unknown
  int fd;                 // current fake fd
  FILE *stream;           // current fake FILE*
};
static ucsan_file_state __ucsan_file = {0, 0, 0, -1, -1, nullptr};

// Counter for synthetic fd/FILE* values returned by our open/fopen wrappers.
// Start above the usual stdio fds and at a recognizable bit pattern for
// FILE* so accidental dereferences fault loudly instead of returning data.
static int __ucsan_fake_fd_counter = 1000;
static uintptr_t __ucsan_fake_file_counter = 0xFAFE0000;

static off_t concrete_file_size(const char *path) {
  if (!path) return -1;
  struct stat st;
  if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
    return st.st_size;
  return -1;
}

static void materialize_file_object(ucsan_file_state *state) {
  if (!state || state->object_id != 0) return;

  uint32_t obj_id = 0;
  lookup_object(state->label, 0, __builtin_return_address(0), &obj_id, 0, 0);
  state->object_id = obj_id;
  UCSAN_OUT("file simulator: resolved file_obj_id=%u (label=%u)\n",
            obj_id, state->label);
}

// Each open/fopen creates an anchor pointer in the super object. The file
// content object is then discovered through lookup_object({obj0, anchor_off})
// so replay can rebuild obj_map from the seed metadata.
static ucsan_file_state *open_file_state(off_t size = -1) {
  auto lbl = create_label_from_super_object(sizeof(void*), true);
  __ucsan_file.label = lbl.label;
  __ucsan_file.object_id = 0;
  __ucsan_file.offset = 0;
  __ucsan_file.size = size;
  UCSAN_OUT("file simulator: opened anchor label=%u offset=%lu\n",
            __ucsan_file.label, lbl.offset);
  materialize_file_object(&__ucsan_file);
  return &__ucsan_file;
}

// Fallback for read/getchar-style use without a prior open wrapper.
static ucsan_file_state *get_file_state() {
  if (__ucsan_file.label == 0) {
    return open_file_state();
  }
  return &__ucsan_file;
}

static off_t simulated_file_size(ucsan_file_state *s) {
  if (!s) return 0;
  if (s->size >= 0) return s->size;
  materialize_file_object(s);
  if (s->object_id != 0 && s->object_id < ucsan_tainted.objects->size())
    return (off_t)ucsan_tainted.objects->at(s->object_id).data.size();
  return s->offset;
}

// Symbolize n bytes into ptr from the file UC object at position pos.
// Grows obj.data to cover [pos, pos+n) on first touch of those bytes;
// existing bytes (e.g. populated from seed) are preserved.
static size_t simulate_file_read(ucsan_file_state *state, void *ptr, size_t n, off_t pos) {
  if (!state || !ptr || n == 0) return 0;

  materialize_file_object(state);
  if (state->object_id == 0) return 0;

  // Clamp at the per-object size limit. Anything past the cap returns
  // short (caller treats as EOF) rather than silently wrapping.
  off_t end = pos + (off_t)n;
  if (end > (off_t)ucsan_object_size_limit()) {
    UCSAN_OUT("WARNING: file read end %ld exceeds object limit %lu, capping\n",
              (long)end, ucsan_object_size_limit());
    end = ucsan_object_size_limit();
    if (pos >= end) return 0;
    n = (size_t)(end - pos);
  }

  // Grow the file object's data to cover the read window. Seeded bytes
  // (from solver feedback in re-runs) are preserved by ByteBuffer::resize.
  UCSanObject &obj = ucsan_tainted.objects->at(state->object_id);
  if (obj.data.size() < (uint32_t)end) {
    obj.data.resize((uint32_t)end);
  }

  ucsan_label *shadow = ucsan_shadow_for(ptr);
  for (size_t i = 0; i < n; i++) {
    off_t byte_off = pos + (off_t)i;

    ucsan_label byte_label = allocate_label();
    check_label(byte_label);

    ucsan_label_info *info = get_label_info(byte_label);
    ucsan_byte_info *byte = to_byte_info(info);
    byte->op = OP_NONE;
    byte->object_id = state->object_id;
    byte->offset = byte_off;

    shadow[i] = byte_label;

    // Bridge to SymSan: a symbolic 1-byte label rooted at the file object.
    void *byte_addr = (void *)((uintptr_t)ptr + i);
    dfsan_label symsan_label = __taint_create_label(state->object_id, (uint64_t)byte_off, 1);
    __taint_set_label(symsan_label, byte_addr, 1);

    // Copy concrete byte from obj.data (zero on first run, seed value on re-runs).
    ((uint8_t *)ptr)[i] = obj.data.at((uint32_t)byte_off);
  }

  return n;
}

// ===== open/fopen wrappers =====
// These do NOT forward to libc — we return a unique opaque handle so
// reads can be fully simulated. Other libc operations on the returned
// handle (fstat, ferror, ...) are not supported.

// SymSan retval TLS is sticky: handleUCSanCall always emits a load from
// __dfsan_retval_tls after each __dfsw_* call, so any wrapper that doesn't
// store a meaningful label there will read whatever the previous call left
// behind (notably, fgetc's byte label). Clear retval slot 0 explicitly in
// wrappers whose return value carries no symbolic content.
__attribute__((visibility("default")))
int __dfsw_open(const char *path, int oflags, ucsan_label path_label,
                ucsan_label oflags_label, ucsan_label *va_labels,
                ucsan_label *ret_label, ...) {
  int fake_fd = __ucsan_fake_fd_counter++;
  UCSAN_OUT("__dfsw_open(path=%s, oflags=%d) = fake fd %d\n",
            path ? path : "(null)", oflags, fake_fd);
  // The returned fd is just an opaque concrete handle; symbolic content comes
  // from the file object anchored in obj0 at this open call.
  ucsan_file_state *s = open_file_state(concrete_file_size(path));
  s->fd = fake_fd;
  s->stream = nullptr;
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(int) * 8);
  return fake_fd;
}

__attribute__((visibility("default")))
int __dfsw_openat(int dirfd, const char *path, int oflags,
                  ucsan_label dirfd_label, ucsan_label path_label,
                  ucsan_label oflags_label, ucsan_label *va_labels,
                  ucsan_label *ret_label, ...) {
  int fake_fd = __ucsan_fake_fd_counter++;
  UCSAN_OUT("__dfsw_openat(dirfd=%d, path=%s, oflags=%d) = fake fd %d\n",
            dirfd, path ? path : "(null)", oflags, fake_fd);
  ucsan_file_state *s = open_file_state(concrete_file_size(path));
  s->fd = fake_fd;
  s->stream = nullptr;
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(int) * 8);
  return fake_fd;
}

__attribute__((visibility("default")))
FILE *__dfsw_fopen(const char *filename, const char *mode,
                   ucsan_label filename_label, ucsan_label mode_label,
                   ucsan_label *ret_label) {
  FILE *fake = (FILE *)(__ucsan_fake_file_counter++);
  UCSAN_OUT("__dfsw_fopen(filename=%s, mode=%s) = fake FILE* %p\n",
            filename ? filename : "(null)", mode ? mode : "(null)", fake);
  ucsan_file_state *s = open_file_state(concrete_file_size(filename));
  s->fd = __ucsan_fake_fd_counter++;
  s->stream = fake;
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(FILE*) * 8);
  return fake;
}

__attribute__((visibility("default")))
FILE *__dfsw_fopen64(const char *filename, const char *mode,
                     ucsan_label filename_label, ucsan_label mode_label,
                     ucsan_label *ret_label) {
  return __dfsw_fopen(filename, mode, filename_label, mode_label, ret_label);
}

__attribute__((visibility("default")))
FILE *__dfsw_freopen(const char *filename, const char *mode, FILE *stream,
                     ucsan_label filename_label, ucsan_label mode_label,
                     ucsan_label stream_label, ucsan_label *ret_label) {
  // Single-file simulator: reset position; reissue a fresh fake FILE*.
  __ucsan_file.offset = 0;
  return __dfsw_fopen(filename, mode, filename_label, mode_label, ret_label);
}

__attribute__((visibility("default")))
int __dfsw_close(int fd, ucsan_label fd_label, ucsan_label *ret_label) {
  // Single-file simulator: no per-handle state to tear down. Reset offset
  // so a later open()+read() starts at byte 0 like a fresh handle would.
  __ucsan_file.offset = 0;
  __ucsan_file.fd = -1;
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(int) * 8);
  return 0;
}

__attribute__((visibility("default")))
int __dfsw_fclose(FILE *stream, ucsan_label stream_label, ucsan_label *ret_label) {
  __ucsan_file.offset = 0;
  __ucsan_file.fd = -1;
  __ucsan_file.stream = nullptr;
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(int) * 8);
  return 0;
}

__attribute__((visibility("default")))
int __dfsw_fileno(FILE *stream, ucsan_label stream_label,
                  ucsan_label *ret_label) {
  ucsan_file_state *s = get_file_state();
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(int) * 8);
  if (stream == s->stream)
    return s->fd;
  return s->fd >= 0 ? s->fd : 0;
}

__attribute__((visibility("default")))
int __dfsw_fileno_unlocked(FILE *stream, ucsan_label stream_label,
                           ucsan_label *ret_label) {
  return __dfsw_fileno(stream, stream_label, ret_label);
}

static int simulate_fstat(int fd, struct stat *buf, ucsan_label *ret_label) {
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(int) * 8);
  ucsan_file_state *s = get_file_state();
  if (!buf)
    return -1;
  internal_memset(buf, 0, sizeof(struct stat));
  __taint_set_label(0, buf, sizeof(struct stat));
  buf->st_mode = S_IFREG | 0600;
  buf->st_nlink = 1;
  buf->st_size = simulated_file_size(s);
  UCSAN_OUT("__dfsw_fstat(fd=%d) simulated st_size=%ld\n",
            fd, (long)buf->st_size);
  return 0;
}

__attribute__((visibility("default")))
int __dfsw_ucsan_fstat(int fd, struct stat *buf, ucsan_label fd_label,
                       ucsan_label buf_label, ucsan_label *ret_label) {
  return simulate_fstat(fd, buf, ret_label);
}

__attribute__((visibility("default")))
int __dfsw_ucsan_fstat64(int fd, struct stat *buf, ucsan_label fd_label,
                         ucsan_label buf_label, ucsan_label *ret_label) {
  return simulate_fstat(fd, buf, ret_label);
}

__attribute__((visibility("default")))
int __dfsw_ucsan_fxstat(int vers, int fd, struct stat *buf,
                        ucsan_label vers_label, ucsan_label fd_label,
                        ucsan_label buf_label, ucsan_label *ret_label) {
  return simulate_fstat(fd, buf, ret_label);
}

__attribute__((visibility("default")))
int __dfsw_ucsan_fxstat64(int vers, int fd, struct stat *buf,
                          ucsan_label vers_label, ucsan_label fd_label,
                          ucsan_label buf_label, ucsan_label *ret_label) {
  return simulate_fstat(fd, buf, ret_label);
}

// ===== seek wrappers — just update the simulator offset =====

static void file_seek(ucsan_file_state *s, off_t offset, int whence) {
  if (!s) return;
  off_t new_off;
  switch (whence) {
    case SEEK_SET: new_off = offset; break;
    case SEEK_CUR: new_off = s->offset + offset; break;
    case SEEK_END:
      // Object grows on demand — current size is our best "end" estimate.
      if (s->object_id != 0 && s->object_id < ucsan_tainted.objects->size()) {
        new_off = (off_t)ucsan_tainted.objects->at(s->object_id).data.size() + offset;
      } else {
        new_off = offset;
      }
      break;
    default: return;
  }
  if (new_off < 0) new_off = 0;
  s->offset = new_off;
}

__attribute__((visibility("default")))
int __dfsw_fseek(FILE *stream, long offset, int whence,
                 ucsan_label stream_label, ucsan_label offset_label,
                 ucsan_label whence_label, ucsan_label *ret_label) {
  file_seek(get_file_state(), (off_t)offset, whence);
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(int) * 8);
  return 0;
}

__attribute__((visibility("default")))
int __dfsw_fseeko(FILE *stream, off_t offset, int whence,
                  ucsan_label stream_label, ucsan_label offset_label,
                  ucsan_label whence_label, ucsan_label *ret_label) {
  file_seek(get_file_state(), offset, whence);
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(int) * 8);
  return 0;
}

__attribute__((visibility("default")))
off_t __dfsw_lseek(int fd, off_t offset, int whence,
                   ucsan_label fd_label, ucsan_label offset_label,
                   ucsan_label whence_label, ucsan_label *ret_label) {
  ucsan_file_state *s = get_file_state();
  file_seek(s, offset, whence);
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(off_t) * 8);
  return s->offset;
}

__attribute__((visibility("default")))
void __dfsw_rewind(FILE *stream, ucsan_label stream_label) {
  get_file_state()->offset = 0;
}

__attribute__((visibility("default")))
long __dfsw_ftell(FILE *stream, ucsan_label stream_label, ucsan_label *ret_label) {
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(long) * 8);
  return (long)get_file_state()->offset;
}

// ===== read wrappers — simulate via the file UC object =====

__attribute__((visibility("default")))
ssize_t __dfsw_read(int fd, void *buf, size_t count,
                    ucsan_label fd_label, ucsan_label buf_label,
                    ucsan_label count_label, ucsan_label *ret_label) {
  UCSAN_OUT("__dfsw_read(fd=%d, buf=%p, count=%zu)\n", fd, buf, count);
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(ssize_t) * 8);
  if (!buf || count == 0) return 0;
  ucsan_file_state *s = get_file_state();
  size_t did = simulate_file_read(s, buf, count, s->offset);
  s->offset += (off_t)did;
  return (ssize_t)did;
}

__attribute__((visibility("default")))
ssize_t __dfsw_pread(int fd, void *buf, size_t count, off_t offset,
                     ucsan_label fd_label, ucsan_label buf_label,
                     ucsan_label count_label, ucsan_label offset_label,
                     ucsan_label *ret_label) {
  UCSAN_OUT("__dfsw_pread(fd=%d, buf=%p, count=%zu, offset=%ld)\n", fd, buf, count, (long)offset);
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(ssize_t) * 8);
  if (!buf || count == 0) return 0;
  // pread() does not advance the kernel file offset, and per the design
  // it shouldn't advance ours either — just symbolize from offset.
  ucsan_file_state *s = get_file_state();
  size_t did = simulate_file_read(s, buf, count, offset);
  return (ssize_t)did;
}

__attribute__((visibility("default")))
ssize_t __dfsw_pread64(int fd, void *buf, size_t count, off_t offset,
                       ucsan_label fd_label, ucsan_label buf_label,
                       ucsan_label count_label, ucsan_label offset_label,
                       ucsan_label *ret_label) {
  return __dfsw_pread(fd, buf, count, offset, fd_label, buf_label,
                      count_label, offset_label, ret_label);
}

__attribute__((visibility("default")))
size_t __dfsw_fread(void *ptr, size_t size, size_t nmemb, FILE *stream,
                    ucsan_label ptr_label, ucsan_label size_label,
                    ucsan_label nmemb_label, ucsan_label stream_label,
                    ucsan_label *ret_label) {
  UCSAN_OUT("__dfsw_fread(ptr=%p, size=%zu, nmemb=%zu, stream=%p)\n",
            ptr, size, nmemb, stream);
  *ret_label = 0;
  __taint_set_retval_tls(0, 0, sizeof(size_t) * 8);
  if (!ptr || size == 0 || nmemb == 0) return 0;
  ucsan_file_state *s = get_file_state();
  size_t total = size * nmemb;
  size_t did = simulate_file_read(s, ptr, total, s->offset);
  s->offset += (off_t)did;
  // fread returns count of full elements actually read.
  return did / size;
}

__attribute__((visibility("default")))
size_t __dfsw_fread_unlocked(void *ptr, size_t size, size_t nmemb, FILE *stream,
                             ucsan_label ptr_label, ucsan_label size_label,
                             ucsan_label nmemb_label, ucsan_label stream_label,
                             ucsan_label *ret_label) {
  return __dfsw_fread(ptr, size, nmemb, stream, ptr_label, size_label,
                      nmemb_label, stream_label, ret_label);
}

// ===== fgetc / getc family — single-byte read returned as int =====

static int file_getc(ucsan_file_state *s, ucsan_label *ret_label) {
  if (!s) { *ret_label = 0; return -1; }
  uint8_t byte = 0;
  size_t did = simulate_file_read(s, &byte, 1, s->offset);
  if (did == 0) { *ret_label = 0; return -1; }
  // The byte we just wrote into &byte carries its file-byte label in shadow.
  // Lift that label into the int return value's ret_label slot. The int's
  // upper bits are concrete-zero — only the low 8 bits are symbolic, which
  // matches how the IR will zero-extend the byte into the int register.
  ucsan_label *shadow = ucsan_shadow_for(&byte);
  *ret_label = shadow[0];
  s->offset += 1;

  // Bridge to SymSan: create an 8-bit label for the byte, then ZExt it to 32
  // bits to match fgetc's int return type (C-standard: byte 0..255 zero-extended
  // into int, EOF == -1 handled by the concrete return path above). Z3 errors
  // on width mismatch between the loaded retval TLS shadow and the i32 return.
  dfsan_label byte_label = __taint_create_label(s->object_id, (uint64_t)(s->offset - 1), 1);
  dfsan_label int_label = __taint_extend_label(byte_label, /*sign_extend=*/false, 32);
  __taint_set_retval_tls(0, int_label, 32);

  return (int)byte;
}

__attribute__((visibility("default")))
int __dfsw_fgetc(FILE *stream, ucsan_label stream_label, ucsan_label *ret_label) {
  return file_getc(get_file_state(), ret_label);
}

__attribute__((visibility("default")))
int __dfsw_fgetc_unlocked(FILE *stream, ucsan_label stream_label, ucsan_label *ret_label) {
  return __dfsw_fgetc(stream, stream_label, ret_label);
}

__attribute__((visibility("default")))
int __dfsw_getc(FILE *stream, ucsan_label stream_label, ucsan_label *ret_label) {
  return __dfsw_fgetc(stream, stream_label, ret_label);
}

__attribute__((visibility("default")))
int __dfsw_getc_unlocked(FILE *stream, ucsan_label stream_label, ucsan_label *ret_label) {
  return __dfsw_fgetc(stream, stream_label, ret_label);
}

__attribute__((visibility("default")))
int __dfsw__IO_getc(FILE *stream, ucsan_label stream_label, ucsan_label *ret_label) {
  return __dfsw_fgetc(stream, stream_label, ret_label);
}

__attribute__((visibility("default")))
int __dfsw_getchar(ucsan_label *ret_label) {
  return file_getc(get_file_state(), ret_label);
}

} // extern "C"
