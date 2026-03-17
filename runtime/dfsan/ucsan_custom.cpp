// UCSan custom function wrappers for standalone mode
// Provides minimal malloc/free wrappers with bounds tracking

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_common.h"
#include "ucsan_platform.h"
#include "ucsan.h"

#include <malloc.h>

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
}

// Simple passthrough wrappers for malloc family
// In standalone UCSan mode, we don't track taint, just provide the symbols

extern "C" {

// Helper to create an alloca-style bounds label for heap allocations
// Also sets shadow memory to kUninitializedLabel for UBI detection
static ucsan_label create_alloca_label(void *ptr, size_t size, bool set_uninitialized) {
  ucsan_label label = allocate_label();
  check_label(label);

  ucsan_label_info *info = get_label_info(label);
  ucsan_obj_info *obj = to_obj_info(info);

  obj->op = OP_ALLOCA;
  obj->_reserved = 0;
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
  void *ret = __libc_malloc(size);
  UCSAN_OUT("__dfsw_malloc(%zu) = %p\n", size, ret);
  if (ret) {
    // Create bounds label (sets shadow to kUninitializedLabel for UBI)
    *ret_label = create_alloca_label(ret, size, true);
  } else {
    *ret_label = UCSAN_CONST_LABEL;
  }
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
  void *ret = __libc_calloc(nmemb, size);
  size_t total_size = nmemb * size;
  if (ret) {
    // Create bounds label (sets shadow to kUninitializedLabel for UBI)
    // (calloc zeros memory, but we still want to detect reads before writes)
    *ret_label = create_alloca_label(ret, total_size, false);
  } else {
    *ret_label = UCSAN_CONST_LABEL;
  }
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
      ucsan_obj_info *old_obj = to_obj_info(old_info);
      if (old_obj->op == OP_ALLOCA) {
        old_obj->op = OP_FREE;  // Mark old buffer as freed
      }
      old_size = old_obj->upper_bound - old_obj->lower_bound;
      if (ptr != old_obj->real_ptr) {
        UCSAN_OUT("WARNING: realloc ptr %p does not match real_ptr %p\n", ptr, old_obj->real_ptr);
      }
    } else {
      old_size = malloc_usable_size(ptr);
    }
  }

  // don't actually free the buffer
  void *ret = __libc_malloc(size);
  if (ret) {
    // Create bounds label (sets shadow to kUninitializedLabel for UBI)
    *ret_label = create_alloca_label(ret, size, true);
    // Copy data from old buffer to new buffer (up to min of old/new size)
    size_t copy_size = old_size < size ? old_size : size;
    internal_memcpy(ret, ptr, copy_size);
    // Copy UCSan shadow memory from old to new
    ucsan_label *sdest = ucsan_shadow_for(ret);
    const ucsan_label *ssrc = ucsan_shadow_for(ptr);
    internal_memcpy((void *)sdest, (const void *)ssrc, copy_size * sizeof(ucsan_label));
    // Bridge to SymSan: copy SymSan shadow memory
    __taint_copy_shadow(ret, (void *)ptr, copy_size);
  } else {
    *ret_label = UCSAN_CONST_LABEL;
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
  void *ret = aligned_alloc(alignment, size);
  if (ret) {
    // Create bounds label (sets shadow to kUninitializedLabel for UBI)
    *ret_label = create_alloca_label(ret, size, true);
  } else {
    *ret_label = UCSAN_CONST_LABEL;
  }
  return ret;
}

__attribute__((visibility("default")))
void *__dfsw_aligned_alloc(size_t alignment, size_t size,
                           ucsan_label alignment_label, ucsan_label size_label,
                           ucsan_label *ret_label) {
  void *ret = aligned_alloc(alignment, size);
  if (ret) {
    // Create bounds label (sets shadow to kUninitializedLabel for UBI)
    *ret_label = create_alloca_label(ret, size, true);
  } else {
    *ret_label = UCSAN_CONST_LABEL;
  }
  return ret;
}

#define PAGE_SIZE 4096

__attribute__((visibility("default")))
void *__dfsw_valloc(size_t size, ucsan_label size_label, ucsan_label *ret_label) {
  void *ret = aligned_alloc(PAGE_SIZE, size);
  if (ret) {
    // Create bounds label (sets shadow to kUninitializedLabel for UBI)
    *ret_label = create_alloca_label(ret, size, true);
  } else {
    *ret_label = UCSAN_CONST_LABEL;
  }
  return ret;
}

__attribute__((visibility("default")))
void *__dfsw_pvalloc(size_t size, ucsan_label size_label, ucsan_label *ret_label) {
  void *ret = aligned_alloc(PAGE_SIZE, size);
  if (ret) {
    // Create bounds label (sets shadow to kUninitializedLabel for UBI)
    *ret_label = create_alloca_label(ret, size, true);
  } else {
    *ret_label = UCSAN_CONST_LABEL;
  }
  return ret;
}

__attribute__((visibility("default")))
int __dfsw_posix_memalign(void **memptr, size_t alignment, size_t size,
                          ucsan_label memptr_label, ucsan_label alignment_label,
                          ucsan_label size_label, ucsan_label *ret_label) {
  int result = posix_memalign(memptr, alignment, size);
  if (result == 0 && *memptr) {
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

SANITIZER_INTERFACE_ATTRIBUTE void
__dfsw_assert_allocated(void *ptr, size_t size, uint64_t id, ucsan_label ptr_label,
                        ucsan_label size_label, ucsan_label id_label) {
  if (ptr_label == 0) {
    UCSAN_OUT("ERROR: assertion %lu failure non-symbolic label: ptr %p\n", id, ptr);
    return;
  }
  ucsan_label_info *info = get_label_info(ptr_label);
  ucsan_obj_info *obj = to_obj_info(info);
  if (obj->op != OP_ALLOCA) {
    UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, label %d, op %d\n", id, ptr, ptr_label, obj->op);
    return;
  }
  if (ptr != obj->real_ptr) {
    UCSAN_OUT("ERROR: assertion %lu failure: ptr %p does not match real_ptr %p\n", id, ptr, obj->real_ptr);
    return;
  }
  if (size > obj->upper_bound) {
    UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, label %d, size %lu exceeds upper bound %u\n",
              id, ptr, ptr_label, size, obj->upper_bound);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void
__dfsw_assert_freed(void *ptr, uint64_t id, ucsan_label ptr_label, ucsan_label id_label) {
  if (ptr_label == 0) {
    UCSAN_OUT("ERROR: assertion %lu failure non-symbolic label: ptr %p, label %d\n", id, ptr, ptr_label);
    return;
  }
  ucsan_label_info *info = get_label_info(ptr_label);
  ucsan_obj_info *obj = to_obj_info(info);
  if (obj->op != OP_FREE) {
    UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, label %d, op %d\n", id, ptr, ptr_label, obj->op);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void
__dfsw_assert_init(void *ptr, size_t size, uint64_t id, ucsan_label ptr_label,
                   ucsan_label size_label, ucsan_label id_label) {
  // check ptr is allocated and the size is in bound
  if (ptr_label == 0) {
    UCSAN_OUT("ERROR: assertion %lu failure non-symbolic label: ptr %p, label %d\n", id, ptr, ptr_label);
    return;
  }
  ucsan_label_info *info = get_label_info(ptr_label);
  ucsan_obj_info *obj = to_obj_info(info);
  if (obj->op != OP_ALLOCA) {
    UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, label %d, op %d\n", id, ptr, ptr_label, obj->op);
    return;
  }
  if (size > obj->upper_bound) {
    UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, label %d, size %lu exceeds upper bound %u\n",
              id, ptr, ptr_label, size, obj->upper_bound);
    return;
  }
  ucsan_label *shadow = ucsan_shadow_for(ptr);
  for (size_t i = 0; i < size; i++) {
    if (shadow[i] == kUninitializedLabel) {
      UCSAN_OUT("ERROR: assertion %lu failure: ptr %p, index %lu, label %d\n", id, ptr, i, shadow[i]);
    }
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
    void *new_ptr = __dfsw_malloc(size, size_label, ret_label);
    if (new_ptr) {
      void *old_ptr = ucsan_check_pointer(ptr, ptr_label, size, true);
      ucsan_label dummy;
      __dfsw_memcpy(new_ptr, old_ptr, size, *ret_label, ptr_label, size_label, &dummy);
      return new_ptr;
    }
  }

  return ptr;
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

} // extern "C"
