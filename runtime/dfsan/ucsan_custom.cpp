// UCSan custom function wrappers for standalone mode
// Provides minimal malloc/free wrappers with bounds tracking

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_common.h"
#include "ucsan_platform.h"
#include "ucsan.h"

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
  void __taint_copy_shadow(void *dst, void *src, u64 size);
  void __taint_move_shadow(void *dst, void *src, u64 size);
  void __taint_set_label(u32 label, void *addr, u64 size);
}

// Simple passthrough wrappers for malloc family
// In standalone UCSan mode, we don't track taint, just provide the symbols

extern "C" {

// Helper to create an alloca-style bounds label for heap allocations
// Also sets shadow memory to kUninitializedLabel for UBI detection
static ucsan_label create_alloca_label(void *ptr, size_t size) {
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
  ucsan_label *shadow = ucsan_shadow_for(ptr);
  for (size_t i = 0; i < size; i++) {
    shadow[i] = kUninitializedLabel;
  }

  return label;
}

__attribute__((visibility("default")))
void *__dfsw_malloc(size_t size, ucsan_label size_label, ucsan_label *ret_label) {
  void *ret = __libc_malloc(size);
  UCSAN_OUT("__dfsw_malloc(%zu) = %p\n", size, ret);
  if (ret) {
    // Create bounds label (sets shadow to kUninitializedLabel for UBI)
    *ret_label = create_alloca_label(ret, size);
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
    *ret_label = create_alloca_label(ret, total_size);
  } else {
    *ret_label = UCSAN_CONST_LABEL;
  }
  return ret;
}

__attribute__((visibility("default")))
void *__dfsw_realloc(void *ptr, size_t size, ucsan_label ptr_label,
                     ucsan_label size_label, ucsan_label *ret_label) {
  // If ptr has an alloca label, mark it as freed
  if (ptr && ptr_label > UCSAN_CONST_LABEL) {
    ucsan_label_info *old_info = get_label_info(ptr_label);
    if (old_info->common.op == OP_ALLOCA) {
      old_info->common.op = OP_FREE;  // Mark old buffer as freed
    }
  }

  // don't actually free the buffer
  void *ret = __libc_malloc(size);
  if (ret) {
    // Create bounds label (sets shadow to kUninitializedLabel for UBI)
    *ret_label = create_alloca_label(ret, size);
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
    *ret_label = create_alloca_label(ret, size);
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
    *ret_label = create_alloca_label(ret, size);
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
    *ret_label = create_alloca_label(ret, size);
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
    *ret_label = create_alloca_label(ret, size);
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
    ucsan_label alloca_label = create_alloca_label(*memptr, size);
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

} // extern "C"
