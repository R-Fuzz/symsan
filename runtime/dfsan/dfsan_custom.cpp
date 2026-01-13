//===-- dfsan.cc ----------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// This file defines the custom functions listed in done_abilist.txt.
//===----------------------------------------------------------------------===//

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <malloc.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utmpx.h>
#include <wchar.h>

#include "dfsan.h"

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_stackdepot.h"

using namespace __dfsan;

#define CALL_WEAK_INTERCEPTOR_HOOK(f, ...)                                     \
  do {                                                                         \
    if (f)                                                                     \
      f(__VA_ARGS__);                                                          \
  } while (false)
#define DECLARE_WEAK_INTERCEPTOR_HOOK(f, ...) \
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE void f(__VA_ARGS__);

#define AIXCC_HACK 1

static off_t current_stdin_offset = 0;

// Runtime maps to track string labels by buffer address
// Use simple fixed-size arrays to avoid STL dependencies in runtime

// Map for content labels (fsubstr, fstrcat) from strncpy/strcat destinations
static const uptr CONTENT_MAP_SIZE = 1024;
static struct {
  uptr addr;
  dfsan_label label;
} __taint_content_map[CONTENT_MAP_SIZE];
static uptr content_map_count = 0;

// Map for indexOf labels (fstrchr, fstrrchr, etc.) from strchr/memchr result positions
static const uptr INDEXOF_MAP_SIZE = 1024;
static struct {
  uptr addr;
  dfsan_label label;
} __taint_indexof_map[INDEXOF_MAP_SIZE];
static uptr indexof_map_count = 0;

// Set/get for content labels (fsubstr, fstrcat)
static inline void set_content_label(void *addr, dfsan_label label) {
  AOUT("set_content_label: addr=%p, label=%u\n", addr, label);
  for (uptr i = 0; i < content_map_count; i++) {
    if (__taint_content_map[i].addr == (uptr)addr) {
      AOUT("update content label: old = %u\n", __taint_content_map[i].label);
      __taint_content_map[i].label = label;
      return;
    }
  }
  if (content_map_count < CONTENT_MAP_SIZE) {
    __taint_content_map[content_map_count].addr = (uptr)addr;
    __taint_content_map[content_map_count].label = label;
    content_map_count++;
  }
}

static inline dfsan_label get_content_label(const void *addr) {
  for (uptr i = 0; i < content_map_count; i++) {
    if (__taint_content_map[i].addr == (uptr)addr) {
      AOUT("get_content_label: addr=%p, found label=%u\n", addr, __taint_content_map[i].label);
      return __taint_content_map[i].label;
    }
  }
  AOUT("addr=%p, not found\n", addr);
  return 0;
}

// Set/get for indexOf labels (fstrchr, fstrrchr, fstrstr, fstrpbrk)
static inline void set_indexof_label(void *addr, dfsan_label label) {
  AOUT("set_indexof_label: addr=%p, label=%u\n", addr, label);
  for (uptr i = 0; i < indexof_map_count; i++) {
    if (__taint_indexof_map[i].addr == (uptr)addr) {
      AOUT("update indexof label: old = %u\n", __taint_indexof_map[i].label);
      __taint_indexof_map[i].label = label;
      return;
    }
  }
  if (indexof_map_count < INDEXOF_MAP_SIZE) {
    __taint_indexof_map[indexof_map_count].addr = (uptr)addr;
    __taint_indexof_map[indexof_map_count].label = label;
    indexof_map_count++;
  }
}

static inline dfsan_label get_indexof_label(const void *addr) {
  for (uptr i = 0; i < indexof_map_count; i++) {
    if (__taint_indexof_map[i].addr == (uptr)addr) {
      AOUT("addr=%p, found label=%u\n", addr, __taint_indexof_map[i].label);
      return __taint_indexof_map[i].label;
    }
  }
  AOUT("addr=%p, not found\n", addr);
  return 0;
}

// Check if an op is a string operation (fstr_op_start to fstr_op_end)
static inline bool is_string_op(uint16_t op) {
  return op >= __dfsan::fstr_op_start && op < __dfsan::fstr_op_end;
}

// Check if an op is an indexOf-type operation (returns position, not content)
// These are: fstrchr, fstrrchr, fstrstr, fstrpbrk, fstr_off
static inline bool is_indexof_op(uint16_t op) {
  return op >= __dfsan::fstrchr && op <= __dfsan::fstr_off;
}

// Check if an op is a content-type string operation (fsubstr, fstrcat)
static inline bool is_content_string_op(uint16_t op) {
  return op == __dfsan::fsubstr || op == __dfsan::fstrcat;
}

// Helper: Find the first (base) input byte label from a content label.
// Walks through Concat chains and Load operations to find the starting input.
// Returns the base label, or 0 if not found.
static dfsan_label get_base_input_label(dfsan_label label) {
  if (label < CONST_OFFSET) return 0;

  dfsan_label_info *info = dfsan_get_label_info(label);

  // Base input label has op == 0
  if (info->op == 0) return label;

  // For Concat (op 72), walk left (l1) to find the base
  if (info->op == __dfsan::Concat) {
    return get_base_input_label(info->l1);
  }

  // For Load (op 32), l1 is the starting label
  if (info->op == __dfsan::Load) {
    return info->l1;
  }

  // For other ops, try l1
  if (info->l1 >= CONST_OFFSET) {
    return get_base_input_label(info->l1);
  }

  return 0;
}

// Helper: Find if a label derives from a string op (fstrchr, fstrrchr, fstrstr)
// by walking through PtrToInt, Sub, Add operations.
// Returns the string op label if found, 0 otherwise.
static dfsan_label find_string_op_source(dfsan_label label) {
  if (label < CONST_OFFSET) return 0;

  dfsan_label_info *info = dfsan_get_label_info(label);
  uint16_t op = info->op;

  // Check if this is directly a string op
  if (is_string_op(op)) {
    return label;
  }

  // Follow through PtrToInt, Sub, Add to find the source string op
  if (op == __dfsan::PtrToInt || op == __dfsan::Sub || op == __dfsan::Add) {
    // Recursively check l1 (the primary operand)
    if (info->l1 >= CONST_OFFSET) {
      dfsan_label result = find_string_op_source(info->l1);
      if (result != 0) return result;
    }
    // For Sub/Add, also check l2
    if ((op == __dfsan::Sub || op == __dfsan::Add) && info->l2 >= CONST_OFFSET) {
      dfsan_label result = find_string_op_source(info->l2);
      if (result != 0) return result;
    }
  }

  return 0;
}

// Unified method to get string label with explicit length
// Checks (in order):
// 1. Runtime content map (for strncpy/strcat destinations)
// 2. Pointer label itself being a content-type string op (for chaining)
// 3. indexOf map at address s for suffix case (strcpy from pos+1)
// 4. If n_label derives from a string op, create fsubstr to preserve constraint
// 5. Buffer content labels via dfsan_read_label
static inline dfsan_label get_str_label_n(const void *s, dfsan_label s_label,
                                           size_t n, dfsan_label n_label) {
  AOUT("get_str_label_n: s=%p, s_label=%u, n=%zu, n_label=%u\n", s, s_label, n, n_label);

  // 1. Check content map for fsubstr/fstrcat labels (from strncpy/strcat destinations)
  dfsan_label content = get_content_label(s);
  if (content != 0) {
    AOUT("get_str_label_n: step 1 returns content=%u\n", content);
    return content;
  }

  // 2. Check if pointer label itself is a content-type string op (for chaining)
  // Only chain on fsubstr/fstrcat, NOT indexOf ops (fstrchr, fstrrchr, etc.)
  if (s_label >= CONST_OFFSET) {
    dfsan_label_info *info = dfsan_get_label_info(s_label);
    AOUT("get_str_label_n: step 2 s_label op=%u, is_content=%d\n",
         info ? info->op : 0, info ? is_content_string_op(info->op) : 0);
    if (info && is_content_string_op(info->op)) {
      AOUT("get_str_label_n: step 2 returns s_label=%u\n", s_label);
      return s_label;
    }
  }

  // 3. Check for suffix case: searching from a previous indexOf result position
  // Creates fsubstr(content, start_pos, remaining) for:
  //   a) strcpy(suffix, pos + 1) where gep_ptr stored fstr_off at pos+1
  //   b) memchr(t1, c, len) where t1 was returned by previous indexOf
  dfsan_label start_label = get_indexof_label(s);
  if (start_label != 0) {
    dfsan_label_info *start_info = dfsan_get_label_info(start_label);
    if (start_info) {
      dfsan_label indexOf_label = 0;

      if (start_info->op == __dfsan::fstr_off && start_info->l1 >= CONST_OFFSET) {
        // Case 3a: fstr_off points to indexOf op
        indexOf_label = start_info->l1;
      } else if (is_indexof_op(start_info->op)) {
        // Case 3b: Direct indexOf - only if s_label confirms indexOf origin
        // This distinguishes memchr(t1,...) from memchr(buf,...) when t1==buf
        dfsan_label_info *s_info = (s_label >= CONST_OFFSET) ?
                                    dfsan_get_label_info(s_label) : nullptr;
        if (s_info && is_indexof_op(s_info->op)) {
          indexOf_label = start_label;
        }
      }

      if (indexOf_label != 0) {
        dfsan_label_info *idx_info = dfsan_get_label_info(indexOf_label);
        if (idx_info && idx_info->l1 >= CONST_OFFSET) {
          // Create suffix fsubstr: substr(content, start_pos, remaining)
          // l1=content, l2=position label, op1=concrete len, op2=1 (suffix mode)
          return dfsan_union(idx_info->l1, start_label, __dfsan::fsubstr,
                             sizeof(void*) * 8, (uint64_t)n, 1);
        }
      }
    }
  }

  // 4. Check if n_label derives from a string op (e.g., ptr arithmetic on memchr result)
  // If so, create fsubstr to represent substr(content, 0, idx) where idx is the string op result
  // IMPORTANT: Do this even when n=0 to preserve the symbolic constraint!
  dfsan_label str_op_label = find_string_op_source(n_label);
  if (str_op_label != 0) {
    dfsan_label_info *str_op_info = dfsan_get_label_info(str_op_label);
    dfsan_label str_op_content = str_op_info->l1;

    if (str_op_content >= CONST_OFFSET) {
      // Get content label from buffer if available for same-buffer verification
      dfsan_label content_label = (n > 0) ? dfsan_read_label(s, n) : 0;

      // Verify same underlying buffer only if content is available
      bool same_buffer = true;
      if (content_label != 0) {
        dfsan_label src_base = get_base_input_label(content_label);
        dfsan_label str_op_base = get_base_input_label(str_op_content);
        same_buffer = (src_base != 0 && src_base == str_op_base);
      }
      // When n=0, trust that n_label derives from same buffer
      // (the alternative is losing the constraint entirely)

      if (same_buffer) {
        // Create fsubstr: substr(str_op_content, 0, str_op_label)
        // l1 = original content, l2 = string op label (index), op1 = concrete n, op2 = 0
        return dfsan_union(str_op_content, str_op_label, __dfsan::fsubstr,
                           sizeof(void*) * 8, (uint64_t)n, 0);
      }
    }
  }

  // 5. Fall back to reading buffer content labels
  return dfsan_read_label(s, n);
}

// Unified method to get string label for null-terminated strings
// Uses strlen to determine length
// Also checks if null terminator was placed at a strchr/strstr result position
static inline dfsan_label get_str_label(const char *s, dfsan_label s_label) {
  size_t len = strlen(s);

  // Check if null terminator was placed at a position found by strchr/strstr/etc.
  // This allows us to recover symbolic length when code does:
  //   pos = strchr(buf, '_'); *pos = '\0'; strcpy(dest, buf);
  dfsan_label term_label = get_indexof_label(s + len);

  return get_str_label_n(s, s_label, len + 1, term_label);
}

static inline dfsan_label get_label_for(int fd, off_t offset) {
  // check if fd is stdin, if so, the label hasn't been pre-allocated
  if (is_stdin_taint() || (fd ==0 && flags().force_stdin))
    return dfsan_create_label(current_stdin_offset++);
  // if fd is a tainted file, the label should have been pre-allocated
  else return (offset + CONST_OFFSET);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_offset(dfsan_label offset_label, int64_t offset, unsigned size);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_memcmp(dfsan_label label);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_check_bounds(dfsan_label addr_label, uptr addr,
                          dfsan_label size_label, uint64_t size);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_trace_cond(dfsan_label label, bool r, uint8_t flag, uint32_t cid);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_solve_bounds(dfsan_label ptr_label, uint64_t ptr,
                          dfsan_label index_label, int64_t index,
                          uint64_t num_elems, uint64_t elem_size,
                          int64_t current_offset, uint32_t cid);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_solve_size(dfsan_label ptr_label, uint64_t ptr,
                        dfsan_label size_label, uint64_t size,
                        uint32_t cid);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_trace_memerr(dfsan_label ptr_label, uptr ptr,
                          dfsan_label size_label, uint64_t size,
                          uint16_t flag, void *addr);

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_stat(const char *path, struct stat *buf, dfsan_label path_label,
            dfsan_label buf_label, dfsan_label *ret_label) {
  int ret = stat(path, buf);
  if (ret == 0) {
    dfsan_set_label(0, buf, sizeof(struct stat));
    if (flags().trace_fsize && is_taint_file(path)) {
      dfsan_label size = dfsan_union(0, 0, fsize, sizeof(buf->st_size) * 8, 0, 0);
      dfsan_set_label(size, &buf->st_size, sizeof(buf->st_size));
    }
  }
  *ret_label = 0;
  return ret;
}

#if __GLIBC__ <= 2 && __GLIBC_MINOR__ < 33
SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw___xstat(int vers, const char *path, struct stat *buf,
               dfsan_label vers_label, dfsan_label path_label,
               dfsan_label buf_label, dfsan_label *ret_label) {
  int ret = __xstat(vers, path, buf);
  if (ret == 0) {
    dfsan_set_label(0, buf, sizeof(struct stat));
    if (flags().trace_fsize && is_taint_file(path)) {
      dfsan_label size = dfsan_union(0, 0, fsize, sizeof(buf->st_size) * 8, 0, 0);
      dfsan_set_label(size, &buf->st_size, sizeof(buf->st_size));
    }
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw___fxstat(int vers, const int fd, struct stat *buf,
                dfsan_label vers_label, dfsan_label fd_label,
                dfsan_label buf_label, dfsan_label *ret_label) {
  int ret = __fxstat(vers, fd, buf);
  if (ret == 0) {
    dfsan_set_label(0, buf, sizeof(struct stat));
    if (flags().trace_fsize && taint_get_file(fd)) {
      dfsan_label size = dfsan_union(0, 0, fsize, sizeof(buf->st_size) * 8, 0, 0);
      dfsan_set_label(size, &buf->st_size, sizeof(buf->st_size));
    }
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw___lxstat(int vers, const char *path, struct stat *buf,
                dfsan_label vers_label, dfsan_label path_label,
                dfsan_label buf_label, dfsan_label *ret_label) {
  int ret = __lxstat(vers, path, buf);
  if (ret == 0) {
    dfsan_set_label(0, buf, sizeof(struct stat));
    if (flags().trace_fsize && is_taint_file(path)) {
      dfsan_label size = dfsan_union(0, 0, fsize, sizeof(buf->st_size) * 8, 0, 0);
      dfsan_set_label(size, &buf->st_size, sizeof(buf->st_size));
    }
  }
  *ret_label = 0;
  return ret;
}
#endif

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_fstat(int fd, struct stat *buf,
                                               dfsan_label fd_label,
                                               dfsan_label buf_label,
                                               dfsan_label *ret_label) {
  int ret = fstat(fd, buf);
  if (ret == 0) {
    dfsan_set_label(0, buf, sizeof(struct stat));
    if (flags().trace_fsize && taint_get_file(fd)) {
      dfsan_label size = dfsan_union(0, 0, fsize, sizeof(buf->st_size) * 8, 0, 0);
      dfsan_set_label(size, &buf->st_size, sizeof(buf->st_size));
    }
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_lstat(const char *path, struct stat *buf, dfsan_label path_label,
             dfsan_label buf_label, dfsan_label *ret_label) {
  int ret = lstat(path, buf);
  if (ret == 0) {
    dfsan_set_label(0, buf, sizeof(struct stat));
    if (flags().trace_fsize && is_taint_file(path)) {
      dfsan_label size = dfsan_union(0, 0, fsize, sizeof(buf->st_size) * 8, 0, 0);
      dfsan_set_label(size, &buf->st_size, sizeof(buf->st_size));
    }
  }
  *ret_label = 0;
  return ret;
}

// Create a label for string op + constant offset (for pointer arithmetic like sep + 1)
// If base_label is a string op, returns a new fstr_off label; otherwise returns base_label
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_trace_gep_ptr(dfsan_label base_label, char *result, char *base) {
  if (base_label < CONST_OFFSET) return;

  // Check if base_label is or derives from a string op
  dfsan_label str_op_label = find_string_op_source(base_label);
  if (str_op_label == 0) {
    // Not a string op - return base label unchanged
    return;
  }

  // Create fstr_off label: l1=str_op_label, op1=offset
  // This represents the content at (string_op_position + offset)
  uint64_t offset = (uint64_t)(result - base);
  dfsan_label off_label = dfsan_union(str_op_label, 0, __dfsan::fstr_off,
                                       sizeof(void*) * 8,
                                       0, (uint64_t)offset);
  AOUT("gep_ptr: base=%u, str_op=%u, offset=%ld, result=%u\n",
       base_label, str_op_label, offset, off_label);

  // record the label (fstr_off is an indexOf-type op)
  set_indexof_label(result, off_label);
}

SANITIZER_INTERFACE_ATTRIBUTE char *__dfsw_strchr(char *s, int c,
                                                  dfsan_label s_label,
                                                  dfsan_label c_label,
                                                  dfsan_label *ret_label) {
  char *ret = strchr(s, c);

  // Use unified get_str_label to get source label
  // Handles str_map, pointer label fsubstr, and buffer content
  dfsan_label src_label = get_str_label(s, s_label);

  // Create label if source or char is tainted
  if (src_label != 0 || c_label != 0) {
    // Determine which operand is concrete and set size accordingly
    size_t haystack_len = strlen(s);
    uint16_t content_len = (src_label == 0) ? (uint16_t)haystack_len : 0;

    // l1 = src_label (source - for chaining or content dependencies)
    // l2 = c_label (target char - may be symbolic!)
    // op1 = haystack pointer (for concrete content retrieval)
    // op2 = char value
    // size = haystack length if concrete, else 0
    *ret_label = dfsan_union(src_label, c_label, __dfsan::fstrchr,
                             content_len,
                             (uint64_t)s,
                             (uint64_t)(uint8_t)c);

    // Send concrete haystack content if haystack is concrete
    if (content_len > 0 && *ret_label) {
      __taint_trace_memcmp(*ret_label);
    }

    // Store the result pointer to recover symbolic length
    if (ret) {
      set_indexof_label(ret, *ret_label);
    }
  } else {
    *ret_label = 0;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE char *__dfsw_strpbrk(const char *s,
                                                   const char *accept,
                                                   dfsan_label s_label,
                                                   dfsan_label accept_label,
                                                   dfsan_label *ret_label) {
  const char *ret = strpbrk(s, accept);
  size_t accept_len = strlen(accept);

  // Use unified get_str_label for source string
  dfsan_label src_label = get_str_label(s, s_label);

  // Use unified get_str_label for accept string
  dfsan_label real_accept_label = get_str_label(accept, accept_label);

  if (src_label != 0 || real_accept_label != 0) {
    // Determine which operand is concrete and set size accordingly
    size_t haystack_len = strlen(s);
    uint16_t content_len = 0;
    if (src_label == 0) {
      content_len = (uint16_t)haystack_len;
    } else if (real_accept_label == 0) {
      content_len = (uint16_t)accept_len;
    }

    // l1 = src_label (source content)
    // l2 = accept_label (character set - may be symbolic)
    // op1 = haystack pointer (for concrete content retrieval)
    // op2 = accept pointer (for concrete content retrieval)
    // size = haystack length if haystack concrete, else accept length if accept concrete, else 0
    dfsan_label label = dfsan_union(src_label, real_accept_label, __dfsan::fstrpbrk,
                                    content_len,
                                    (uint64_t)s,
                                    (uint64_t)accept);

    // Send concrete content (haystack or accept)
    if (content_len > 0 && label) {
      __taint_trace_memcmp(label);
    }

    *ret_label = label;
    // Store the result pointer to recover symbolic length
    if (ret) {
      set_indexof_label(const_cast<char *>(ret), *ret_label);
    }
  } else {
    *ret_label = 0;
  }
  return const_cast<char *>(ret);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_memcmp(const void *s1, const void *s2, size_t n) {
  dfsan_label l1 = dfsan_read_label(s1, n);
  dfsan_label l2 = dfsan_read_label(s2, n);
  dfsan_label ret = dfsan_union(l1, l2, fmemcmp, n, (uint64_t)s1, (uint64_t)s2);
  if (ret) __taint_trace_memcmp(ret);
  return ret;
}

DECLARE_WEAK_INTERCEPTOR_HOOK(dfsan_weak_hook_memcmp, uptr caller_pc,
                              const void *s1, const void *s2, size_t n,
                              dfsan_label s1_label, dfsan_label s2_label,
                              dfsan_label n_label)

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_memcmp(const void *s1, const void *s2,
                                                size_t n, dfsan_label s1_label,
                                                dfsan_label s2_label,
                                                dfsan_label n_label,
                                                dfsan_label *ret_label) {
  CALL_WEAK_INTERCEPTOR_HOOK(dfsan_weak_hook_memcmp, GET_CALLER_PC(), s1, s2, n,
                             s1_label, s2_label, n_label);
  __taint_check_bounds(s1_label, (uptr)s1, n_label, n);
  __taint_check_bounds(s2_label, (uptr)s2, n_label, n);
  int ret = memcmp(s1, s2, n);

  // Check for fsubstr labels
  dfsan_label l1 = get_str_label_n(s1, s1_label, n, n_label);
  dfsan_label l2 = get_str_label_n(s2, s2_label, n, n_label);

  if (l1 == 0 && l2 == 0) {
    *ret_label = 0;
    return ret;
  }

  // Check if either side is a string op - use string theory comparison
  bool l1_is_string_op = (l1 >= CONST_OFFSET && is_string_op(dfsan_get_label_info(l1)->op));
  bool l2_is_string_op = (l2 >= CONST_OFFSET && is_string_op(dfsan_get_label_info(l2)->op));

  if (l1_is_string_op || l2_is_string_op) {
    dfsan_label cmp = dfsan_union(l1, l2, __dfsan::fstrcmp, n,
                                   (uint64_t)s1, (uint64_t)s2);
    if (cmp) __taint_trace_memcmp(cmp);
    *ret_label = cmp;
  } else {
    // Normal case: use fmemcmp
    *ret_label = __taint_memcmp(s1, s2, n);
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_bcmp(const void *s1, const void *s2,
                                              size_t n, dfsan_label s1_label,
                                              dfsan_label s2_label,
                                              dfsan_label n_label,
                                              dfsan_label *ret_label) {
  __taint_check_bounds(s1_label, (uptr)s1, n_label, n);
  __taint_check_bounds(s2_label, (uptr)s2, n_label, n);
  int ret = bcmp(s1, s2, n);

  // Check for fsubstr labels (from strncpy with symbolic length)
  dfsan_label l1 = get_str_label_n(s1, s1_label, n, n_label);
  dfsan_label l2 = get_str_label_n(s2, s2_label, n, n_label);

  if (l1 == 0 && l2 == 0) {
    *ret_label = 0;
    return ret;
  }

  // Check if either side is a string op - use string theory comparison
  bool l1_is_string_op = (l1 >= CONST_OFFSET && is_string_op(dfsan_get_label_info(l1)->op));
  bool l2_is_string_op = (l2 >= CONST_OFFSET && is_string_op(dfsan_get_label_info(l2)->op));

  if (l1_is_string_op || l2_is_string_op) {
    // fstrcmp is commutative - dfsan_union will swap to put concrete in op1
    dfsan_label cmp = dfsan_union(l1, l2, __dfsan::fstrcmp, n,
                                   (uint64_t)s1, (uint64_t)s2);
    if (cmp) __taint_trace_memcmp(cmp);
    *ret_label = cmp;
  } else {
    // Normal case: use fmemcmp
    *ret_label = __taint_memcmp(s1, s2, n);
  }
  return ret;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_strcmp(const char *s1, const char *s2) {
  size_t n = strlen(s1) + 1; // including tailing '\0'
  if (dfsan_get_label(s1) != 0)
    n = strlen(s2) + 1; // including tailing '\0'

  // Check if first byte of s1 or s2 has an fsubstr label
  // If so, use it directly instead of dfsan_read_label to avoid mixing String/BV sorts
  dfsan_label l1 = 0;
  dfsan_label s1_first = dfsan_get_label((char*)s1);
  if (s1_first >= CONST_OFFSET) {
    dfsan_label_info *info = dfsan_get_label_info(s1_first);
    if (info->op == __dfsan::fsubstr) {
      l1 = s1_first;  // Use fsubstr directly
    }
  }
  if (l1 == 0) {
    l1 = dfsan_read_label(s1, n);
  }

  dfsan_label l2 = 0;
  dfsan_label s2_first = dfsan_get_label((char*)s2);
  if (s2_first >= CONST_OFFSET) {
    dfsan_label_info *info = dfsan_get_label_info(s2_first);
    if (info->op == __dfsan::fsubstr) {
      l2 = s2_first;  // Use fsubstr directly
    }
  }
  if (l2 == 0) {
    l2 = dfsan_read_label(s2, n);
  }

  dfsan_label ret = dfsan_union(l1, l2, __dfsan::fstrcmp, n, (uint64_t)s1, (uint64_t)s2);
  if (ret) __taint_trace_memcmp(ret);
  return ret;
}

DECLARE_WEAK_INTERCEPTOR_HOOK(dfsan_weak_hook_strcmp, uptr caller_pc,
                              const char *s1, const char *s2,
                              dfsan_label s1_label, dfsan_label s2_label)

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_strcmp(const char *s1, const char *s2,
                                                dfsan_label s1_label,
                                                dfsan_label s2_label,
                                                dfsan_label *ret_label) {
  CALL_WEAK_INTERCEPTOR_HOOK(dfsan_weak_hook_strcmp, GET_CALLER_PC(), s1, s2,
                             s1_label, s2_label);
  int ret = strcmp(s1, s2);

  AOUT("strcmp: s1=%p s2=%p s1_label=%u s2_label=%u\n", s1, s2, s1_label, s2_label);

  // Use unified get_str_label to get labels for both strings
  // Handles str_map, pointer label fsubstr, and buffer content
  dfsan_label l1 = get_str_label(s1, s1_label);
  dfsan_label l2 = get_str_label(s2, s2_label);
  AOUT("strcmp: l1=%u l2=%u\n", l1, l2);

  if (l1 == 0 && l2 == 0) {
    *ret_label = 0;
  } else {
    // Determine length for comparison (use concrete side if one is fsubstr)
    size_t n = strlen(s1) + 1;
    dfsan_label s1_fsubstr = get_content_label(s1);
    if (s1_fsubstr != 0)
      n = strlen(s2) + 1;  // use concrete side for length

    // fstrcmp is commutative - dfsan_union will swap to put concrete in op1
    dfsan_label cmp = dfsan_union(l1, l2, __dfsan::fstrcmp, n,
                                   (uint64_t)s1, (uint64_t)s2);
    if (cmp) __taint_trace_memcmp(cmp);
    *ret_label = cmp;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_strcasecmp(const char *s1, const char *s2, dfsan_label s1_label,
                  dfsan_label s2_label, dfsan_label *ret_label) {
  int ret = strcasecmp(s1, s2);
  // doing an optimistic solving, hoping we can get the same case
  // Use unified get_str_label for fsubstr support
  dfsan_label l1 = get_str_label(s1, s1_label);
  dfsan_label l2 = get_str_label(s2, s2_label);

  if (l1 == 0 && l2 == 0) {
    *ret_label = 0;
  } else {
    size_t n = strlen(s1) + 1;
    dfsan_label s1_fsubstr = get_content_label(s1);
    if (s1_fsubstr != 0)
      n = strlen(s2) + 1;

    // fstrcmp is commutative - dfsan_union will swap to put concrete in op1
    dfsan_label cmp = dfsan_union(l1, l2, __dfsan::fstrcmp, n,
                                   (uint64_t)s1, (uint64_t)s2);
    if (cmp) __taint_trace_memcmp(cmp);
    *ret_label = cmp;
  }
  return ret;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_strncmp(const char *s1, const char *s2, size_t n) {
  if (n == 0) return 0;
  if (dfsan_get_label(s1) == 0 && strlen(s1) < (n - 1))
    n = strlen(s1) + 1;
  if (dfsan_get_label(s2) == 0 && strlen(s2) < (n - 1))
    n = strlen(s2) + 1;
  dfsan_label l1 = dfsan_read_label(s1, n);
  dfsan_label l2 = dfsan_read_label(s2, n);
  // Use string theory comparison (fstrcmp) for all strncmp
  dfsan_label ret = dfsan_union(l1, l2, __dfsan::fstrcmp, n, (uint64_t)s1, (uint64_t)s2);
  if (ret) __taint_trace_memcmp(ret);
  return ret;
}

DECLARE_WEAK_INTERCEPTOR_HOOK(dfsan_weak_hook_strncmp, uptr caller_pc,
                              const char *s1, const char *s2, size_t n,
                              dfsan_label s1_label, dfsan_label s2_label,
                              dfsan_label n_label)

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_strncmp(const char *s1, const char *s2,
                                                 size_t n, dfsan_label s1_label,
                                                 dfsan_label s2_label,
                                                 dfsan_label n_label,
                                                 dfsan_label *ret_label) {
  if (n == 0) {
    *ret_label = 0;
    return 0;
  }

  CALL_WEAK_INTERCEPTOR_HOOK(dfsan_weak_hook_strncmp, GET_CALLER_PC(), s1, s2,
                             n, s1_label, s2_label, n_label);

  int ret = strncmp(s1, s2, n);

  // Use unified get_str_label for fsubstr support
  dfsan_label l1 = get_str_label(s1, s1_label);
  dfsan_label l2 = get_str_label(s2, s2_label);

  if (l1 == 0 && l2 == 0) {
    *ret_label = 0;
  } else {
    // Adjust n for shorter strings when one side is concrete
    if (l1 == 0 && strlen(s1) < (n - 1))
      n = strlen(s1) + 1;
    if (l2 == 0 && strlen(s2) < (n - 1))
      n = strlen(s2) + 1;

    dfsan_label cmp = dfsan_union(l1, l2, __dfsan::fstrcmp, n,
                                   (uint64_t)s1, (uint64_t)s2);
    if (cmp) __taint_trace_memcmp(cmp);
    *ret_label = cmp;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_strncasecmp(const char *s1, const char *s2, size_t n,
                   dfsan_label s1_label, dfsan_label s2_label,
                   dfsan_label n_label, dfsan_label *ret_label) {
  if (n == 0) {
    *ret_label = 0;
    return 0;
  }

  int ret = strncasecmp(s1, s2, n);
  // doing an optimistic solving here too, hoping the case can be the same
  // Use unified get_str_label for fsubstr support
  dfsan_label l1 = get_str_label(s1, s1_label);
  dfsan_label l2 = get_str_label(s2, s2_label);

  if (l1 == 0 && l2 == 0) {
    *ret_label = 0;
  } else {
    // Adjust n for shorter strings when one side is concrete
    if (l1 == 0 && strlen(s1) < (n - 1))
      n = strlen(s1) + 1;
    if (l2 == 0 && strlen(s2) < (n - 1))
      n = strlen(s2) + 1;

    dfsan_label cmp = dfsan_union(l1, l2, __dfsan::fstrcmp, n,
                                   (uint64_t)s1, (uint64_t)s2);
    if (cmp) __taint_trace_memcmp(cmp);
    *ret_label = cmp;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE size_t
__dfsw_strlen(const char *s, dfsan_label s_label, dfsan_label *ret_label) {
  size_t ret = strlen(s);
  dfsan_label str_label = dfsan_read_label(s, ret + 1);

  if (str_label == 0) {
    *ret_label = 0;
  } else {
    // Check if the null terminator byte is from input (tainted)
    // If not, it was added programmatically (e.g., by the program setting '\0')
    dfsan_label null_label = dfsan_read_label(s + ret, 1);
    bool null_from_input = (null_label != 0);

    // Create fstrlen label:
    // - l1 = 0 (following fsize/fatoi pattern to avoid Alloca rejection)
    // - l2 = str_label (content label for dependencies)
    // - op1 = null_from_input flag (1 if null is from input, 0 if programmatic)
    // - op2 = actual length (for solution generation)
    // Note: str_label contains the offset info via Load labels
    *ret_label = dfsan_union(0, str_label, fstrlen,
                             sizeof(size_t) * 8,
                             null_from_input ? 1 : 0, ret);
  }
  return ret;
}

static void *dfsan_memcpy(void *dest, const void *src, size_t n) {
  if (n == 0) return dest;
  dfsan_label *sdest = shadow_for(dest);
  const dfsan_label *ssrc = shadow_for(src);
  // FIXME: check and avoid copying labels?
  internal_memcpy((void *)sdest, (const void *)ssrc, n * sizeof(dfsan_label));
  return internal_memcpy(dest, src, n);
}

static void dfsan_memset(void *s, int c, dfsan_label c_label, size_t n) {
  if (n == 0) return;
  internal_memset(s, c, n);
  dfsan_set_label(c_label, s, n);
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw_memcpy(void *dest, const void *src, size_t n,
                    dfsan_label dest_label, dfsan_label src_label,
                    dfsan_label n_label, dfsan_label *ret_label) {
  __taint_check_bounds(src_label, (uptr)src, n_label, n);
  __taint_check_bounds(dest_label, (uptr)dest, n_label, n);
  if (n_label) {
    __taint_solve_bounds(src_label, (uint64_t)src, n_label, n, 0, 1, 0, 0);
    __taint_solve_bounds(dest_label, (uint64_t)dest, n_label, n, 0, 1, 0, 0);
  }
  *ret_label = dest_label;
  return dfsan_memcpy(dest, src, n);
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw_memmove(void *dest, const void *src, size_t n,
                     dfsan_label dest_label, dfsan_label src_label,
                     dfsan_label n_label, dfsan_label *ret_label) {
  __taint_check_bounds(src_label, (uptr)src, n_label, n);
  __taint_check_bounds(dest_label, (uptr)dest, n_label, n);
  if (n_label) {
    __taint_solve_bounds(src_label, (uint64_t)src, n_label, n, 0, 1, 0, 0);
    __taint_solve_bounds(dest_label, (uint64_t)dest, n_label, n, 0, 1, 0, 0);
  }
  dfsan_label tmp[n];
  dfsan_label *sdest = shadow_for(dest);
  const dfsan_label *ssrc = shadow_for(src);
  internal_memcpy((void *)tmp, (const void *)ssrc, n * sizeof(dfsan_label));
  void *ret = internal_memmove(dest, src, n);
  internal_memcpy((void *)sdest, (const void *)tmp, n * sizeof(dfsan_label));
  *ret_label = dest_label;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw_memset(void *s, int c, size_t n,
                    dfsan_label s_label, dfsan_label c_label,
                    dfsan_label n_label, dfsan_label *ret_label) {
  __taint_check_bounds(s_label, (uptr)s, n_label, n);
  if (n_label)
    __taint_solve_bounds(s_label, (uint64_t)s, n_label, n, 0, 1, 0, 0);
  dfsan_memset(s, c, c_label, n);
  *ret_label = s_label;
  return s;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_tolower(int c, dfsan_label c_label, dfsan_label *ret_label) {
  int ret = tolower(c);
  *ret_label = dfsan_union(0, c_label, __dfsan::Or, 8, 0x20, 0);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_toupper(int c, dfsan_label c_label, dfsan_label *ret_label) {
  int ret = toupper(c);
  *ret_label = dfsan_union(0, c_label, __dfsan::And, 8, 0x5f, 0);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
char *__dfsw_strcat(char *dest, const char *src, dfsan_label d_label,
                    dfsan_label s_label, dfsan_label *ret_label) {
  size_t dest_len = strlen(dest);
  size_t copy_len = strlen(src) + 1; // including tailing '\0'
  __taint_check_bounds(d_label, (uptr)dest, 0, dest_len + copy_len);

  // Get labels for both strings using unified label retrieval
  dfsan_label dest_str_label = get_str_label(dest, d_label);
  dfsan_label src_str_label = get_str_label(src, s_label);

  AOUT("strcat: dest=%p, src=%p, dest_label=%u, src_label=%u, "
       "dest_str_label=%u, src_str_label=%u\n",
       dest, src, d_label, s_label, dest_str_label, src_str_label);

  // Perform the actual strcat (copy src to dest + dest_len)
  dfsan_memcpy(dest + dest_len, src, copy_len);

  // If either string is tainted, create fstrcat label
  if (dest_str_label != 0 || src_str_label != 0) {
    // Create fstrcat: l1=dest, l2=src
    // op1=dest pointer, op2=src pointer (for concrete content access)
    // size = length of concrete operand (for memcmp_cache), 0 if both symbolic
    size_t src_len = copy_len - 1;  // excluding null
    uint16_t concrete_len = 0;
    if (dest_str_label == 0) {
      concrete_len = (uint16_t)dest_len;
    } else if (src_str_label == 0) {
      concrete_len = (uint16_t)src_len;
    }
    dfsan_label concat_label = dfsan_union(dest_str_label, src_str_label,
                                            __dfsan::fstrcat,
                                            concrete_len,
                                            (uint64_t)dest,
                                            (uint64_t)src);
    AOUT("strcat: created fstrcat label=%u\n", concat_label);
    // Send concrete content through pipe if one side is concrete
    if (concrete_len > 0) {
      __taint_trace_memcmp(concat_label);
    }
    // Store in str_map so downstream ops can find it
    set_content_label(dest, concat_label);
  }

  *ret_label = d_label;
  return dest;
}

SANITIZER_INTERFACE_ATTRIBUTE char *
__dfsw_strncat(char *dest, const char *src, size_t n,
               dfsan_label d_label, dfsan_label s_label, dfsan_label n_label,
               dfsan_label *ret_label) {
  size_t dest_len = strlen(dest);
  size_t src_len = strlen(src);
  size_t copy_len = (n < src_len) ? n : src_len;  // min(n, strlen(src))
  __taint_check_bounds(d_label, (uptr)dest, 0, dest_len + copy_len + 1);

  AOUT("strncat: dest=%p, src=%p, n=%zu, d_label=%u, s_label=%u, n_label=%u\n",
       dest, src, n, d_label, s_label, n_label);

  // Get dest label using unified label retrieval
  dfsan_label dest_str_label = get_str_label(dest, d_label);

  // Get src label - use get_str_label_n to handle symbolic n
  // This will create fsubstr if n_label derives from a string op (e.g., strchr)
  dfsan_label src_str_label = get_str_label_n(src, s_label, copy_len, n_label);

  AOUT("strncat: dest_str_label=%u, src_str_label=%u, copy_len=%zu\n",
       dest_str_label, src_str_label, copy_len);

  // Perform the actual strncat
  dfsan_memcpy(dest + dest_len, src, copy_len);
  dest[dest_len + copy_len] = '\0';

  // If either string is tainted, create fstrcat label
  if (dest_str_label != 0 || src_str_label != 0) {
    // Create fstrcat: l1=dest, l2=src
    // op1=dest pointer, op2=src pointer (for concrete content access)
    // size = length of concrete operand (for memcmp_cache), 0 if both symbolic
    uint16_t concrete_len = 0;
    if (dest_str_label == 0) {
      concrete_len = (uint16_t)dest_len;
    } else if (src_str_label == 0) {
      concrete_len = (uint16_t)copy_len;
    }
    dfsan_label concat_label = dfsan_union(dest_str_label, src_str_label,
                                            __dfsan::fstrcat,
                                            concrete_len,
                                            (uint64_t)dest,
                                            (uint64_t)src);
    AOUT("strncat: created fstrcat label=%u\n", concat_label);
    // Send concrete content through pipe if one side is concrete
    if (concrete_len > 0) {
      __taint_trace_memcmp(concat_label);
    }
    // Store in content map so downstream ops can find it
    set_content_label(dest, concat_label);
  }

  *ret_label = d_label;
  return dest;
}

SANITIZER_INTERFACE_ATTRIBUTE char *
__dfsw_strdup(const char *s, dfsan_label s_label, dfsan_label *ret_label) {
  size_t len = strlen(s);
  void *p = malloc(len+1);
  dfsan_memcpy(p, s, len+1);

  // Propagate string label to duplicated string
  dfsan_label str_label = get_str_label(s, s_label);
  if (str_label != 0) {
    set_content_label(static_cast<char *>(p), str_label);
  }

  *ret_label = 0;
  return static_cast<char *>(p);
}

SANITIZER_INTERFACE_ATTRIBUTE char *
__dfsw___strdup(const char *s, dfsan_label s_label, dfsan_label *ret_label) {
  size_t len = strlen(s);
  void *p = malloc(len+1);
  dfsan_memcpy(p, s, len+1);

  // Propagate string label to duplicated string
  dfsan_label str_label = get_str_label(s, s_label);
  if (str_label != 0) {
    set_content_label(static_cast<char *>(p), str_label);
  }

  *ret_label = 0;
  return static_cast<char *>(p);
}

SANITIZER_INTERFACE_ATTRIBUTE char *
__dfsw___strndup(const char *s, size_t n, dfsan_label s_label,
                 dfsan_label n_label, dfsan_label *ret_label) {
  size_t len = strlen(s);
  len = len > n ? n : len;
  char *p = static_cast<char *>(malloc(len+1));
  if (p == nullptr) {
    *ret_label = 0;
    return nullptr;
  }
  dfsan_memcpy(p, s, len); // copy at most n bytes
  p[len] = '\0';
  dfsan_set_label(0, p + len, 1);
  *ret_label = 0;
  return p;
}

SANITIZER_INTERFACE_ATTRIBUTE char *
__dfsw_strncpy(char *s1, const char *s2, size_t n, dfsan_label s1_label,
               dfsan_label s2_label, dfsan_label n_label,
               dfsan_label *ret_label) {
  size_t len = strlen(s2);
  size_t copy_len = len < n ? len : n;

  if (n_label)
    __taint_solve_bounds(s1_label, (uint64_t)s1, n_label, n, 0, 1, 0, 0);

  // Check if n_label derives from a string op (e.g., strchr index)
  dfsan_label str_op_label = n_label ? find_string_op_source(n_label) : 0;
  bool created_fsubstr = false;

  if (str_op_label != 0) {
    // Get the content label from the string op
    dfsan_label_info *str_op_info = dfsan_get_label_info(str_op_label);
    dfsan_label str_op_content = str_op_info->l1;  // content from strchr

    // Verify buffers match: str_op searched the same buffer we're copying
    // When copy_len = 0, we can't read from s2, so trust str_op_content
    bool buffers_match = false;
    if (str_op_content >= CONST_OFFSET) {
      if (copy_len > 0) {
        dfsan_label src_content = dfsan_read_label(s2, copy_len);
        if (src_content >= CONST_OFFSET) {
          dfsan_label src_base = get_base_input_label(src_content);
          dfsan_label str_op_base = get_base_input_label(str_op_content);
          buffers_match = (src_base != 0 && src_base == str_op_base);
        }
      } else {
        // copy_len = 0: trust the str_op_content (empty substring case)
        buffers_match = true;
      }
    }

    if (buffers_match) {
      // Create fsubstr: represents substr(src, 0, len) where len is symbolic
      // Use str_op_content (full haystack) for proper string theory solving
      dfsan_label substr_label = dfsan_union(str_op_content, str_op_label,
                                              __dfsan::fsubstr,
                                              sizeof(void*) * 8,
                                              (uint64_t)n, 0);

      // Store fsubstr label in runtime map keyed by destination address
      // This survives buffer content being overwritten (e.g., key[len] = '\0')
      set_content_label(s1, substr_label);

      *ret_label = s1_label;
    }
  }

  // Normal case: copy byte-by-byte labels
  if (len < n) {
    dfsan_memcpy(s1, s2, len + 1);
  } else {
    dfsan_memcpy(s1, s2, n);
  }

  // Handle padding (strncpy pads with zeros if len < n)
  if (len < n) {
    dfsan_memset(s1 + len + 1, 0, 0, n - len - 1);
  }

  *ret_label = s1_label;
  return s1;
}

SANITIZER_INTERFACE_ATTRIBUTE ssize_t
__dfsw_pread(int fd, void *buf, size_t count, off_t offset,
             dfsan_label fd_label, dfsan_label buf_label,
             dfsan_label count_label, dfsan_label offset_label,
             dfsan_label *ret_label) {
  __taint_check_bounds(buf_label, (uptr)buf, count_label, count);
  if (count_label)
    __taint_solve_bounds(buf_label, (uint64_t)buf, count_label, count, 0, 1, 0, 0);
  ssize_t ret = pread(fd, buf, count, offset);
  *ret_label = 0;
  if (ret >= 0) {
    if (taint_get_file(fd)) {
      for (ssize_t i = 0; i < ret; i++) {
        dfsan_set_label(get_label_for(fd, offset + i), (char *)buf + i, 1);
      }
      // *ret_label = dfsan_union(0, 0, fsize, sizeof(ret) * 8, offset, 0);
    } else {
      dfsan_set_label(0, buf, ret);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE ssize_t
__dfsw_pread64(int fd, void *buf, size_t count, off_t offset,
               dfsan_label fd_label, dfsan_label buf_label,
               dfsan_label count_label, dfsan_label offset_label,
               dfsan_label *ret_label) {
  __taint_check_bounds(buf_label, (uptr)buf, count_label, count);
  if (count_label)
    __taint_solve_bounds(buf_label, (uint64_t)buf, count_label, count, 0, 1, 0, 0);
  ssize_t ret = pread64(fd, buf, count, offset);
  *ret_label = 0;
  if (ret >= 0) {
    if (taint_get_file(fd)) {
      for (ssize_t i = 0; i < ret; i++) {
        dfsan_set_label(get_label_for(fd, offset + i), (char *)buf + i, 1);
      }
      // *ret_label = dfsan_union(0, 0, fsize, sizeof(ret) * 8, offset, 0);
    } else {
      dfsan_set_label(0, buf, ret);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE ssize_t
__dfsw_read(int fd, void *buf, size_t count,
             dfsan_label fd_label, dfsan_label buf_label,
             dfsan_label count_label,
             dfsan_label *ret_label) {
  off_t offset = lseek(fd, 0, SEEK_CUR);
  __taint_check_bounds(buf_label, (uptr)buf, count_label, count);
  if (count_label)
    __taint_solve_bounds(buf_label, (uint64_t)buf, count_label, count, 0, 1, 0, 0);
  ssize_t ret = read(fd, buf, count);
  *ret_label = 0;
  if (ret >= 0) {
    if (taint_get_file(fd)) {
      AOUT("offset = %ld, ret = %ld\n", offset, ret);
      for(ssize_t i = 0; i < ret; i++) {
        dfsan_set_label(get_label_for(fd, offset + i), (char *)buf + i, 1);
      }
      // for (size_t i = ret; i < count; i++)
      //   dfsan_set_label(-1, (char *)buf + i, 1);
      // *ret_label = dfsan_union(0, 0, fsize, sizeof(ret) * 8, offset, 0);
    } else {
      dfsan_set_label(0, buf, ret);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_clock_gettime(clockid_t clk_id,
                                                       struct timespec *tp,
                                                       dfsan_label clk_id_label,
                                                       dfsan_label tp_label,
                                                       dfsan_label *ret_label) {
  int ret = clock_gettime(clk_id, tp);
  if (ret == 0)
    dfsan_set_label(0, tp, sizeof(struct timespec));
  *ret_label = 0;
  return ret;
}

static void dfsan_set_zero_label(const void *ptr, uptr size) {
  dfsan_set_label(0, const_cast<void *>(ptr), size);
}

// dlopen() ultimately calls mmap() down inside the loader, which generally
// doesn't participate in dynamic symbol resolution.  Therefore we won't
// intercept its calls to mmap, and we have to hook it here.
SANITIZER_INTERFACE_ATTRIBUTE void *
__dfsw_dlopen(const char *filename, int flag, dfsan_label filename_label,
              dfsan_label flag_label, dfsan_label *ret_label) {
  void *handle = dlopen(filename, flag);
  link_map *map = GET_LINK_MAP_BY_DLOPEN_HANDLE(handle);
  if (map && map->l_addr)
    ForEachMappedRegion(map, dfsan_set_zero_label);
  *ret_label = 0;
  return handle;
}

struct pthread_create_info {
  void *(*start_routine_trampoline)(void *, void *, dfsan_label, dfsan_label *);
  void *start_routine;
  void *arg;
};

static void *pthread_create_cb(void *p) {
  pthread_create_info pci(*(pthread_create_info *)p);
  free(p);
  dfsan_label ret_label;
  return pci.start_routine_trampoline(pci.start_routine, pci.arg, 0,
                                      &ret_label);
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_pthread_create(
    pthread_t *thread, const pthread_attr_t *attr,
    void *(*start_routine_trampoline)(void *, void *, dfsan_label,
                                      dfsan_label *),
    void *start_routine, void *arg, dfsan_label thread_label,
    dfsan_label attr_label, dfsan_label start_routine_label,
    dfsan_label arg_label, dfsan_label *ret_label) {
  pthread_create_info *pci =
      (pthread_create_info *)malloc(sizeof(pthread_create_info));
  pci->start_routine_trampoline = start_routine_trampoline;
  pci->start_routine = start_routine;
  pci->arg = arg;
  int rv = pthread_create(thread, attr, pthread_create_cb, (void *)pci);
  if (rv != 0)
    free(pci);
  *ret_label = 0;
  return rv;
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_pthread_join(pthread_t thread,
                                                      void **retval,
                                                      dfsan_label thread_label,
                                                      dfsan_label retval_label,
                                                      dfsan_label *ret_label) {
  int ret = pthread_join(thread, retval);
  if (ret == 0 && retval)
    dfsan_set_label(0, retval, sizeof(*retval));
  *ret_label = 0;
  return ret;
}

struct dl_iterate_phdr_info {
  int (*callback_trampoline)(void *callback, struct dl_phdr_info *info,
                             size_t size, void *data, dfsan_label info_label,
                             dfsan_label size_label, dfsan_label data_label,
                             dfsan_label *ret_label);
  void *callback;
  void *data;
};

int dl_iterate_phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
  dl_iterate_phdr_info *dipi = (dl_iterate_phdr_info *)data;
  dfsan_set_label(0, *info);
  dfsan_set_label(0, const_cast<char *>(info->dlpi_name),
                  strlen(info->dlpi_name) + 1);
  dfsan_set_label(
      0, const_cast<char *>(reinterpret_cast<const char *>(info->dlpi_phdr)),
      sizeof(*info->dlpi_phdr) * info->dlpi_phnum);
  dfsan_label ret_label;
  return dipi->callback_trampoline(dipi->callback, info, size, dipi->data, 0, 0,
                                   0, &ret_label);
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_dl_iterate_phdr(
    int (*callback_trampoline)(void *callback, struct dl_phdr_info *info,
                               size_t size, void *data, dfsan_label info_label,
                               dfsan_label size_label, dfsan_label data_label,
                               dfsan_label *ret_label),
    void *callback, void *data, dfsan_label callback_label,
    dfsan_label data_label, dfsan_label *ret_label) {
  dl_iterate_phdr_info dipi = { callback_trampoline, callback, data };
  *ret_label = 0;
  return dl_iterate_phdr(dl_iterate_phdr_cb, &dipi);
}

#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 27
// This function is only available for glibc 2.27 or newer.  Mark it weak so
// linking succeeds with older glibcs.
SANITIZER_WEAK_ATTRIBUTE void _dl_get_tls_static_info(size_t *sizep,
                                                      size_t *alignp);

SANITIZER_INTERFACE_ATTRIBUTE void __dfsw__dl_get_tls_static_info(
    size_t *sizep, size_t *alignp, dfsan_label sizep_label,
    dfsan_label alignp_label) {
  assert(_dl_get_tls_static_info);
  _dl_get_tls_static_info(sizep, alignp);
  dfsan_set_label(0, sizep, sizeof(*sizep));
  dfsan_set_label(0, alignp, sizeof(*alignp));
}
#endif

SANITIZER_INTERFACE_ATTRIBUTE
char *__dfsw_ctime_r(const time_t *timep, char *buf, dfsan_label timep_label,
                     dfsan_label buf_label, dfsan_label *ret_label) {
  char *ret = ctime_r(timep, buf);
  if (ret) {
    dfsan_set_label(dfsan_read_label(timep, sizeof(time_t)), buf,
                    strlen(buf) + 1);
    *ret_label = buf_label;
  } else {
    *ret_label = 0;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
char *__dfsw_getcwd(char *buf, size_t size, dfsan_label buf_label,
                    dfsan_label size_label, dfsan_label *ret_label) {
  char *ret = getcwd(buf, size);
  if (ret) {
    dfsan_set_label(0, ret, strlen(ret) + 1);
    *ret_label = buf_label;
  } else {
    *ret_label = 0;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
char *__dfsw_get_current_dir_name(dfsan_label *ret_label) {
  char *ret = get_current_dir_name();
  if (ret) {
    dfsan_set_label(0, ret, strlen(ret) + 1);
  }
  *ret_label = 0;
  return ret;
}

#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
// This function is only available for glibc 2.25 or newer.  Mark it weak so
// linking succeeds with older glibcs.
SANITIZER_WEAK_ATTRIBUTE int getentropy(void *buffer, size_t length);

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_getentropy(void *buffer, size_t length,
                                                    dfsan_label buffer_label,
                                                    dfsan_label length_label,
                                                    dfsan_label *ret_label) {
  int ret = getentropy(buffer, length);
  if (ret == 0) {
    dfsan_set_label(0, buffer, length);
  }
  *ret_label = 0;
  return ret;
}
#endif

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_gethostname(char *name, size_t len, dfsan_label name_label,
                       dfsan_label len_label, dfsan_label *ret_label) {
  int ret = gethostname(name, len);
  if (ret == 0) {
    dfsan_set_label(0, name, strlen(name) + 1);
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_getpeername(
    int sockfd, struct sockaddr *addr, socklen_t *addrlen,
    dfsan_label sockfd_label, dfsan_label addr_label, dfsan_label addrlen_label,
    dfsan_label *ret_label) {
  socklen_t origlen = addrlen ? *addrlen : 0;
  int ret = getpeername(sockfd, addr, addrlen);
  if (ret != -1 && addr && addrlen) {
    socklen_t written_bytes = origlen < *addrlen ? origlen : *addrlen;
    dfsan_set_label(0, addrlen, sizeof(*addrlen));
    dfsan_set_label(0, addr, written_bytes);
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_getrlimit(int resource, struct rlimit *rlim,
                     dfsan_label resource_label, dfsan_label rlim_label,
                     dfsan_label *ret_label) {
  int ret = getrlimit(resource, rlim);
  if (ret == 0) {
    dfsan_set_label(0, rlim, sizeof(struct rlimit));
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_getrusage(int who, struct rusage *usage, dfsan_label who_label,
                     dfsan_label usage_label, dfsan_label *ret_label) {
  int ret = getrusage(who, usage);
  if (ret == 0) {
    dfsan_set_label(0, usage, sizeof(struct rusage));
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_getsockname(
    int sockfd, struct sockaddr *addr, socklen_t *addrlen,
    dfsan_label sockfd_label, dfsan_label addr_label, dfsan_label addrlen_label,
    dfsan_label *ret_label) {
  socklen_t origlen = addrlen ? *addrlen : 0;
  int ret = getsockname(sockfd, addr, addrlen);
  if (ret != -1 && addr && addrlen) {
    socklen_t written_bytes = origlen < *addrlen ? origlen : *addrlen;
    dfsan_set_label(0, addrlen, sizeof(*addrlen));
    dfsan_set_label(0, addr, written_bytes);
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_getsockopt(
    int sockfd, int level, int optname, void *optval, socklen_t *optlen,
    dfsan_label sockfd_label, dfsan_label level_label,
    dfsan_label optname_label, dfsan_label optval_label,
    dfsan_label optlen_label, dfsan_label *ret_label) {
  int ret = getsockopt(sockfd, level, optname, optval, optlen);
  if (ret != -1 && optval && optlen) {
    dfsan_set_label(0, optlen, sizeof(*optlen));
    dfsan_set_label(0, optval, *optlen);
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_nanosleep(const struct timespec *req,
                                                   struct timespec *rem,
                                                   dfsan_label req_label,
                                                   dfsan_label rem_label,
                                                   dfsan_label *ret_label) {
  int ret = nanosleep(req, rem);
  *ret_label = 0;
  if (ret == -1) {
    // Interrupted by a signal, rem is filled with the remaining time.
    dfsan_set_label(0, rem, sizeof(struct timespec));
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
char *__dfsw_stpcpy(char *dest, const char *src, dfsan_label dest_label,
                    dfsan_label src_label, dfsan_label *ret_label) {
  size_t len = strlen(src) + 1;
  __taint_check_bounds(dest_label, (uptr)dest, 0, len);
  char *ret = stpcpy(dest, src);
  if (ret) {
    internal_memcpy(shadow_for(dest), shadow_for(src), sizeof(dfsan_label) * len);
  }
  *ret_label = dest_label;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
char *__dfsw_strcpy(char *dest, const char *src, dfsan_label dst_label,
                    dfsan_label src_label, dfsan_label *ret_label) {
  size_t len = strlen(src) + 1;
  __taint_check_bounds(dst_label, (uptr)dest, 0, len);
  char *ret = strcpy(dest, src);
  *ret_label = dst_label;

  // Use get_str_label to properly get the source label
  // This handles str_map, pointer label string ops, and buffer content
  dfsan_label real_src_label = get_str_label(src, src_label);
  AOUT("strcpy: src='%p', src_label=%d, real_src_label=%d\n", src, src_label, real_src_label);

  if (real_src_label != 0) {
    // Store the label in runtime map keyed by destination address
    set_content_label(dest, real_src_label);
    *ret_label = real_src_label;
  }

  if (ret) {
    internal_memcpy(shadow_for(dest), shadow_for(src),
                    sizeof(dfsan_label) * len);
  }
  return ret;
}

static dfsan_label taint_strtol(const char *nptr, uptr len, size_t ret_size, int base) {
  dfsan_label load = 0;
  if (len > 0) {
    load = dfsan_read_label(nptr, len);
  } else {
    // well, no byte get consumed, handle specially
    dfsan_label l = shadow_for(nptr)[0];
    if (l == 0) // constant
      return 0;
    load = dfsan_union(l, 0, Load, 0, 0, 0);
  }
  return dfsan_union(0, load, fatoi, sizeof(ret_size) * 8, base, len);
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_atoi(const char *nptr, dfsan_label nptr_label, dfsan_label *ret_label) {
  char *tmp_endptr;
  int ret = (int)strtol(nptr, &tmp_endptr, 10);
  uptr len = (uptr)tmp_endptr - (uptr)nptr;
  *ret_label = taint_strtol(nptr, len, sizeof(ret), 10);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
long __dfsw_atol(const char *nptr, dfsan_label nptr_label, dfsan_label *ret_label) {
  char *tmp_endptr;
  long ret = strtol(nptr, &tmp_endptr, 10);
  uptr len = (uptr)tmp_endptr - (uptr)nptr;
  *ret_label = taint_strtol(nptr, len, sizeof(ret), 10);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
long long __dfsw_atoll(const char *nptr, dfsan_label nptr_label, dfsan_label *ret_label) {
  char *tmp_endptr;
  long long ret = strtoll(nptr, &tmp_endptr, 10);
  uptr len = (uptr)tmp_endptr - (uptr)nptr;
  *ret_label = taint_strtol(nptr, len, sizeof(ret), 10);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
long __dfsw_strtol(const char *nptr, char **endptr, int base,
                   dfsan_label nptr_label, dfsan_label endptr_label,
                   dfsan_label base_label, dfsan_label *ret_label) {
  char *tmp_endptr;
  long ret = strtol(nptr, &tmp_endptr, base);
  if (endptr) {
    *endptr = tmp_endptr;
  }
  uptr len = (uptr)tmp_endptr - (uptr)nptr;
  *ret_label = taint_strtol(nptr, len, sizeof(ret), base);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
double __dfsw_strtod(const char *nptr, char **endptr,
                     dfsan_label nptr_label, dfsan_label endptr_label,
                     dfsan_label *ret_label) {
  char *tmp_endptr;
  double ret = strtod(nptr, &tmp_endptr);
  if (endptr) {
    *endptr = tmp_endptr;
  }
  *ret_label = 0; // TODO: implement
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
long long __dfsw_strtoll(const char *nptr, char **endptr, int base,
                         dfsan_label nptr_label, dfsan_label endptr_label,
                         dfsan_label base_label, dfsan_label *ret_label) {
  char *tmp_endptr;
  long long ret = strtoll(nptr, &tmp_endptr, base);
  if (endptr) {
    *endptr = tmp_endptr;
  }
  AOUT("strtoll: %s\n", nptr);
  uptr len = (uptr)tmp_endptr - (uptr)nptr;
  *ret_label = taint_strtol(nptr, len, sizeof(ret), base);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
unsigned long __dfsw_strtoul(const char *nptr, char **endptr, int base,
                             dfsan_label nptr_label, dfsan_label endptr_label,
                             dfsan_label base_label, dfsan_label *ret_label) {
  char *tmp_endptr;
  unsigned long ret = strtoul(nptr, &tmp_endptr, base);
  if (endptr) {
    *endptr = tmp_endptr;
  }
  uptr len = (uptr)tmp_endptr - (uptr)nptr;
  *ret_label = taint_strtol(nptr, len, sizeof(ret), base);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
unsigned long long __dfsw_strtoull(const char *nptr, char **endptr,
                                   dfsan_label nptr_label,
                                   int base, dfsan_label endptr_label,
                                   dfsan_label base_label,
                                   dfsan_label *ret_label) {
  char *tmp_endptr;
  unsigned long long ret = strtoull(nptr, &tmp_endptr, base);
  if (endptr) {
    *endptr = tmp_endptr;
  }
  uptr len = (uptr)tmp_endptr - (uptr)nptr;
  *ret_label = taint_strtol(nptr, len, sizeof(ret), base);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
time_t __dfsw_time(time_t *t, dfsan_label t_label, dfsan_label *ret_label) {
  time_t ret = time(t);
  if (ret != (time_t) -1 && t) {
    dfsan_set_label(0, t, sizeof(time_t));
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_inet_pton(int af, const char *src, void *dst, dfsan_label af_label,
                     dfsan_label src_label, dfsan_label dst_label,
                     dfsan_label *ret_label) {
  int ret = inet_pton(af, src, dst);
  if (ret == 1) {
    dfsan_set_label(dfsan_read_label(src, strlen(src) + 1), dst,
                    af == AF_INET ? sizeof(struct in_addr) : sizeof(in6_addr));
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
struct tm *__dfsw_localtime_r(const time_t *timep, struct tm *result,
                              dfsan_label timep_label, dfsan_label result_label,
                              dfsan_label *ret_label) {
  struct tm *ret = localtime_r(timep, result);
  if (ret) {
    dfsan_set_label(dfsan_read_label(timep, sizeof(time_t)), result,
                    sizeof(struct tm));
    *ret_label = result_label;
  } else {
    *ret_label = 0;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_getpwuid_r(id_t uid, struct passwd *pwd,
                      char *buf, size_t buflen, struct passwd **result,
                      dfsan_label uid_label, dfsan_label pwd_label,
                      dfsan_label buf_label, dfsan_label buflen_label,
                      dfsan_label result_label, dfsan_label *ret_label) {
  // Store the data in pwd, the strings referenced from pwd in buf, and the
  // address of pwd in *result.  On failure, NULL is stored in *result.
  int ret = getpwuid_r(uid, pwd, buf, buflen, result);
  if (ret == 0) {
    dfsan_set_label(0, pwd, sizeof(struct passwd));
    dfsan_set_label(0, buf, strlen(buf) + 1);
  }
  *ret_label = 0;
  dfsan_set_label(0, result, sizeof(struct passwd*));
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                      int timeout, dfsan_label epfd_label,
                      dfsan_label events_label, dfsan_label maxevents_label,
                      dfsan_label timeout_label, dfsan_label *ret_label) {
  int ret = epoll_wait(epfd, events, maxevents, timeout);
  if (ret > 0)
    dfsan_set_label(0, events, ret * sizeof(*events));
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_poll(struct pollfd *fds, nfds_t nfds, int timeout,
                dfsan_label dfs_label, dfsan_label nfds_label,
                dfsan_label timeout_label, dfsan_label *ret_label) {
  int ret = poll(fds, nfds, timeout);
  if (ret >= 0) {
    for (; nfds > 0; --nfds) {
      dfsan_set_label(0, &fds[nfds - 1].revents, sizeof(fds[nfds - 1].revents));
    }
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout,
                  dfsan_label nfds_label, dfsan_label readfds_label,
                  dfsan_label writefds_label, dfsan_label exceptfds_label,
                  dfsan_label timeout_label, dfsan_label *ret_label) {
  int ret = select(nfds, readfds, writefds, exceptfds, timeout);
  // Clear everything (also on error) since their content is either set or
  // undefined.
  if (readfds) {
    dfsan_set_label(0, readfds, sizeof(fd_set));
  }
  if (writefds) {
    dfsan_set_label(0, writefds, sizeof(fd_set));
  }
  if (exceptfds) {
    dfsan_set_label(0, exceptfds, sizeof(fd_set));
  }
  if (timeout) {
    dfsan_set_label(0, timeout, sizeof(struct timeval));
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask,
                             dfsan_label pid_label,
                             dfsan_label cpusetsize_label,
                             dfsan_label mask_label, dfsan_label *ret_label) {
  int ret = sched_getaffinity(pid, cpusetsize, mask);
  if (ret == 0) {
    dfsan_set_label(0, mask, cpusetsize);
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_sigemptyset(sigset_t *set, dfsan_label set_label,
                       dfsan_label *ret_label) {
  int ret = sigemptyset(set);
  dfsan_set_label(0, set, sizeof(sigset_t));
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_sigaction(int signum, const struct sigaction *act,
                     struct sigaction *oldact, dfsan_label signum_label,
                     dfsan_label act_label, dfsan_label oldact_label,
                     dfsan_label *ret_label) {
  int ret = sigaction(signum, act, oldact);
  if (oldact) {
    dfsan_set_label(0, oldact, sizeof(struct sigaction));
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_sigaltstack(const stack_t *ss, stack_t *old_ss, dfsan_label ss_label,
                       dfsan_label old_ss_label, dfsan_label *ret_label) {
  int ret = sigaltstack(ss, old_ss);
  if (ret != -1 && old_ss)
    dfsan_set_label(0, old_ss, sizeof(*old_ss));
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_gettimeofday(struct timeval *tv, struct timezone *tz,
                        dfsan_label tv_label, dfsan_label tz_label,
                        dfsan_label *ret_label) {
  int ret = gettimeofday(tv, tz);
  if (tv) {
    dfsan_set_label(0, tv, sizeof(struct timeval));
  }
  if (tz) {
    dfsan_set_label(0, tz, sizeof(struct timezone));
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE void *__dfsw_memchr(void *s, int c, size_t n,
                                                  dfsan_label s_label,
                                                  dfsan_label c_label,
                                                  dfsan_label n_label,
                                                  dfsan_label *ret_label) {
  void *ret = memchr(s, c, n);

  // Use unified get_str_label_n for source label
  // Pass n_label to handle fsubstr creation when n derives from a string op
  dfsan_label src_label = get_str_label_n(s, s_label, n, n_label);

  if (src_label != 0 || c_label != 0) {
    int64_t found_pos = ret ? ((char*)ret - (char*)s) : -1;
    // Same structure as strchr
    *ret_label = dfsan_union(src_label, c_label, __dfsan::fstrchr,
                             sizeof(void*) * 8,
                             (uint64_t)found_pos, (uint64_t)(uint8_t)c);
    // Store the result pointer to recover symbolic length
    if (ret) {
      set_indexof_label(ret, *ret_label);
    }
  } else {
    *ret_label = 0;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE char *__dfsw_strrchr(char *s, int c,
                                                   dfsan_label s_label,
                                                   dfsan_label c_label,
                                                   dfsan_label *ret_label) {
  char *ret = strrchr(s, c);

  // Use unified get_str_label for source label
  dfsan_label src_label = get_str_label(s, s_label);

  if (src_label != 0 || c_label != 0) {
    // Determine which operand is concrete and set size accordingly
    size_t haystack_len = strlen(s);
    uint16_t content_len = (src_label == 0) ? (uint16_t)haystack_len : 0;

    // l1 = src_label (source - for chaining or content dependencies)
    // l2 = c_label (target char - may be symbolic!)
    // op1 = haystack pointer (for concrete content retrieval)
    // op2 = char value
    // size = haystack length if concrete, else 0
    *ret_label = dfsan_union(src_label, c_label, __dfsan::fstrrchr,
                             content_len,
                             (uint64_t)s,
                             (uint64_t)(uint8_t)c);

    // Send concrete haystack content if haystack is concrete
    if (content_len > 0 && *ret_label) {
      __taint_trace_memcmp(*ret_label);
    }

    // Store the result pointer to recover symbolic length
    if (ret) {
      set_indexof_label(ret, *ret_label);
    }
  } else {
    *ret_label = 0;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE void *__dfsw_memrchr(const void *s, int c, size_t n,
                                                   dfsan_label s_label,
                                                   dfsan_label c_label,
                                                   dfsan_label n_label,
                                                   dfsan_label *ret_label) {
  void *ret = const_cast<void*>(memrchr(s, c, n));

  // Use unified get_str_label_n for source label
  // Pass n_label to handle fsubstr creation when n derives from a string op
  dfsan_label src_label = get_str_label_n(s, s_label, n, n_label);

  if (src_label != 0 || c_label != 0) {
    int64_t found_pos = ret ? ((const char*)ret - (const char*)s) : -1;
    // Use fstrrchr for reverse search
    *ret_label = dfsan_union(src_label, c_label, __dfsan::fstrrchr,
                             sizeof(void*) * 8,
                             (uint64_t)found_pos, (uint64_t)(uint8_t)c);
    // Store the result pointer to recover symbolic length
    if (ret) {
      set_indexof_label(ret, *ret_label);
    }
  } else {
    *ret_label = 0;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE char *__dfsw_strstr(char *haystack, char *needle,
                                                  dfsan_label haystack_label,
                                                  dfsan_label needle_label,
                                                  dfsan_label *ret_label) {
  char *ret = strstr(haystack, needle);

  // Use unified get_str_label for haystack and needle
  dfsan_label src_label = get_str_label(haystack, haystack_label);
  dfsan_label real_needle_label = get_str_label(needle, needle_label);

  if (src_label != 0 || real_needle_label != 0) {
    // Determine which operand is concrete and set size accordingly
    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);
    uint16_t content_len = 0;
    if (src_label == 0) {
      content_len = (uint16_t)haystack_len;
    } else if (real_needle_label == 0) {
      content_len = (uint16_t)needle_len;
    }

    // l1 = src_label (source - for chaining or content dependencies)
    // l2 = real_needle_label (may be symbolic string!)
    // op1 = haystack pointer (for concrete content retrieval)
    // op2 = needle pointer (for concrete content retrieval)
    // size = haystack length if haystack concrete, else needle length if needle concrete, else 0
    dfsan_label label = dfsan_union(src_label, real_needle_label, __dfsan::fstrstr,
                                    content_len,
                                    (uint64_t)haystack,
                                    (uint64_t)needle);

    // Send concrete content (haystack or needle)
    if (content_len > 0 && label) {
      __taint_trace_memcmp(label);
    }

    *ret_label = label;
    // Store the result pointer to recover symbolic length
    if (ret) {
      set_indexof_label(ret, *ret_label);
    }
  } else {
    *ret_label = 0;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE void *__dfsw_memmem(const void *haystack, size_t haystacklen,
                                                   const void *needle, size_t needlelen,
                                                   dfsan_label haystack_label,
                                                   dfsan_label haystacklen_label,
                                                   dfsan_label needle_label,
                                                   dfsan_label needlelen_label,
                                                   dfsan_label *ret_label) {
  void *ret = memmem(haystack, haystacklen, needle, needlelen);

  // Use unified get_str_label_n for haystack and needle
  // Pass haystacklen_label to handle fsubstr creation when haystacklen derives from a string op
  dfsan_label src_label =
      get_str_label_n(haystack, haystack_label, haystacklen, haystacklen_label);

  // Use unified get_str_label_n for needle
  dfsan_label real_needle_label =
      get_str_label_n(needle, needle_label, needlelen, needlelen_label);

  if (src_label != 0 || real_needle_label != 0) {
    int64_t found_pos = ret ? ((const char*)ret - (const char*)haystack) : -1;

    // l1 = src_label (source - for chaining or content dependencies)
    // l2 = real_needle_label (may be symbolic!)
    // op1 = needle pointer (for caching if concrete)
    // op2 = found position
    // size = needle length
    dfsan_label label = dfsan_union(src_label, real_needle_label, __dfsan::fstrstr,
                                    needlelen,
                                    (uint64_t)found_pos, (uint64_t)needle);

    // Cache needle content only if needle is concrete
    if (real_needle_label == 0 && label) {
      __taint_trace_memcmp(label);
    }
    *ret_label = label;
    // Store the result pointer to recover symbolic length
    if (ret) {
      set_indexof_label(ret, *ret_label);
    }
  } else {
    *ret_label = 0;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_connect(
    int sockfd, const struct sockaddr *addr, socklen_t addrlen,
    dfsan_label sockfd_label, dfsan_label addr_label, dfsan_label addrlen_label,
    dfsan_label *ret_label) {
  int ret = connect(sockfd, addr, addrlen);
  if (ret == 0 || errno == EINPROGRESS || errno == EALREADY) {
    taint_set_socket(addr, addrlen, sockfd);
  }
  *ret_label = 0;
  return ret;
}


SANITIZER_INTERFACE_ATTRIBUTE ssize_t __dfsw_recv(
    int sockfd, void *buf, size_t leng, int flags, dfsan_label sockfd_label,
    dfsan_label buf_label, dfsan_label leng_label, dfsan_label flags_label,
    dfsan_label *ret_label) {
  __taint_check_bounds(buf_label, (uptr)buf, leng_label, leng);
  if (leng_label)
    __taint_solve_bounds(buf_label, (uint64_t)buf, leng_label, leng, 0, 1, 0, 0);
  internal_memset(buf, 0, leng);
  ssize_t ret = recv(sockfd, buf, leng, flags);
#if AIXCC_HACK
  ssize_t readed = strlen((char *)buf);
  if (ret == 0 && readed > 0) ret = readed; // we actually readed something
#endif
  if (ret > 0) {
    off_t offset = taint_get_socket(sockfd);
    if (offset >= 0) {
      AOUT("recv: fd = %d, offset = %ld, ret = %ld\n", sockfd, offset, ret);
      for (ssize_t i = 0; i < ret; i++) {
        dfsan_set_label(dfsan_create_label(offset + i), (char *)buf + i, 1);
      }
      taint_update_socket_offset(sockfd, ret);
    } else {
      // clear the label?
      dfsan_set_label(0, buf, ret);
    }
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE ssize_t __dfsw_recvfrom(
    int sockfd, void *buf, size_t leng, int flags, struct sockaddr *src_addr,
    socklen_t *addrlen, dfsan_label sockfd_label, dfsan_label buf_label,
    dfsan_label leng_label, dfsan_label flags_label, dfsan_label src_addr_label,
    dfsan_label addrlen_label, dfsan_label *ret_label) {
  socklen_t alen = 0;
  __taint_check_bounds(buf_label, (uptr)buf, leng_label, leng);
  if (leng_label)
    __taint_solve_bounds(buf_label, (uint64_t)buf, leng_label, leng, 0, 1, 0, 0);
  internal_memset(buf, 0, leng);

  ssize_t ret = recvfrom(sockfd, buf, leng, flags, src_addr, &alen);
#if AIXCC_HACK
  ssize_t readed = strlen((char *)buf);
  if (ret == 0 && readed > 0) ret = readed; // we actually readed something
#endif
  if (ret > 0) {
    off_t offset = taint_get_socket(sockfd);
    if (offset >= 0) {
      for (ssize_t i = 0; i < ret; i++) {
        dfsan_set_label(dfsan_create_label(offset + i), (char *)buf + i, 1);
      }
      taint_update_socket_offset(sockfd, ret);
    } else {
      // clear the label?
      dfsan_set_label(0, buf, ret);
    }
  }
  if (src_addr) { dfsan_set_label(0, src_addr, alen); }
  if (addrlen) { *addrlen = alen; }
  *ret_label = 0;
  return ret;
}

static void taint_handle_msg(int sockfd, struct msghdr *msg, size_t msg_len) {
  // clear labels
  if (msg->msg_name) {
    dfsan_set_label(0, msg->msg_name, msg->msg_namelen);
  }
  if (msg->msg_control) {
    dfsan_set_label(0, msg->msg_control, msg->msg_controllen);
  }
  off_t offset = taint_get_socket(sockfd);
  for (size_t i = 0, bytes_written = msg_len; bytes_written > 0; ++i) {
    assert(i < msg->msg_iovlen);
    struct iovec *iov = &msg->msg_iov[i];
    size_t iov_written =
        bytes_written < iov->iov_len ? bytes_written : iov->iov_len;
    if (offset >= 0) {
      for (size_t j = 0; j < iov_written; ++j) {
        dfsan_set_label(dfsan_create_label(offset + j), (char *)iov->iov_base + j, 1);
      }
      taint_update_socket_offset(sockfd, iov_written);
      offset += iov_written;
    } else {
      dfsan_set_label(0, iov->iov_base, iov_written);
    }
    bytes_written -= iov_written;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE ssize_t __dfsw_recvmsg(
    int sockfd, struct msghdr *msg, int flags, dfsan_label sockfd_label,
    dfsan_label msg_label, dfsan_label flags_label, dfsan_label *ret_label) {
  ssize_t ret = recvmsg(sockfd, msg, flags);
  if (ret >= 0) {
    taint_handle_msg(sockfd, msg, ret);
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int __dfsw_recvmmsg(
    int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags,
    struct timespec *timeout, dfsan_label sockfd_label,
    dfsan_label msgvec_label, dfsan_label vlen_label, dfsan_label flags_label,
    dfsan_label timeout_label, dfsan_label *ret_label) {
  int ret = recvmmsg(sockfd, msgvec, vlen, flags, timeout);
  for (int i = 0; i < ret; ++i) {
    dfsan_set_label(0, &msgvec[i].msg_len, sizeof(msgvec[i].msg_len));
    taint_handle_msg(sockfd, &msgvec[i].msg_hdr, msgvec[i].msg_len);
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_socketpair(int domain, int type, int protocol, int sv[2],
                  dfsan_label domain_label, dfsan_label type_label,
                  dfsan_label protocol_label, dfsan_label sv_label,
                  dfsan_label *ret_label) {
  int ret = socketpair(domain, type, protocol, sv);
  *ret_label = 0;
  if (ret == 0) {
    dfsan_set_label(0, sv, sizeof(*sv) * 2);
  }
  return ret;
}

// Type of the trampoline function passed to the custom version of
// dfsan_set_write_callback.
typedef void (*write_trampoline_t)(
    void *callback,
    int fd, const void *buf, ssize_t count,
    dfsan_label fd_label, dfsan_label buf_label, dfsan_label count_label);

// Calls to dfsan_set_write_callback() set the values in this struct.
// Calls to the custom version of write() read (and invoke) them.
static struct {
  write_trampoline_t write_callback_trampoline = nullptr;
  void *write_callback = nullptr;
} write_callback_info;

SANITIZER_INTERFACE_ATTRIBUTE void
__dfsw_dfsan_set_write_callback(
    write_trampoline_t write_callback_trampoline,
    void *write_callback,
    dfsan_label write_callback_label,
    dfsan_label *ret_label) {
  write_callback_info.write_callback_trampoline = write_callback_trampoline;
  write_callback_info.write_callback = write_callback;
  *ret_label = 0;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_write(int fd, const void *buf, size_t count,
             dfsan_label fd_label, dfsan_label buf_label,
             dfsan_label count_label, dfsan_label *ret_label) {
  if (write_callback_info.write_callback) {
    write_callback_info.write_callback_trampoline(
        write_callback_info.write_callback,
        fd, buf, count,
        fd_label, buf_label, count_label);
  }

  *ret_label = 0;
  int ret = write(fd, buf, count);
#if AIXCC_HACK
  if (buf && tainted.buf && !internal_memcmp(buf, tainted.buf, count)) {
    AOUT("Closing aixcc pipefd %d\n", fd);
    close(fd);
  }
#endif
  return ret;
}

} // extern "C"

// Type used to extract a dfsan_label with va_arg()
typedef int dfsan_label_va;

// Formats a chunk either a constant string or a single format directive (e.g.,
// '%.3f').
struct Formatter {
  Formatter(char *str_, const char *fmt_, size_t size_)
      : str(str_), str_off(0), size(size_), fmt_start(fmt_), fmt_cur(fmt_),
        width(-1) {}

  int format() {
    char *tmp_fmt = build_format_string();
    int retval =
        snprintf(str + str_off, str_off < size ? size - str_off : 0, tmp_fmt,
                 0 /* used only to avoid warnings */);
    free(tmp_fmt);
    return retval;
  }

  template <typename T> int format(T arg) {
    char *tmp_fmt = build_format_string();
    int retval;
    if (width >= 0) {
      retval = snprintf(str + str_off, str_off < size ? size - str_off : 0,
                        tmp_fmt, width, arg);
    } else {
      retval = snprintf(str + str_off, str_off < size ? size - str_off : 0,
                        tmp_fmt, arg);
    }
    free(tmp_fmt);
    return retval;
  }

  char *build_format_string() {
    size_t fmt_size = fmt_cur - fmt_start + 1;
    char *new_fmt = (char *)malloc(fmt_size + 1);
    assert(new_fmt);
    internal_memcpy(new_fmt, fmt_start, fmt_size);
    new_fmt[fmt_size] = '\0';
    return new_fmt;
  }

  char *str_cur() { return str + str_off; }

  size_t num_written_bytes(int retval) {
    if (retval < 0) {
      return 0;
    }

    size_t num_avail = str_off < size ? size - str_off : 0;
    if (num_avail == 0) {
      return 0;
    }

    size_t num_written = retval;
    // A return value of {v,}snprintf of size or more means that the output was
    // truncated.
    if (num_written >= num_avail) {
      num_written -= num_avail;
    }

    return num_written;
  }

  char *str;
  size_t str_off;
  size_t size;
  const char *fmt_start;
  const char *fmt_cur;
  int width;
};

// Formats the input and propagates the input labels to the output. The output
// is stored in 'str'. 'size' bounds the number of output bytes. 'format' and
// 'ap' are the format string and the list of arguments for formatting. Returns
// the return value vsnprintf would return.
//
// The function tokenizes the format string in chunks representing either a
// constant string or a single format directive (e.g., '%.3f') and formats each
// chunk independently into the output string. This approach allows to figure
// out which bytes of the output string depends on which argument and thus to
// propagate labels more precisely.
//
// WARNING: This implementation does not support conversion specifiers with
// positional arguments.
static int format_buffer(char *str, size_t size, const char *fmt,
                         dfsan_label *va_labels, dfsan_label *ret_label,
                         va_list ap) {
  Formatter formatter(str, fmt, size);

  while (*formatter.fmt_cur) {
    formatter.fmt_start = formatter.fmt_cur;
    formatter.width = -1;
    int retval = 0;

    if (*formatter.fmt_cur != '%') {
      // Ordinary character. Consume all the characters until a '%' or the end
      // of the string.
      for (; *(formatter.fmt_cur + 1) && *(formatter.fmt_cur + 1) != '%';
           ++formatter.fmt_cur) {}
      retval = formatter.format();
      dfsan_set_label(0, formatter.str_cur(),
                      formatter.num_written_bytes(retval));
    } else {
      // Conversion directive. Consume all the characters until a conversion
      // specifier or the end of the string.
      bool end_fmt = false;
      for (; *formatter.fmt_cur && !end_fmt; ) {
        switch (*++formatter.fmt_cur) {
        case 'd':
        case 'i':
        case 'o':
        case 'u':
        case 'x':
        case 'X':
          switch (*(formatter.fmt_cur - 1)) {
          case 'h':
            // Also covers the 'hh' case (since the size of the arg is still
            // an int).
            retval = formatter.format(va_arg(ap, int));
            break;
          case 'l':
            if (formatter.fmt_cur - formatter.fmt_start >= 2 &&
                *(formatter.fmt_cur - 2) == 'l') {
              retval = formatter.format(va_arg(ap, long long int));
            } else {
              retval = formatter.format(va_arg(ap, long int));
            }
            break;
          case 'q':
            retval = formatter.format(va_arg(ap, long long int));
            break;
          case 'j':
            retval = formatter.format(va_arg(ap, intmax_t));
            break;
          case 'z':
          case 't':
            retval = formatter.format(va_arg(ap, size_t));
            break;
          default:
            retval = formatter.format(va_arg(ap, int));
          }
          //dfsan_set_label(*va_labels++, formatter.str_cur(),
          //                formatter.num_written_bytes(retval));
          end_fmt = true;
          break;

        case 'a':
        case 'A':
        case 'e':
        case 'E':
        case 'f':
        case 'F':
        case 'g':
        case 'G':
          if (*(formatter.fmt_cur - 1) == 'L') {
            retval = formatter.format(va_arg(ap, long double));
          } else {
            retval = formatter.format(va_arg(ap, double));
          }
          //dfsan_set_label(*va_labels++, formatter.str_cur(),
          //                formatter.num_written_bytes(retval));
          end_fmt = true;
          break;

        case 'c':
          retval = formatter.format(va_arg(ap, int));
          //dfsan_set_label(*va_labels++, formatter.str_cur(),
          //                formatter.num_written_bytes(retval));
          end_fmt = true;
          break;

        case 's': {
          char *arg = va_arg(ap, char *);
          retval = formatter.format(arg);
          va_labels++;
          internal_memcpy(shadow_for(formatter.str_cur()), shadow_for(arg),
                          sizeof(dfsan_label) *
                              formatter.num_written_bytes(retval));
          end_fmt = true;
          break;
        }

        case 'p':
          retval = formatter.format(va_arg(ap, void *));
          //dfsan_set_label(*va_labels++, formatter.str_cur(),
          //                formatter.num_written_bytes(retval));
          end_fmt = true;
          break;

        case 'n': {
          int *ptr = va_arg(ap, int *);
          *ptr = (int)formatter.str_off;
          va_labels++;
          dfsan_set_label(0, ptr, sizeof(ptr));
          end_fmt = true;
          break;
        }

        case '%':
          retval = formatter.format();
          dfsan_set_label(0, formatter.str_cur(),
                          formatter.num_written_bytes(retval));
          end_fmt = true;
          break;

        case '*':
          formatter.width = va_arg(ap, int);
          va_labels++;
          break;

        default:
          break;
        }
      }
    }

    if (retval < 0) {
      return retval;
    }

    formatter.fmt_cur++;
    formatter.str_off += retval;
  }

  *ret_label = 0;

  // Number of bytes written in total.
  return formatter.str_off;
}

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_sprintf(char *str, const char *format, dfsan_label str_label,
                   dfsan_label format_label, dfsan_label *va_labels,
                   dfsan_label *ret_label, ...) {
  va_list ap;
  va_start(ap, ret_label);
  int ret = format_buffer(str, ~0ul, format, va_labels, ret_label, ap);
  va_end(ap);
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_snprintf(char *str, size_t size, const char *format,
                    dfsan_label str_label, dfsan_label size_label,
                    dfsan_label format_label, dfsan_label *va_labels,
                    dfsan_label *ret_label, ...) {
  va_list ap;
  va_start(ap, ret_label);
  int ret = format_buffer(str, size, format, va_labels, ret_label, ap);
  va_end(ap);
  *ret_label = 0;
  return ret;
}

// Default empty implementations (weak). Users should redefine them.
SANITIZER_INTERFACE_WEAK_DEF(void, __sanitizer_cov_trace_pc_guard, u32 *) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __sanitizer_cov_trace_pc_guard_init, u32 *,
                             u32 *) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __sanitizer_cov_pcs_init, const uptr *beg,
                             const uptr *end) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __sanitizer_cov_trace_pc_indir, void) {}

SANITIZER_INTERFACE_WEAK_DEF(void, __dfsw___sanitizer_cov_trace_cmp, void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __dfsw___sanitizer_cov_trace_cmp1, void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __dfsw___sanitizer_cov_trace_cmp2, void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __dfsw___sanitizer_cov_trace_cmp4, void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __dfsw___sanitizer_cov_trace_cmp8, void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __dfsw___sanitizer_cov_trace_const_cmp1,
                             void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __dfsw___sanitizer_cov_trace_const_cmp2,
                             void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __dfsw___sanitizer_cov_trace_const_cmp4,
                             void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __dfsw___sanitizer_cov_trace_const_cmp8,
                             void) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __dfsw___sanitizer_cov_trace_switch, void) {}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_open(const char *path, int oflags, dfsan_label path_label,
            dfsan_label flag_label, dfsan_label *va_labels,
            dfsan_label *ret_label, ...) {
  va_list args;
  va_start(args, ret_label);
  int fd = open(path, oflags, args);
  va_end(args);

  if (fd)
    taint_set_file(AT_FDCWD, path, fd);
  *ret_label = 0;
  return fd;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_openat(int dirfd, const char *path, int oflags, dfsan_label dirfd_label,
              dfsan_label path_label, dfsan_label flag_label,
              dfsan_label *va_labels, dfsan_label *ret_label, ...) {
  va_list args;
  va_start(args, ret_label);
  int fd = openat(dirfd, path, oflags, args);
  va_end(args);

  if (fd)
    taint_set_file(dirfd, path, fd);
  *ret_label = 0;
  return fd;
}

SANITIZER_INTERFACE_ATTRIBUTE FILE *
__dfsw_fopen(const char *filename, const char *mode,
             dfsan_label filename_label, dfsan_label mode_label,
             dfsan_label *ret_label) {
  FILE *ret = fopen(filename, mode);
  if (ret) {
    AOUT("%d fd is fopened\n", fileno(ret));
    taint_set_file(AT_FDCWD, filename, fileno(ret));
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE FILE *
__dfsw_fopen64(const char *filename, const char *mode,
               dfsan_label filename_label, dfsan_label mode_label,
               dfsan_label *ret_label) {
  FILE *ret = fopen64(filename, mode);
  if (ret) {
    AOUT("%d fd is fopened\n", fileno(ret));
    taint_set_file(AT_FDCWD, filename, fileno(ret));
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE FILE *
__dfsw_freopen(const char *filename, const char *mode,
               FILE *stream, dfsan_label filename_label,
               dfsan_label mode_label, dfsan_label stream_label,
               dfsan_label *ret_label) {
  FILE *ret = freopen(filename, mode, stream);
  if (ret)
    taint_set_file(AT_FDCWD, filename, fileno(ret));
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_close(int fd, dfsan_label fd_label, dfsan_label *ret_label) {
  taint_close_file(fd);
  *ret_label = 0;
  return close(fd);
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_fclose(FILE *fp, dfsan_label fp_label, dfsan_label *ret_label) {
  int fd = fileno(fp);
  int ret = fclose(fp);
  if (!ret) taint_close_file(fd);
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE size_t
__dfsw_fread(void *ptr, size_t size, size_t nmemb, FILE *stream,
             dfsan_label ptr_label, dfsan_label size_label,
             dfsan_label nmemb_label, dfsan_label stream_label,
             dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t tfsize = taint_get_file(fd);
  off_t offset = ftell(stream);
  *ret_label = 0;
#if 0
  // check taint file size
  if (tfsize && (tfsize < offset + (size * nmemb))) {
    // if smaller than a tainted offset, enlarge
    dfsan_label offset_label = taint_get_offset_label();
    if (offset_label) {
      AOUT("fread(%u,%u) from tainted offset %lld\n", size, nmemb, offset);
      // instead of read, write
      internal_memset(ptr, 0, size * nmemb);
      fwrite(ptr, size, nmemb, stream);
      // update taint
      for (size_t i = 0; i < size * nmemb; i++) {
        dfsan_set_label(dfsan_create_label(offset + i), (char *)ptr + i, 1);
      }
      return nmemb; // directly return
    }
  }
#endif
  __taint_check_bounds(ptr_label, (uptr)ptr, nmemb_label, size * nmemb);
  if (nmemb_label)
    __taint_solve_bounds(ptr_label, (uint64_t)ptr, nmemb_label, nmemb, 0, size, 0, 0);
  size_t ret = fread(ptr, size, nmemb, stream);
  AOUT("fread(%lu,%lu) = %ld, off = %ld\n", size, nmemb, ret, offset);
  if (ret) {
    if (tfsize) {
      for (size_t i = 0; i < ret * size; i++) {
        dfsan_set_label(get_label_for(fd, offset + i), (char *)ptr + i, 1);
      }
      // for (size_t i = ret * size; i < size * nmemb; i++) {
      //   dfsan_set_label(-1, (char *)ptr + i, 1);
      // }
      // *ret_label = dfsan_union(0, 0, fsize, sizeof(ret) * 8, offset, 0);
    } else {
      dfsan_set_label(0, ptr, ret * size);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE size_t
__dfsw_fread_unlocked(
             void *ptr, size_t size, size_t nmemb, FILE *stream,
             dfsan_label ptr_label, dfsan_label size_label,
             dfsan_label nmemb_label, dfsan_label stream_label,
             dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t tfsize = taint_get_file(fd);
  off_t offset = ftell(stream);
  *ret_label = 0;
#if 0
  // check taint file size
  if (tfsize && (tfsize < offset + (size * nmemb))) {
    // if smaller than a tainted offset, enlarge
    dfsan_label offset_label = taint_get_offset_label();
    if (offset_label) {
      AOUT("fread(%u,%u) from tainted offset %lld\n", size, nmemb, offset);
      // instead of read, write
      internal_memset(ptr, 0, size * nmemb);
      fwrite(ptr, size, nmemb, stream);
      // update taint
      for (size_t i = 0; i < size * nmemb; i++) {
        dfsan_set_label(dfsan_create_label(offset + i), (char *)ptr + i, 1);
      }
      return nmemb; // directly return
    }
  }
#endif
  __taint_check_bounds(ptr_label, (uptr)ptr, nmemb_label, size * nmemb);
  if (nmemb_label)
    __taint_solve_bounds(ptr_label, (uint64_t)ptr, nmemb_label, nmemb, 0, size, 0, 0);
  size_t ret = fread_unlocked(ptr, size, nmemb, stream);
  AOUT("fread(%lu,%lu) = %ld, off = %ld\n", size, nmemb, ret, offset);
  if (ret) {
    if (tfsize) {
      for (size_t i = 0; i < ret * size; i++) {
        dfsan_set_label(get_label_for(fd, offset + i), (char *)ptr + i, 1);
      }
      // for (size_t i = ret * size; i < nmemb * size; i++) {
      //   dfsan_set_label(-1, (char *)ptr + i, 1);
      // }
      // *ret_label = dfsan_union(0, 0, fsize, sizeof(ret) * 8, offset, 0);
    } else {
      dfsan_set_label(0, ptr, ret * size);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE ssize_t
__dfsw_getline(char **lineptr, size_t *n, FILE *stream,
               dfsan_label lineptr_label, dfsan_label n_label,
               dfsan_label stream_label, dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t offset = ftell(stream);
  ssize_t ret = getline(lineptr, n, stream);
  *ret_label = 0;
  if (ret) {
    if (taint_get_file(fd)) {
      // including a terminating null byte
      for (ssize_t i = 0; i < ret; i++) {
        void *addr = (*lineptr) + i;
        dfsan_set_label(get_label_for(fd, offset + i), addr, 1);
      }
      dfsan_set_label(0, (*lineptr) + ret, 1);
      // *ret_label = dfsan_union(0, 0, fsize, sizeof(ret) * 8, offset, 0);
      // FIXME: set the label for the ptr to track the buffer size
    } else {
      dfsan_set_label(0, *lineptr, ret + 1);
    }
  }
  return ret;
}

// ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);
SANITIZER_INTERFACE_ATTRIBUTE ssize_t
__dfsw_getdelim(char **lineptr, size_t *n, int delim, FILE *stream,
                dfsan_label buf_label, dfsan_label size_label,
                dfsan_label delim_label, dfsan_label stream_label,
                dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t offset = ftell(stream);
  ssize_t ret = getdelim(lineptr, n, delim, stream);
  *ret_label = 0;
  if (ret) {
    if (taint_get_file(fd)) {
      // including a terminating null byte
      for(ssize_t i = 0; i < ret; i++) {
        void *addr = (*lineptr) + i;
        dfsan_set_label(get_label_for(fd, offset + i), addr, 1);
        // FIXME: set the label for the ptr to track the buffer size
      }
      dfsan_set_label(0, (*lineptr) + ret, 1);
      // *ret_label = dfsan_union(0, 0, fsize, sizeof(ret) * 8, offset, 0);
    } else {
      dfsan_set_label(0, *lineptr, ret + 1);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE ssize_t
__dfsw___getdelim(char **lineptr, size_t *n, int delim, FILE *stream,
                  dfsan_label buf_label, dfsan_label size_label,
                  dfsan_label delim_label, dfsan_label stream_label,
                  dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t offset = ftell(stream);
  ssize_t ret = __getdelim(lineptr, n, delim, stream);
  *ret_label = 0;
  if (ret) {
    if (taint_get_file(fd)) {
      for(ssize_t i = 0; i < ret; i++) {
        void *addr = (*lineptr) + i;
        dfsan_set_label(get_label_for(fd, offset + i), addr, 1);
      }
      dfsan_set_label(0, (*lineptr) + ret, 1);
      // *ret_label = dfsan_union(0, 0, fsize, sizeof(ret) * 8, offset, 0);
      // FIXME: set the label for the ptr to track the buffer size
    } else {
      dfsan_set_label(0, *lineptr, ret + 1);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE char*
__dfsw_gets(char *str, dfsan_label str_label, dfsan_label *ret_label) {
  off_t offset = ftell(stdin);
  // gets discard until c11
  char *ret = fgets(str, sizeof(str), stdin);
  if (ret && taint_get_file(0)) {
    for (off_t i = 0; i <= strlen(ret); i++)
      dfsan_set_label(get_label_for(0, offset + i), ret + i, 1);
    *ret_label = str_label;
  } else {
    *ret_label = 0;
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_utmpxname(const char *file, dfsan_label file_label, dfsan_label *ret_label) {
  if (is_taint_file(file)) {
    set_utmp_offset(0);
  }
  int ret = utmpxname(file);
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE void
__dfsw_setutxent(void) {
  if (is_utmp_taint())
    set_utmp_offset(0);
  setutxent();
}

SANITIZER_INTERFACE_ATTRIBUTE struct utmpx *
__dfsw_getutxent(dfsan_label *ret_label) {
  struct utmpx *ret = getutxent();
  *ret_label = 0;
  if (ret && is_utmp_taint()) {
    off_t offset = get_utmp_offset();
    for (size_t i = 0; i < sizeof(struct utmpx); i++) {
      dfsan_set_label(get_label_for(-1, offset + i), (char *)ret + i, 1);
    }
    set_utmp_offset(offset + sizeof(struct utmpx));
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
char *__dfsw_fgets(char *s, int size, FILE *stream, dfsan_label s_label,
                   dfsan_label size_label, dfsan_label stream_label,
                   dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t offset = ftell(stream);
  __taint_check_bounds(s_label, (uptr)s, size_label, size);
  if (size_label)
    __taint_solve_bounds(s_label, (uint64_t)s, size_label, size, 0, 1, 0, 0);
  char *ret = fgets(s, size, stream);
  if (ret) {
    if (taint_get_file(fd)) {
      // including terminating \0
      for (size_t i = 0; i < strlen(ret); i++) {
        char *buf = s + i;
        dfsan_set_label(get_label_for(fd, offset + i), buf, 1);
      }
      dfsan_set_label(0, s + strlen(ret), 1);
      // for(int i = strlen(ret) + 1; i < size; i++) {
      //   char *buf = s + i;
      //   dfsan_set_label(-1, buf, 1);
      // }
    } else {
      dfsan_set_label(0, s, strlen(ret) + 1);
    }
    *ret_label = s_label;
  } else *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
char *__dfsw_fgets_unlocked(char *s, int size, FILE *stream, dfsan_label s_label,
                   dfsan_label size_label, dfsan_label stream_label,
                   dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t offset = ftell(stream);
  __taint_check_bounds(s_label, (uptr)s, size_label, size);
  if (size_label)
    __taint_solve_bounds(s_label, (uint64_t)s, size_label, size, 0, 1, 0, 0);
  char *ret = fgets_unlocked(s, size, stream);
  if (ret) {
    if (taint_get_file(fd)) {
      // including terminating \0
      for (size_t i = 0; i < strlen(ret); i++) {
        char *buf = s + i;
        dfsan_set_label(get_label_for(fd, offset + i), buf, 1);
      }
      dfsan_set_label(0, s + strlen(ret), 1);
      // for(int i = strlen(ret) + 1; i < size; i++) {
      //   char *buf = s + i;
      //   dfsan_set_label(-1, buf, 1);
      // }
    } else {
      dfsan_set_label(0, s, strlen(ret) + 1);
    }
    *ret_label = s_label;
  } else {
    *ret_label = 0;
  }
  return ret;
}

static inline void __taint_check_malloc_size(size_t size, dfsan_label size_label) {
  if (size_label && flags().solve_ub) {
    AOUT("*alloc size: %lu = %d\n", size, size_label);
    // -fsanitize=unsigned-integer-overflow
    dfsan_label os = dfsan_union(0, size_label, (bveq << 8) | ICmp, 64, 0, size);
    __taint_trace_cond(os, 0, UndefinedCheck, ub_integer_overflow);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void *
__dfsw_realloc(void *ptr, size_t new_size,
               dfsan_label ptr_label, dfsan_label new_size_label,
               dfsan_label *ret_label) {
  __taint_check_malloc_size(new_size, new_size_label);
  void *ret = malloc(new_size);
  *ret_label = 0;

  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * new_size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, new_size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + new_size);
      *ret_label = bound;
    }
  }

  if (ptr) {
    if (ret) {
      // copy old labels
      size_t size = malloc_usable_size(ptr);
      size = size < new_size ? size : new_size;
      internal_memcpy(ret, ptr, size);
      internal_memcpy(shadow_for(ret), shadow_for(ptr), sizeof(dfsan_label) * size);
    }
    if (flags().trace_bounds) {
      // mark old buffer as freed without truely free it
      dfsan_label_info *info = dfsan_get_label_info(ptr_label);
      if (info->op != Alloca) {
        AOUT("WARNING: wrong ptr op %d = %d\n", ptr_label, info->op);
        // Die();
      } else info->op = Free;
    } else {
      free(ptr);
    }
  }

  if (flags().trace_bounds) {
    AOUT("old ptr: %p = %d, new size: %lu = %d, new ptr: %p = %d\n", ptr, ptr_label,
        new_size, new_size_label, ret, *ret_label);
  }

  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE void *
__dfsw___libc_realloc(void *ptr, size_t new_size,
                      dfsan_label ptr_label, dfsan_label new_size_label,
                      dfsan_label *ret_label) {
  __taint_check_malloc_size(new_size, new_size_label);
  void *ret = malloc(new_size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * new_size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, new_size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + new_size);
      *ret_label = bound;
    }
  }

  if (ptr) {
    if (ret) {
      // copy old labels
      size_t size = malloc_usable_size(ptr);
      size = size < new_size ? size : new_size;
      internal_memcpy(ret, ptr, size);
      internal_memcpy(shadow_for(ret), shadow_for(ptr), sizeof(dfsan_label) * size);
    }
    if (flags().trace_bounds) {
      // mark old buffer as freed without truely free it
      dfsan_label_info *info = dfsan_get_label_info(ptr_label);
      if (info->op != Alloca) {
        AOUT("WARNING: wrong ptr op %d = %d\n", ptr_label, info->op);
        // Die();
      } else info->op = Free;
    } else {
      free(ptr);
    }
  }

  if (flags().trace_bounds) {
    AOUT("old ptr: %p = %d, new size: %lu = %d, new ptr: %p = %d\n", ptr, ptr_label,
        new_size, new_size_label, ret, *ret_label);
  }

  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw_reallocarray(void *ptr, size_t nmemb, size_t new_size,
                          dfsan_label ptr_label, dfsan_label nmemb_label,
                          dfsan_label new_size_label, dfsan_label *ret_label) {
  if (nmemb_label != 0 || new_size_label != 0) {
    dfsan_label byte_size = dfsan_union(nmemb_label, new_size_label, Mul,
        64, nmemb, new_size);
    __taint_check_malloc_size(nmemb * new_size, byte_size);
  }
  void *ret = calloc(nmemb, new_size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * new_size * nmemb);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(nmemb_label, new_size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + (new_size * nmemb));
      *ret_label = bound;
    }
  }

  if (ptr) {
    if (ret) {
      // copy old labels
      size_t size = malloc_usable_size(ptr);
      size = size < new_size ? size : new_size * nmemb;
      internal_memcpy(ret, ptr, size);
      internal_memcpy(shadow_for(ret), shadow_for(ptr), sizeof(dfsan_label) * size);
    }
    if (flags().trace_bounds) {
      // mark old buffer as freed without truely free it
      dfsan_label_info *info = dfsan_get_label_info(ptr_label);
      if (info->op != Alloca) {
        AOUT("WARNING: wrong ptr op %d = %d\n", ptr_label, info->op);
        // Die();
      } else info->op = Free;
    } else {
      free(ptr);
    }
  }

  if (flags().trace_bounds) {
    AOUT("old ptr: %p = %d, new size: %lu = %d, new ptr: %p = %d\n", ptr, ptr_label,
        new_size, new_size_label, ret, *ret_label);
  }

  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw___libc_reallocarray(void *ptr, size_t nmemb, size_t new_size,
                                 dfsan_label ptr_label, dfsan_label nmemb_label,
                                 dfsan_label new_size_label, dfsan_label *ret_label) {
  if (nmemb_label != 0 || new_size_label != 0) {
    dfsan_label byte_size = dfsan_union(nmemb_label, new_size_label, Mul,
        64, nmemb, new_size);
    __taint_check_malloc_size(nmemb * new_size, byte_size);
  }
  void *ret = calloc(nmemb, new_size);
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * new_size * nmemb);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(nmemb_label, new_size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + (new_size * nmemb));
      *ret_label = bound;
    }
  }

  if (ptr) {
    if (ret) {
      // copy old labels
      size_t size = malloc_usable_size(ptr);
      size = size < new_size ? size : new_size * nmemb;
      internal_memcpy(ret, ptr, size);
      internal_memcpy(shadow_for(ret), shadow_for(ptr), sizeof(dfsan_label) * size);
    }
    if (flags().trace_bounds) {
      // mark old buffer as freed without truely free it
      dfsan_label_info *info = dfsan_get_label_info(ptr_label);
      if (info->op != Alloca) {
        AOUT("WARNING: wrong ptr op %d = %d\n", ptr_label, info->op);
        // Die();
      } else info->op = Free;
    } else {
      free(ptr);
    }
  }

  if (flags().trace_bounds) {
    AOUT("old ptr: %p = %d, nmemb: %lu = %d, new size: %lu = %d, new ptr: %p = %d\n",
        ptr, ptr_label, nmemb, nmemb_label, new_size, new_size_label, ret, *ret_label);
  }

  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw_calloc(size_t nmemb, size_t size,
                    dfsan_label nmemb_label, dfsan_label size_label,
                    dfsan_label *ret_label) {
  if (nmemb_label != 0 || size_label != 0) {
    dfsan_label byte_size = dfsan_union(nmemb_label, size_label, Mul,
        64, nmemb, size);
    __taint_check_malloc_size(nmemb * size, byte_size);
  }
  void *ret = calloc(nmemb, size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size * nmemb);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(nmemb_label, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + (size * nmemb));
      *ret_label = bound;
      AOUT("nmemb: %lu = %d, size: %lu = %d, addr: %p = %d\n", nmemb, nmemb_label,
          size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw___libc_calloc(size_t nmemb, size_t size,
                           dfsan_label nmemb_label, dfsan_label size_label,
                           dfsan_label *ret_label) {
  if (nmemb_label != 0 || size_label != 0) {
    dfsan_label byte_size = dfsan_union(nmemb_label, size_label, Mul,
        64, nmemb, size);
    __taint_check_malloc_size(nmemb * size, byte_size);
  }
  void *ret = calloc(nmemb, size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size * nmemb);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(nmemb_label, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + (size * nmemb));
      *ret_label = bound;
      AOUT("nmemb: %lu = %d, size: %lu = %d, addr: %p = %d\n", nmemb, nmemb_label,
          size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw_malloc(size_t size, dfsan_label size_label,
                   dfsan_label *ret_label) {
  __taint_check_malloc_size(size, size_label);
  void *ret = malloc(size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + size);
      *ret_label = bound;
      AOUT("length: %lu = %d, addr: %p = %d\n", size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw___libc_malloc(size_t size, dfsan_label size_label,
                           dfsan_label *ret_label) {
  __taint_check_malloc_size(size, size_label);
  void *ret = malloc(size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + size);
      *ret_label = bound;
      AOUT("length: %lu = %d, addr: %p = %d\n", size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw_aligned_alloc(size_t alignment, size_t size,
                           dfsan_label alignment_label, dfsan_label size_label,
                           dfsan_label *ret_label) {
  __taint_check_malloc_size(size, size_label);
  void *ret = aligned_alloc(alignment, size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + size);
      *ret_label = bound;
      AOUT("length: %lu = %d, addr: %p = %d\n", size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
int __dfsw_posix_memalign(void **memptr, size_t alignment, size_t size,
                          dfsan_label memptr_label, dfsan_label alignment_label,
                          dfsan_label size_label, dfsan_label *ret_label) {
  __taint_check_malloc_size(size, size_label);
  int ret = posix_memalign(memptr, alignment, size);
  *ret_label = 0;
  if (!ret && memptr && *memptr) {
    internal_memset(shadow_for(*memptr), 0, sizeof(dfsan_label) * size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, size_label, Alloca, sizeof(*memptr) * 8,
          (uint64_t)(*memptr), (uint64_t)(*memptr) + size);
      dfsan_set_label(bound, memptr, sizeof(*memptr));
      AOUT("length: %lu = %d, addr: %p = %d\n", size, size_label, *memptr, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw_valloc(size_t size, dfsan_label size_label, dfsan_label *ret_label) {
  __taint_check_malloc_size(size, size_label);
  void *ret = valloc(size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + size);
      *ret_label = bound;
      AOUT("length: %lu = %d, addr: %p = %d\n", size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw___libc_valloc(size_t size, dfsan_label size_label, dfsan_label *ret_label) {
  __taint_check_malloc_size(size, size_label);
  void *ret = valloc(size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + size);
      *ret_label = bound;
      AOUT("length: %lu = %d, addr: %p = %d\n", size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw_memalign(size_t alignment, size_t size, dfsan_label alignment_label,
                      dfsan_label size_label, dfsan_label *ret_label) {
  __taint_check_malloc_size(size, size_label);
  void *ret = memalign(alignment, size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + size);
      *ret_label = bound;
      AOUT("length: %lu = %d, addr: %p = %d\n", size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw___libc_memalign(size_t alignment, size_t size, dfsan_label alignment_label,
                             dfsan_label size_label, dfsan_label *ret_label) {
  __taint_check_malloc_size(size, size_label);
  void *ret = memalign(alignment, size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + size);
      *ret_label = bound;
      AOUT("length: %lu = %d, addr: %p = %d\n", size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw_pvalloc(size_t size, dfsan_label size_label, dfsan_label *ret_label) {
  __taint_check_malloc_size(size, size_label);
  void *ret = pvalloc(size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + size);
      *ret_label = bound;
      AOUT("length: %lu = %d, addr: %p = %d\n", size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__dfsw___libc_pvalloc(size_t size, dfsan_label size_label, dfsan_label *ret_label) {
  __taint_check_malloc_size(size, size_label);
  void *ret = pvalloc(size);
  *ret_label = 0;
  if (ret) {
    internal_memset(shadow_for(ret), 0, sizeof(dfsan_label) * size);
    if (flags().trace_bounds) {
      dfsan_label bound = dfsan_union(0, size_label, Alloca, sizeof(ret) * 8,
          (uint64_t)ret, (uint64_t)ret + size);
      *ret_label = bound;
      AOUT("length: %lu = %d, addr: %p = %d\n", size, size_label, ret, *ret_label);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE void __dfsw_free(void *ptr, dfsan_label ptr_label) {
  if (ptr && flags().trace_bounds) {
    // don't really free, a hacky way to avoid reusing the address
    // just mark as freed
    AOUT("addr: %p = %d\n", ptr, ptr_label);
    dfsan_label_info *info = dfsan_get_label_info(ptr_label);
    if (info->op == Alloca) {
      info->op = Free;
    } else if (info->op == Free) {
      void *addr = __builtin_return_address(0);
      AOUT("WARNING: double free %p = %d @%p\n", ptr, ptr_label, addr);
      __taint_trace_memerr(ptr_label, (uptr)ptr, 0, 0, F_MEMERR_FREE, addr);
    } else {
      AOUT("WARNING: wrong ptr op %d = %d @%p\n", ptr_label, info->op,
           __builtin_return_address(0));
      // Die();
    }
  } else {
    free(ptr);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE
void __dfsw___libc_free(void *ptr, dfsan_label ptr_label) {
  if (ptr && flags().trace_bounds) {
    // don't really free, a hacky way to avoid reusing the address
    // just mark as freed
    AOUT("addr: %p = %d\n", ptr, ptr_label);
    dfsan_label_info *info = dfsan_get_label_info(ptr_label);
    if (info->op == Alloca) {
      info->op = Free;
    } else if (info->op == Free) {
      void *addr = __builtin_return_address(0);
      AOUT("WARNING: double free %p = %d @%p\n", ptr, ptr_label, addr);
      __taint_trace_memerr(ptr_label, (uptr)ptr, 0, 0, F_MEMERR_FREE, addr);
    } else {
      AOUT("WARNING: wrong ptr op %d = %d\n", ptr_label, info->op);
      // Die();
    }
  } else {
    free(ptr);
  }
}

static dfsan_label taint_getc(int fd, off_t offset, int ret) {
  if (ret != EOF && taint_get_file(fd)) {
    dfsan_label label = label = dfsan_union(get_label_for(fd, offset), CONST_LABEL, ZExt, 32, 0, 0);
    AOUT("%d label is readed by fgetc\n", label);
  }
  return 0;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_fgetc(FILE *stream, dfsan_label stream_label, dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t offset = ftell(stream);
  int ret = fgetc(stream);
  *ret_label = taint_getc(fd, offset, ret);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_fgetc_unlocked(FILE *stream, dfsan_label stream_label, dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t offset = ftell(stream);
  int ret = fgetc(stream);
  *ret_label = taint_getc(fd, offset, ret);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_getc(FILE *stream, dfsan_label stream_label, dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t offset = ftell(stream);
  int ret = getc(stream);
  *ret_label = taint_getc(fd, offset, ret);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_getc_unlocked(FILE *stream, dfsan_label stream_label,
                     dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t offset = ftell(stream);
  int ret = getc_unlocked(stream);
  *ret_label = taint_getc(fd, offset, ret);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw__IO_getc(FILE *stream, dfsan_label stream_label, dfsan_label *ret_label) {
  int fd = fileno(stream);
  off_t offset = ftell(stream);
  int ret = getc(stream);
  *ret_label = taint_getc(fd, offset, ret);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_getchar(dfsan_label *ret_label) {
  off_t offset = ftell(stdin);
  int ret = getchar();
  *ret_label = taint_getc(0, offset, ret);
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE size_t
__dfsw_mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps,
               dfsan_label pwc_label, dfsan_label s_label, dfsan_label
               n_label, dfsan_label ps_label, dfsan_label *ret_label) {
  *ret_label = 0;
  size_t ret = mbrtowc(pwc, s, n, ps);
  if (ret == (size_t)-1 || ret == (size_t)-2) return ret;
  else if (pwc != 0) {
    dfsan_label multibyte = dfsan_read_label(s, ret);
    assert(false);
    dfsan_store_label(multibyte, (void *)pwc, sizeof(wchar_t));
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE void*
__dfsw_mmap(void *start, size_t length, int prot, int flags, int fd,
            off_t offset, dfsan_label start_label, dfsan_label len_label,
            dfsan_label prot_label, dfsan_label flags_label,
            dfsan_label fd_label, dfsan_label offset_label,
            dfsan_label *ret_label) {
  void *ret = mmap(start, length, prot, flags, fd, offset);
  if (ret != MAP_FAILED) {
    off_t fsize = taint_get_file(fd);
    if (fsize) {
      AOUT("mmap tainted file at addr %p, offset: %ld, length %lu \n",
           ret, offset, length);
      size_t tainted_length = (offset + length) > fsize ? (fsize - offset)
                                                        : length;
      for (size_t i = 0; i < tainted_length; i++)
        dfsan_set_label(get_label_for(fd, offset + i), (char *)ret + i, 1);
      for (size_t i = tainted_length; i < length; i++)
        dfsan_set_label(-1, (char *)ret + i, 1);
    } else {
      dfsan_set_label(0, ret, length);
    }
  }
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_munmap(void *addr, size_t length, dfsan_label addr_label,
              dfsan_label length_label, dfsan_label *ret_label) {
  // clear sth
  AOUT("munmap, addr %p, length %lu \n", addr, length);
  int ret = munmap(addr, length);
  if (!ret) dfsan_set_label(0, addr, length);
  *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE off_t
__dfsw_lseek(int fd, off_t offset, int whence, dfsan_label fd_label,
             dfsan_label offset_label, dfsan_label whence_label,
             dfsan_label *ret_label) {
  off_t ret = lseek(fd, offset, whence);
  if (ret != (off_t)-1) {
    if (taint_get_file(fd)) {
      taint_set_offset_label(offset_label);
      if (offset_label) {
        __taint_trace_offset(offset_label, offset, sizeof(offset) * 8);
      }
    }
    *ret_label = offset_label;
  } else *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE off64_t
__dfsw_lseek64(int fd, off64_t offset, int whence, dfsan_label fd_label,
               dfsan_label offset_label, dfsan_label whence_label,
               dfsan_label *ret_label) {
  off64_t ret = lseek64(fd, offset, whence);
  if (ret != (off64_t)-1) {
    if (taint_get_file(fd)) {
      taint_set_offset_label(offset_label);
      if (offset_label) {
        __taint_trace_offset(offset_label, offset, sizeof(offset) * 8);
      }
    }
    *ret_label = offset_label;
  } else *ret_label = 0;
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_fseek(FILE *stream, long offset, int whence, dfsan_label stream_label,
             dfsan_label offset_label, dfsan_label whence_label,
             dfsan_label *ret_label) {
  int fd = fileno(stream);
  int ret = fseek(stream, offset, whence);
  *ret_label = 0;
  if (ret == 0 && taint_get_file(fd)) {
    taint_set_offset_label(offset_label);
    if (offset_label) {
      __taint_trace_offset(offset_label, offset, sizeof(offset) * 8);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_fseeko(FILE *stream, off_t offset, int whence, dfsan_label stream_label,
             dfsan_label offset_label, dfsan_label whence_label,
             dfsan_label *ret_label) {
  int fd = fileno(stream);
  int ret = fseeko(stream, offset, whence);
  *ret_label = 0;
  if (ret == 0 && taint_get_file(fd)) {
    taint_set_offset_label(offset_label);
    if (offset_label) {
      __taint_trace_offset(offset_label, offset, sizeof(offset) * 8);
    }
  }
  return ret;
}

SANITIZER_INTERFACE_ATTRIBUTE int
__dfsw_fseeko64(FILE *stream, off64_t offset, int whence, dfsan_label stream_label,
             dfsan_label offset_label, dfsan_label whence_label,
             dfsan_label *ret_label) {
  int fd = fileno(stream);
  int ret = fseeko64(stream, offset, whence);
  *ret_label = 0;
  if (ret == 0 && taint_get_file(fd)) {
    taint_set_offset_label(offset_label);
    if (offset_label) {
      __taint_trace_offset(offset_label, offset, sizeof(offset) * 8);
    }
  }
  return ret;
}

}  // extern "C"
