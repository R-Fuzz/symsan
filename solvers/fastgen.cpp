/*
  The code is for out-of-process constraints solving with fastgen.

   ------------------------------------------------

   Written by Chengyu Song <csong@cs.ucr.edu> and
              Ju Chen <jchen757@ucr.edu>

   Copyright 2021-2024 UC Riverside. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */
#include <climits>

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "dfsan/dfsan.h"

using namespace __dfsan;

static uint32_t __instance_id;
static uint32_t __session_id;
static int __pipe_fd;

SANITIZER_WEAK_ATTRIBUTE uint8_t* __afl_area_ptr=nullptr;

// filter?
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uint32_t __taint_trace_callstack;
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uint32_t __taint_trace_callstack_addr;

static inline void __handle_new_state(uint32_t cid, void *addr, uint8_t result) {
  uint16_t flags = 0;

  long global_min_dist = -2;
  long local_min_dist = -2;
  unsigned long counter = 0;
  if (__afl_area_ptr){
    counter = *(unsigned long*)(__afl_area_ptr+MAP_SIZE+16);
    if (counter){
      flags |= F_HAS_DISTANCE;
      local_min_dist = (long)(*(unsigned long*)(__afl_area_ptr+MAP_SIZE+8));
    }
    global_min_dist = (long)*(unsigned long*)(__afl_area_ptr+MAP_SIZE);
    *(unsigned long*)(__afl_area_ptr+MAP_SIZE+8) = INT_MAX;
    *(unsigned long*)(__afl_area_ptr+MAP_SIZE+16) = 0;
  }
  AOUT("pc: 0x%x, global distance: %llu, avg distance: %llu \n", (uptr)addr, global_min_dist, local_min_dist);

  mazerunner_msg mmsg = {
    .flags = flags,
    .id = cid,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack_addr,
    .global_min_dist = global_min_dist,
    .local_min_dist = local_min_dist
  };
  internal_write(__pipe_fd, &mmsg, sizeof(mmsg));
}

static inline void __solve_cond(dfsan_label label, uint8_t result, uint8_t add_nested,
                                uint32_t cid, void *addr) {

  if (__pipe_fd < 0)
    return;

  uint16_t flags = 0;
  if (add_nested) flags |= F_ADD_CONS;
  // send info
  pipe_msg msg = {
    .msg_type = cond_type,
    .flags = flags,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .id = cid,
    .label = label,
    .result = result
  };
  if (internal_write(__pipe_fd, &msg, sizeof(msg)) < 0) {
    Die();
  }
  // mazerunner msg
  __handle_new_state(cid, addr, result);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_cmp(dfsan_label op1, dfsan_label op2, uint32_t size, uint32_t predicate,
                  uint64_t c1, uint64_t c2, uint32_t cid) {
  if ((op1 == 0 && op2 == 0))
    return;

  void *addr = __builtin_return_address(0);

  AOUT("solving cmp: %u %u %u %d %llu %llu 0x%x @%p\n",
       op1, op2, size, predicate, c1, c2, cid, addr);

  // save info to a union table slot
  uint8_t r = get_const_result(c1, c2, predicate);
  dfsan_label temp = dfsan_union(op1, op2, (predicate << 8) | ICmp, size, c1, c2);

  // add nested only for matching cases
  __solve_cond(temp, r, r, cid, addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_cond(dfsan_label label, uint8_t r, uint32_t cid) {
  if (label == 0) {
      return;
  }

  void *addr = __builtin_return_address(0);
  AOUT("solving cond: %u %u 0x%x 0x%x %p\n",
       label, r, __taint_trace_callstack, cid, addr);
  // always add nested
  __solve_cond(label, r, 1, cid, addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_indcall(dfsan_label label) {
  if (label == 0)
    return;

  AOUT("tainted indirect call target: %d\n", label);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_gep(dfsan_label ptr_label, uint64_t ptr, dfsan_label index_label, int64_t index,
                  uint64_t num_elems, uint64_t elem_size, int64_t current_offset) {
  if (index_label == 0)
    return;

  void *addr = __builtin_return_address(0);

  AOUT("tainted GEP index: %lld = %d, ne: %lld, es: %lld, offset: %lld\n",
      index, index_label, num_elems, elem_size, current_offset);

  if (__pipe_fd < 0)
    return;

  // send gep info, in two pieces
  pipe_msg msg = {
    .msg_type = gep_type,
    .flags = 0,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .label = index_label, // just in case
    .result = (uint64_t)index
  };

  if (internal_write(__pipe_fd, &msg, sizeof(msg)) < 0) {
    Die();
  }

  gep_msg gmsg = {
    .ptr_label = ptr_label,
    .index_label = index_label,
    .ptr = ptr,
    .index = index,
    .num_elems = num_elems,
    .elem_size = elem_size,
    .current_offset = current_offset
  };

  // FIXME: assuming single writer so msg will arrive in the same order
  if (internal_write(__pipe_fd, &gmsg, sizeof(gmsg)) < 0) {
    Die();
  }

  return; 
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_offset(dfsan_label offset_label, s64 offset, unsigned size) {
  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_memcmp(dfsan_label label) {
  if (label == 0)
    return;

  void *addr = __builtin_return_address(0);
  dfsan_label_info *info = get_label_info(label);

  AOUT("tainted memcmp: %d, size: %d\n", label, info->size);

  if (__pipe_fd < 0)
    return;

  uint16_t has_content = 1;
  // if both operands are symbolic, skip sending the content
  if (info->l1 != CONST_LABEL && info->l2 != CONST_LABEL)
    has_content = 0;

  pipe_msg msg = {
    .msg_type = memcmp_type,
    .flags = has_content,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .label = label, // just in case
    .result = (uint64_t)info->size
  };

  if (internal_write(__pipe_fd, &msg, sizeof(msg)) < 0) {
    Die();
  }

  if (!has_content)
    return;

  size_t msg_size = sizeof(memcmp_msg) + info->size;
  memcmp_msg *mmsg = (memcmp_msg*)__builtin_alloca(msg_size);
  mmsg->label = label;
  internal_memcpy(mmsg->content, (void*)info->op1.i, info->size); // concrete oprand is always in op1

  // FIXME: assuming single writer so msg will arrive in the same order
  if (internal_write(__pipe_fd, mmsg, msg_size) < 0) {
    Die();
  }

  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_fini(){

  long global_min_dist = -2;
  if (__afl_area_ptr){
    global_min_dist = (long)*(unsigned long*)(__afl_area_ptr+MAP_SIZE);
  }
  AOUT("global min distance: %llu\n", global_min_dist);

  pipe_msg msg = {
    .msg_type = fini_type,
    .flags = 0,
    .instance_id = 0,
    .addr = (uptr)0,
    .context = 0,
    .label = 0,
    .result = (uint64_t)global_min_dist
  };

  internal_write(__pipe_fd, &msg, sizeof(msg));
  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_memerr(dfsan_label ptr_label, uptr ptr, dfsan_label size_label,
                     uint64_t size, uint16_t flag, void *addr) {
  if (ptr_label == 0 && size_label == 0)
    return;

  if (__pipe_fd < 0)
    return;

  uint64_t r = 0;
  switch(flag) {
    case F_MEMERR_UAF: r = ptr; break;
    case F_MEMERR_OLB: r = ptr; break;
    case F_MEMERR_OUB: r = ptr + size; break;
    case F_MEMERR_UBI: r = ptr; break;
    default: return;
  }

  pipe_msg msg = {
    .msg_type = memerr_type,
    .flags = flag,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .label = ptr_label, // just in case
    .result = r
  };

  __taint_trace_fini();
  if (internal_write(__pipe_fd, &msg, sizeof(msg)) < 0) {
    Die();
  }
}

extern "C" void InitializeSolver() {
  __instance_id = flags().instance_id;
  __session_id = flags().session_id;
  __pipe_fd = flags().pipe_fd;
}
