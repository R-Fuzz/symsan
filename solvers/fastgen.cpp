/*
  The code is for out-of-process constraints solving with fastgen.

   ------------------------------------------------

   Written by Chengyu Song <csong@cs.ucr.edu> and
              Ju Chen <jchen757@ucr.edu>

   Copyright 2021,2022 UC Riverside. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "dfsan/dfsan.h"

using namespace __dfsan;

static u32 __instance_id;
static u32 __session_id;
static int __pipe_fd;
extern "C" {
  extern u8* __afl_area_ptr;
}

// filter?
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL u32 __taint_trace_callstack;
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL u32 __taint_trace_callstack_addr;

static u8 get_const_result(u64 c1, u64 c2, u32 predicate) {
  switch (predicate) {
    case __dfsan::bveq:  return c1 == c2;
    case __dfsan::bvneq: return c1 != c2;
    case __dfsan::bvugt: return c1 > c2;
    case __dfsan::bvuge: return c1 >= c2;
    case __dfsan::bvult: return c1 < c2;
    case __dfsan::bvule: return c1 <= c2;
    case __dfsan::bvsgt: return (s64)c1 > (s64)c2;
    case __dfsan::bvsge: return (s64)c1 >= (s64)c2;
    case __dfsan::bvslt: return (s64)c1 < (s64)c2;
    case __dfsan::bvsle: return (s64)c1 <= (s64)c2;
    default: break;
  }
  return 0;
}

static inline void __solve_cond(dfsan_label label, u8 result, u8 add_nested,
                                u8 loop_flag, u32 cid, void *addr) {

  u16 flags = 0;
  if (add_nested) flags |= F_ADD_CONS;
  // set the loop flags according to branching results
  if (result) {
    // loop_flag |= 0x2; True branch for loop exit
    if (loop_flag & 0x2) flags |= F_LOOP_EXIT;
    if (loop_flag & 0x8) flags |= F_LOOP_LATCH;
  } else {
    // loop_flag |= 0x1; False branch for loop exit
    if (loop_flag & 0x1) flags |= F_LOOP_EXIT;
    if (loop_flag & 0x4) flags |= F_LOOP_LATCH;
  }

  // send info
  pipe_msg msg = {
    .msg_type = cond_type,
    .flags = flags,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .context_addr = __taint_trace_callstack_addr,
    .id = cid,
    .label = label,
    .result = result
  };

  internal_write(__pipe_fd, &msg, sizeof(msg));
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_cmp(dfsan_label op1, dfsan_label op2, u32 size, u32 predicate,
                  u64 c1, u64 c2, u32 cid) {
  if ((op1 == 0 && op2 == 0))
    return;

  void *addr = __builtin_return_address(0);

  AOUT("solving cmp: %u %u %u %d %llu %llu 0x%x @%p\n",
       op1, op2, size, predicate, c1, c2, cid, addr);

  // save info to a union table slot
  u8 r = get_const_result(c1, c2, predicate);
  dfsan_label temp = dfsan_union(op1, op2, (predicate << 8) | ICmp, size, c1, c2);

  // add nested only for matching cases
  __solve_cond(temp, r, r, 0, cid, addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_cond(dfsan_label label, u8 r, u8 flag, u32 cid) {
  if (label == 0) {
    // check for real loop loop exits
    if (!(((flag & 0x1) && !r) || ((flag & 0x2) && r)))
      return;
  }

  void *addr = __builtin_return_address(0);

  AOUT("solving cond: %u %u 0x%x 0x%x 0x%x %p\n",
       label, r, flag, __taint_trace_callstack, cid, addr);

#ifdef __x86_64__
  AOUT("BB distance: %llu, accumulated distance: %llu, counter: %llu \n", 
                    *(unsigned long*)(__afl_area_ptr+MAP_SIZE), 
                    *(unsigned long*)(__afl_area_ptr+MAP_SIZE+8), 
                    *(unsigned long*)(__afl_area_ptr+MAP_SIZE+16));
#else
  AOUT("BB distance: %u, accumulated distance: %u, counter: %u \n", 
                    *(unsigned int*)(__afl_area_ptr+MAP_SIZE), 
                    *(unsigned int*)(__afl_area_ptr+MAP_SIZE+4), 
                    *(unsigned int*)(__afl_area_ptr+MAP_SIZE+8));
#endif
  // always add nested
  __solve_cond(label, r, 1, flag, cid, addr);
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

  // send gep info, in two pieces
  pipe_msg msg = {
    .msg_type = gep_type,
    .flags = 0,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .context_addr = __taint_trace_callstack_addr,
    .id = 0,
    .label = index_label, // just in case
    .result = (u64)index
  };

  internal_write(__pipe_fd, &msg, sizeof(msg));

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
  internal_write(__pipe_fd, &gmsg, sizeof(gmsg));

  return; 
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_loop(u32 bid) {
  void *addr = __builtin_return_address(0);

  AOUT("loop header: %u @%p\n", bid, addr);

  pipe_msg msg = {
    .msg_type = loop_type,
    .flags = 0,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .context_addr = __taint_trace_callstack_addr,
    .id = bid,
    .label = 0,
    .result = 0
  };

  internal_write(__pipe_fd, &msg, sizeof(msg));

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

  pipe_msg msg = {
    .msg_type = memcmp_type,
    .flags = 0,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .context_addr = __taint_trace_callstack_addr,
    .label = label, // just in case
    .result = (u64)info->size
  };

  internal_write(__pipe_fd, &msg, sizeof(msg));

  // FIXME: memcmp msg type miss up the communication pipe
  // if both operands are symbolic, skip sending the content
  // if (info->l1 != CONST_LABEL && info->l2 != CONST_LABEL)
  //   return;

  // size_t msg_size = sizeof(memcmp_msg) + info->size;
  // memcmp_msg *mmsg = (memcmp_msg*)__builtin_alloca(msg_size);
  // mmsg->label = label;
  // internal_memcpy(mmsg->content, (void*)info->op1.i, info->size); // concrete oprand is always in op1

  // // FIXME: assuming single writer so msg will arrive in the same order
  // internal_write(__pipe_fd, mmsg, msg_size);

  return;
}

extern "C" void InitializeSolver() {
  __instance_id = flags().instance_id;
  __session_id = flags().session_id;
  __pipe_fd = flags().pipe_fd;
}
