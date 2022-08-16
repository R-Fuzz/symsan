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

// filter?
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL u32 __taint_trace_callstack;

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

static inline void __solve_cond(dfsan_label label, u8 result, u8 add_nested, void *addr) {

  u16 flags = 0;
  if (add_nested) flags |= F_ADD_CONS;

  // send info
  pipe_msg msg = {
    .msg_type = cond_type,
    .flags = flags,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .label = label,
    .result = result
  };

  internal_write(__pipe_fd, &msg, sizeof(msg));
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_cmp(dfsan_label op1, dfsan_label op2, u32 size, u32 predicate,
                  u64 c1, u64 c2) {
  if ((op1 == 0 && op2 == 0))
    return;

  void *addr = __builtin_return_address(0);

  AOUT("solving cmp: %u %u %u %d %llu %llu @%p\n", op1, op2, size, predicate, c1, c2, addr);

  // save info to a union table slot
  u8 r = get_const_result(c1, c2, predicate);
  dfsan_label temp = dfsan_union(op1, op2, (predicate << 8) | ICmp, size, c1, c2);

  // add nested only for matching cases
  __solve_cond(temp, r, r, addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_cond(dfsan_label label, u8 r) {
  if (label == 0)
    return;

  void *addr = __builtin_return_address(0);

  AOUT("solving cond: %u %u %u %p\n", label, r, __taint_trace_callstack, addr);

  // always add nested
  __solve_cond(label, r, 1, addr);
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
__taint_trace_offset(dfsan_label offset_label, s64 offset, unsigned size) {
  return;
}

extern "C" void InitializeSolver() {
  __instance_id = flags().instance_id;
  __session_id = flags().session_id;
  __pipe_fd = flags().pipe_fd;
}
