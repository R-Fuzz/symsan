/*
  The code is for out-of-process constraints solving with thoroupy.

   ------------------------------------------------

   Written by Chengyu Song <csong@cs.ucr.edu>
              Ju Chen <jchen757@ucr.edu> and
              Mingjun Yin <myin013@ucr.edu>

   Copyright 2021-2026 UC Riverside. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include "solver_common.h"
#include "dfsan/ucsan.h"
#include <cstdio>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <malloc.h>

#define __handle_segfualt__
#define LOOP_COUNTER_SIZE 1024

using namespace __dfsan;
using __ucsan::ucsan_tainted;
using __ucsan::ucsan_flags;

struct ucsan_ticket {
  u32 msg_type;
  u32 instance_id;
  u32 session_id;
  u64 payload_size;
  u8 payload[0];
} __attribute__((packed));

static int __loop_threshold = 20;
int __stack_threshold = 20;
static uint32_t __loop_counter[LOOP_COUNTER_SIZE];
static uint32_t __loop_bid[LOOP_COUNTER_SIZE];
static int __current_loop_depth = 0;
static int __previous_loop_depth = 0;
static int __loop_depth_stack_current[LOOP_COUNTER_SIZE];
static int __loop_depth_stack_base[LOOP_COUNTER_SIZE];
static int __loop_depth_stack_previous[LOOP_COUNTER_SIZE];
static int __loop_depth_stack_top = 0;
static int __base_loop_depth = 0;

extern void* __ucsan_null_deref_flag;

// based on https://github.com/Cyan4973/xxHash
// simplified since we only have 12 bytes info
static inline uint32_t xxhash(uint32_t h1, uint32_t h2, uint32_t h3) {
  const uint32_t PRIME32_1 = 2654435761U;
  const uint32_t PRIME32_2 = 2246822519U;
  const uint32_t PRIME32_3 = 3266489917U;
  const uint32_t PRIME32_4 =  668265263U;
  const uint32_t PRIME32_5 =  374761393U;

  #define XXH_rotl32(x,r) ((x << r) | (x >> (32 - r)))
  uint32_t h32 = PRIME32_5;
  h32 += h1 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  h32 += h2 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  h32 += h3 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  #undef XXH_rotl32

  h32 ^= h32 >> 15;
  h32 *= PRIME32_2;
  h32 ^= h32 >> 13;
  h32 *= PRIME32_3;
  h32 ^= h32 >> 16;

  return h32;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_loop_push_stack() {
  __loop_depth_stack_current[__loop_depth_stack_top] = __current_loop_depth;
  __loop_depth_stack_base[__loop_depth_stack_top] = __base_loop_depth;
  __loop_depth_stack_previous[__loop_depth_stack_top] = __previous_loop_depth;
  __base_loop_depth += __current_loop_depth;
  __current_loop_depth = 0;
  __loop_depth_stack_top++;
  AOUT("loop push stack: %u %u %u\n", __current_loop_depth, __base_loop_depth, __previous_loop_depth);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_loop_pop_stack() {
  __loop_depth_stack_top--;
  __current_loop_depth = __loop_depth_stack_current[__loop_depth_stack_top];
  __base_loop_depth = __loop_depth_stack_base[__loop_depth_stack_top];
  __previous_loop_depth = __loop_depth_stack_previous[__loop_depth_stack_top];
  AOUT("loop pop stack: %u %u %u\n", __current_loop_depth, __base_loop_depth, __previous_loop_depth);
}

#define get_nested_loop_depth() (__base_loop_depth + __current_loop_depth)

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_loop(uint32_t bid, int depth) {
  void *addr = __builtin_return_address(0);

  AOUT("loop header: %u depth: %d current: %d base: %d previous: %d, top bid = %u, @%p\n",
       bid, depth, __current_loop_depth, __base_loop_depth, __previous_loop_depth,
       __loop_bid[get_nested_loop_depth()], addr);

  if (depth > 0) {
    // loop header
    if (bid == __loop_bid[get_nested_loop_depth()]) {
      // same loop, increase the loop counter
      __loop_counter[get_nested_loop_depth()]++;
      AOUT("Increasing loop counter for loop %u, depth: %u, counter: %u\n",
           bid, __current_loop_depth, __loop_counter[get_nested_loop_depth()]);

      if (__loop_counter[get_nested_loop_depth()] > __loop_threshold) {
        AOUT("loop threshold reached, exiting\n");
        internal__exit(exit_reason::REASON_LOOP_OOB);
      }
    } else {
      // different loop
      if (depth + __base_loop_depth > __previous_loop_depth) { // enter a new loop
        // assert(depth == __current_loop_depth + 1);
        __current_loop_depth += 1; // update the current loop depth
        __loop_counter[get_nested_loop_depth()] = 0; // reset the loop counter
        __loop_bid[get_nested_loop_depth()] = bid;

        __previous_loop_depth = depth + __base_loop_depth;
        AOUT("enter new loop: %u depth: %u\n", bid, __current_loop_depth);
      } else {
        AOUT("WARNING: loop depth %d is less than current loop depth %d\n",
             depth + __base_loop_depth, __previous_loop_depth);
        internal__exit(exit_reason::REASON_LOOP_OOB);
      }
    }
  } else if (__current_loop_depth + depth >= 0) {
    // exit a loop
    if (bid == __loop_bid[get_nested_loop_depth()]) {
      // exiting the current loop
      __current_loop_depth += depth;
      __previous_loop_depth += depth;
      AOUT("exit to outer loop: %u depth: %u\n", bid, __current_loop_depth);
    } else {
      AOUT("WARNING: loop exit bid %u does not match current loop bid %u\n",
           bid, __loop_bid[get_nested_loop_depth()]);
      return;
    }
  } else {
    return; // no loop to exit
  }

  // send loop info
  if (__pipe_fd < 0)
    return;

  pipe_msg msg = {
    .msg_type = loop_type,
    .flags = 0,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .id = bid,
    .label = 0,
    .result = (uint64_t)get_nested_loop_depth()
  };

  if (internal_write(__pipe_fd, &msg, sizeof(msg)) < 0) {
    Die();
  }

  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_event_addr(dfsan_label label, uint32_t event_id, uint64_t info,
                         void* addr, uint32_t info2) {
  AOUT("event: %u %u %llu @%p\n", label, event_id, info, addr);

  if (__pipe_fd < 0)
    return;

  pipe_msg msg = {
    .msg_type = event_type,
    .flags = 0,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = event_id,
    .id = info2,
    .label = label,
    .result = info
  };

  if (internal_write(__pipe_fd, &msg, sizeof(msg)) < 0) {
    Die();
  }

  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__dfsan_trace_bb(uint32_t function_index, uint64_t bb_index) {
  AOUT("bb: %u %llu\n", function_index, bb_index);

  if (__pipe_fd < 0)
    return;

    pipe_msg msg = {
    .msg_type = bb_type,
    .addr = (uint64_t)__builtin_return_address(0),
    .id = function_index,
    .result = bb_index,
  };

  if (internal_write(__pipe_fd, &msg, sizeof(msg)) < 0) {
    Die();
  }

  return;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_global_var(dfsan_label label, uint64_t size, void *gv) {
  if (label == 0)
    return;

  AOUT("global var: %d, size: %lu @%p\n", label, size, gv);

  if (__pipe_fd < 0)
    return;

  dfsan_label_info *info = get_label_info(label);
  uptr offset = (uptr)info->op1.i; // offset is recorded in op1

  pipe_msg msg = {
    .msg_type = gv_type,
    .flags = 0,
    .instance_id = __instance_id,
    .addr = offset,
    .context = __taint_trace_callstack,
    .label = label, // just in case
    .result = size
  };

  if (internal_write(__pipe_fd, &msg, sizeof(msg)) < 0) {
    Die();
  }
  // FIXME: assuming single writer so msg will arrive in the same order
  if (internal_write(__pipe_fd, gv, size) < 0) {
    Die();
  }

  return;
}

static void segfault_handler(int sig, siginfo_t *si, void *unused)
{
  if (__ucsan_null_deref_flag) {
      AOUT("Poential Null dereference detected\n");
      __taint_trace_event_addr(0, EVENT_NULL_DEREF, 0, __ucsan_null_deref_flag, 0);
      internal__exit(EVENT_NULL_DEREF);
  }
  AOUT("Segmentation fault at address: %p, access type: %d\n", si->si_addr, si->si_code);
  Die();
}

void RegisterSegFault () {
#ifdef __handle_segfualt__
  struct sigaction sa;

  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = segfault_handler;
  if (sigaction(SIGSEGV, &sa, NULL) == -1)
    Die();
#endif
}

extern "C" void InitializeUCSanSolver() {

  RegisterSegFault();

  // initialize pipe fds
  if (internal_strcmp(flags().pipe_name, "") != 0) {
    __pipe_fd = internal_open(flags().pipe_name, O_WRONLY);
  } else {
    __pipe_fd = flags().pipe_fd;
  }
  // communication pipe fd can be -1, meaning no out-of-process solving
  // tracing only

  if (internal_strcmp(flags().control_pipe_name, "") != 0) {
    __control_pipe_fd = internal_open(flags().control_pipe_name, O_RDONLY);
  } else {
    __control_pipe_fd = flags().control_pipe_fd;
  }
  // control pipe fd must be valid
  if (__control_pipe_fd == -1) {
    Printf("FATAL: control_fd not set, control_pipe_fd %d, control_fd_name %s\n",
           flags().control_pipe_fd, flags().control_pipe_name);
    Die();
  }
  Printf("Thouroupy solver fork server pipe_fd: %d\n", __control_pipe_fd);

  ucsan_ticket ticket;
  uint64_t payload_size;
  char *content;
  uptr ret;
  memset(__loop_counter, 0, LOOP_COUNTER_SIZE * sizeof(uint32_t));

  // fork server loop
  while (true) {
    ret = read(__control_pipe_fd, &ticket, sizeof(ucsan_ticket));
    if (ret != sizeof(ucsan_ticket)) {
      Printf("Fork server: read ticket failed, exiting\n");
      internal__exit(1);
    }

    switch (ticket.msg_type){ // exit 
      case 0: {
        Printf("Fork server: exiting\n");
        internal__exit(0);
      }
      break;

      case 1:
      case 2: {
        AOUT("Fork server: received a new session, session id: %d, instance id: %d\n",
             ticket.session_id, ticket.instance_id);

        int pid = fork();
        if (pid == 0) { // child
          __instance_id = ticket.instance_id;
          __session_id = ticket.session_id;

          if (ticket.msg_type == 1) return; // no payload
          payload_size = ticket.payload_size;

          content = (char*)malloc(payload_size);
          if (!content) internal__exit(1);

          internal_read(__control_pipe_fd, content, payload_size);
          // free previous allocation if any
          if (ucsan_tainted.buf) free((void*)ucsan_tainted.buf);

          // parse the input content
          ucsan_tainted.load(content, payload_size);

          return; // jump out to the main function
        } else if (pid > 0) { // parent
          AOUT("Fork server: Wait for the child process\n");
          int status;
          waitpid(pid, &status, 0);
          pipe_msg msg = {
            .msg_type = exit_type,
            .flags = 0,
            .instance_id = __instance_id,
            .addr = 0,
            .context = 0,
            .label = 0,
            .result = (uint64_t)status
          };
          AOUT("Fork server: report exit status: %d\n", status);
          internal_write(__pipe_fd, &msg, sizeof(msg));
        } else {
          AOUT("Fork server: fork failed, exiting\n");
          internal__exit(1);
        }
      }
      break;

      case 3: { // adjust loop threshold
        internal_read(__control_pipe_fd, &__loop_threshold, sizeof(uint32_t));
        AOUT("Fork server: received loop threshold: %d\n", __loop_threshold);
      }
      break;

      case 4: { // adjust stack threshold
        internal_read(__control_pipe_fd, &__stack_threshold, sizeof(uint32_t));
        AOUT("Fork server: received stack threshold: %d\n", __stack_threshold);
      }
      break;
    }
  }

}
