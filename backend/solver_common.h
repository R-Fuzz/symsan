/*
  Common code shared between fastgen and thoroupy solvers.

   ------------------------------------------------

   Written by Chengyu Song <csong@cs.ucr.edu> and
              Ju Chen <jchen757@ucr.edu>

   Copyright 2021-2025 UC Riverside. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef SOLVER_COMMON_H
#define SOLVER_COMMON_H

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "dfsan/dfsan.h"

using namespace __dfsan;

//===----------------------------------------------------------------------===//
// Shared Global State
//===----------------------------------------------------------------------===//

extern uint32_t __instance_id;
extern uint32_t __session_id;
extern int __pipe_fd;
extern int __control_pipe_fd;

// filter, defined in dfsan.cpp
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uint32_t __taint_trace_callstack;

//===----------------------------------------------------------------------===//
// Shared Helper Functions
//===----------------------------------------------------------------------===//

// Note: get_const_result() is defined in dfsan.h

// Send conditional branch info to solver
void __taint_send_cond(dfsan_label label, uint8_t result,
                       uint8_t add_nested, uint8_t loop_flag,
                       uint32_t cid, void *addr);

#endif // SOLVER_COMMON_H
