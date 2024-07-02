//===-- dfsan_flags.inc -----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// DFSan runtime flags.
//
//===----------------------------------------------------------------------===//
#ifndef DFSAN_FLAG
# error "Define DFSAN_FLAG prior to including this file!"
#endif

// DFSAN_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

DFSAN_FLAG(bool, warn_unimplemented, true,
           "Whether to warn on unimplemented functions.")
DFSAN_FLAG(bool, warn_nonzero_labels, false,
           "Whether to warn on unimplemented functions.")
DFSAN_FLAG(
    bool, strict_data_dependencies, true,
    "Whether to propagate labels only when there is an obvious data dependency"
    "(e.g., when comparing strings, ignore the fact that the output of the"
    "comparison might be data-dependent on the content of the strings). This"
    "applies only to the custom functions defined in 'custom.c'.")
DFSAN_FLAG(const char *, dump_labels_at_exit, "", "The path of the file where "
                                                  "to dump the labels when the "
                                                  "program terminates.")
DFSAN_FLAG(const char *, taint_file, "", "The path of the file which "
                                         "will be tainted.")
DFSAN_FLAG(const char *, taint_socket, "", "The network source which "
                                          "will be tainted.")
DFSAN_FLAG(const char *, union_table, "union.txt", "union table.")
DFSAN_FLAG(int, shm_fd, -1, "shared union table.")
DFSAN_FLAG(int, pipe_fd, -1, "communication fd.")
DFSAN_FLAG(bool, trace_bounds, false, "trace bounds info.")
DFSAN_FLAG(bool, exit_on_memerror, true, "terminate on memory error.")
DFSAN_FLAG(bool, debug, false, "Print debug output.")
DFSAN_FLAG(const char *, output_dir, ".", "The path for output file.")
DFSAN_FLAG(int, instance_id, 0, "instance id for multi-instance fuzzing.")
DFSAN_FLAG(int, session_id, 0, "session/round id.")
