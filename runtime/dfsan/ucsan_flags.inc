//===-- ucsan_flags.inc -----------------------------------------*- C++ -*-===//
//
// UCSan runtime flags.
//
//===----------------------------------------------------------------------===//
//
// UCSan runtime flags are defined here using the UCSAN_FLAG macro.
//
//===----------------------------------------------------------------------===//

#ifndef UCSAN_FLAG
#error "Define UCSAN_FLAG prior to including this file!"
#endif

UCSAN_FLAG(bool, debug, false,
           "Enable debug output for UCSan runtime.")

UCSAN_FLAG(bool, trace_object, false,
           "Trace object lazy initializations.")

UCSAN_FLAG(bool, checker_nullderef, false,
           "Check for null pointer dereferences.")

UCSAN_FLAG(bool, no_upcast, false,
           "Disallow upcast (negative offset in container_of).")

UCSAN_FLAG(bool, trace_bounds, false,
           "Enable bounds tracking and exit on OOB/UAF detection.")

UCSAN_FLAG(bool, no_enlarge, false,
           "Disallow object enlargement beyond initial size.")

UCSAN_FLAG(int, max_obj_size, 0,
           "Maximum object size for lazy initialization "
           "(0 = use UCSAN_OBJECT_SIZE_LIMIT).")

UCSAN_FLAG(const char *, input_file, "",
           "Input file containing seed objects.")

UCSAN_FLAG(bool, disable_loop_bounds, false,
           "Disable loop unrolling bounds.")

UCSAN_FLAG(bool, check_memleak, false,
           "Check for memory leaks.")