/*
  Shared session code for SymSan front-ends.

  A front-end (the AFL++ custom mutator, a LibAFL stage, a Python driver, ...)
  needs the same two things: pump events out of a symsan-instrumented target,
  and turn those events into solved inputs.  They are split across two headers
  so that neither front-ends nor solver stacks have to take the other:

    session.h    symsan::TraceSession -- the event pump.  Mechanism only, and
                 deliberately free of any solver-stack types, so that a Z3-TS
                 or thoroupy front-end can reuse it as-is.
    concolic.h   rgd::ConcolicSession -- the RGD policy (parse, queue, solve)
                 layered on top, as an EventHandler.

  (c) 2023 - 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#pragma once

#include "dfsan/dfsan.h"

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace symsan {

// the wire format of the event pipe, defined in runtime/dfsan/dfsan.h
using __dfsan::pipe_msg;
using __dfsan::gep_msg;
using __dfsan::memcmp_msg;
using __dfsan::table_msg;

/// Install the union table that __dfsan::get_label_info() resolves against.
///
/// get_label_info() is a free function because that is how the RGD solvers
/// reach the union table (see solvers/i2s-solver.cpp), which historically forced
/// every front-end to define it -- driver/afltest.cpp and driver/aflpp/symsan.cpp
/// each carried a copy.  Linking against symsan-session provides the one
/// definition; this is how you point it at the table symsan_init() returned.
///
/// TraceSession::init() calls this for you.  Front-ends that drive the launcher
/// directly must call it themselves, or the solvers fault on the first lookup.
void set_label_info_base(void *base, size_t uniontable_size);

/// Runtime options for a symsan-instrumented target.  These map onto the
/// symsan_set_* setters in launch.h, which the launcher packs into the
/// TAINT_OPTIONS environment variable of the child.
struct TraceConfig {
  /// "stdin", a file path, or "tcp@host:port" / "udp@..." / "unix@..."
  std::string input;
  /// argv for the child; argv[0] is conventionally the target path
  std::vector<std::string> args;
  /// per-run timeout in milliseconds passed to the first read of each event;
  /// 0 means block indefinitely
  unsigned timeout_ms = 0;
  bool debug = false;
  bool bounds_check = false;
  bool solve_ub = false;
  bool exit_on_memerror = true;
  bool trace_file_size = false;
  bool force_stdin = false;
  /// spawn the target once as a fork server and fork per input, instead of
  /// exec'ing it again for every run.  Ignored unless the input is a file, and
  /// silently ignored if the target's backend has no fork server; see
  /// symsan_set_forkserver() in launch.h.
  bool forkserver = false;
};

/// Outcome of a single TraceSession::run().
enum trace_result_t {
  /// the target ran to completion and the event pipe reached EOF
  TRACE_OK = 0,
  /// the deadloop guard fired; the target has been terminated
  TRACE_TIMEOUT,
  /// the target could not be launched
  TRACE_LAUNCH_ERROR,
  /// run() was called before init()/configure()
  TRACE_NOT_READY,
};

/// Callbacks invoked by TraceSession::run() for each event read from the
/// target.  Every callback defaults to a no-op, so a front-end overrides only
/// what it cares about.
///
/// The session validates each message before dispatching: a gep event is only
/// delivered once its gep_msg has been read and its index_label matches, and a
/// memcmp event only once its payload has been read and its label matches.
/// Malformed events are dropped with a diagnostic and never reach the handler.
/// Note that dropping still consumes the payload, so that one bad event costs
/// that event rather than desynchronizing the rest of the stream.
class EventHandler {
public:
  virtual ~EventHandler() {}

  /// a conditional branch (cond_type)
  virtual void on_cond(const pipe_msg &msg) { (void)msg; }

  /// a getelementptr with a symbolic index (gep_type)
  virtual void on_gep(const pipe_msg &msg, const gep_msg &gmsg) {
    (void)msg; (void)gmsg;
  }

  /// a memcmp-family call (memcmp_type).  @p content points at the concrete
  /// operand and is valid only for the duration of the call; it is nullptr
  /// (with @p size 0) when the runtime sent no payload, i.e. when both
  /// operands were symbolic or the compared size was zero.
  virtual void on_memcmp(const pipe_msg &msg, const uint8_t *content, size_t size) {
    (void)msg; (void)content; (void)size;
  }

  /// the contents of a read-only global lookup table (table_type), shipped once
  /// per table per trace because the solver runs in another process.  @p content
  /// points at @p size bytes valid only for the duration of the call; the table
  /// is identified by @p tmsg.ptr, not by a label.
  virtual void on_table(const pipe_msg &msg, const table_msg &tmsg,
                        const uint8_t *content, size_t size) {
    (void)msg; (void)tmsg; (void)content; (void)size;
  }

  /// an explicit constraint, typically from a symbolic offset (add_constraint_type)
  virtual void on_add_constraint(const pipe_msg &msg) { (void)msg; }

  /// a memory error (memerr_type); msg.flags is an F_MEMERR_* bitmask
  virtual void on_memerr(const pipe_msg &msg) { (void)msg; }

  /// a label to minimize, e.g. an allocation size (minimize_type)
  virtual void on_minimize(const pipe_msg &msg) { (void)msg; }

  /// any message type the session does not decode itself, including the
  /// thoroupy-specific ones (exit_type, loop_type, bb_type, event_type, gv_type)
  virtual void on_other(const pipe_msg &msg) { (void)msg; }
};

/// The event pump.  Wraps the C launcher in launch.h and drives the read/decode
/// loop that every front-end would otherwise write by hand.
///
/// Threading/lifetime: the launcher keeps its configuration in a file-global
/// (g_config in driver/launcher/launch.c), so a process can host exactly one
/// TraceSession.  Constructing a second one while the first is alive is a hard
/// error.  This is not a limitation in practice -- LibAFL and AFL++ both scale
/// by forking separate fuzzer processes, and the union-table shared-memory name
/// already includes getpid().
class TraceSession {
public:
  TraceSession();
  ~TraceSession();

  TraceSession(const TraceSession &) = delete;
  TraceSession &operator=(const TraceSession &) = delete;

  /// Map the union table and prepare the launcher.
  ///
  /// Returns the mapped union-table base rather than keeping it private,
  /// because the AST parsers are constructed over it (see rgd::RGDAstParser).
  /// Also installs the process-wide __dfsan::get_label_info that the RGD
  /// solvers link against, so front-ends no longer define it themselves.
  ///
  /// @return the union table base, or nullptr on failure
  void *init(const char *symsan_bin, size_t uniontable_size);

  /// Apply runtime options.  Separate from init() because some front-ends only
  /// learn their argv after initialization (the AFL++ mutator builds it from
  /// afl->argv on the first fuzz round).
  ///
  /// Intended to be called once, before the first run().  Calling it again does
  /// take effect, but leaks the previous input/argv strings inside the launcher,
  /// which strdup()s them without freeing the old ones.
  int configure(const TraceConfig &config);

  /// Launch the target and pump events into @p handler until the pipe reaches
  /// EOF or the deadloop guard fires.
  ///
  /// @param fd file descriptor holding the input, rewound and dup'd onto the
  ///           child's stdin when the input mode is "stdin"
  trace_result_t run(int fd, EventHandler &handler);

  /// Kill the target, if still running.
  int terminate();

  /// Retrieve the target's exit status.
  int get_exit_status(int *status);

  /// Number of events read during the last run().
  uint64_t num_events() const { return num_events_; }

  /// The union table base returned by init(), or nullptr.
  void *label_info() const { return label_info_; }

private:
  void *label_info_;
  size_t uniontable_size_;
  unsigned timeout_ms_;
  bool configured_;
  uint64_t num_events_;
};

}; // namespace symsan
