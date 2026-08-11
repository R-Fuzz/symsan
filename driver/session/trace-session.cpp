/*
  symsan::TraceSession -- the shared event pump.

  Every SymSan front-end has to do the same thing: launch the instrumented
  target, then read a stream of packed messages off its event pipe and decode
  the variable-length ones (gep_msg, memcmp_msg payloads).  That loop used to be
  copy-pasted into driver/fgtest.cpp, driver/afltest.cpp, driver/aflpp/symsan.cpp
  and the Python binding, and the copies had already drifted apart.  This is the
  single implementation they can all share.

  (c) 2023 - 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#include "session.h"

// launch.h has no extern "C" guard of its own, matching how the other drivers
// (driver/afltest.cpp, driver/fgtest.cpp) include it
extern "C" {
#include "launch.h"
}

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <stdexcept>
#include <string>
#include <vector>

using namespace __dfsan;

#define SYMSAN_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace {

/// Base of the union table, as returned by symsan_init().  This has to be a
/// file-global rather than a TraceSession member because the RGD solvers reach
/// it through the free function __dfsan::get_label_info() -- see the call at
/// solvers/i2s-solver.cpp:910.  That is also why only one session may exist per
/// process; the launcher has the same restriction for its own reasons.
dfsan_label_info *g_label_info = nullptr;

/// Number of entries in the union table, i.e. one past the largest valid label.
size_t g_max_label = 0;

/// Set once a TraceSession has been constructed, so that a second one fails
/// loudly instead of silently stomping the launcher's global config.
bool g_session_alive = false;

void warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void warn(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  fprintf(stderr, "[symsan] ");
  vfprintf(stderr, fmt, args);
  va_end(args);
}

} // namespace

// The one definition of get_label_info.  Front-ends used to each provide their
// own (driver/afltest.cpp and driver/aflpp/symsan.cpp both carried a copy, both
// marked FIXME); linking against this library replaces them.
dfsan_label_info* __dfsan::get_label_info(dfsan_label label) {
  if (SYMSAN_UNLIKELY(label >= g_max_label)) {
    throw std::out_of_range("label too large " + std::to_string(label));
  }
  return &g_label_info[label];
}

namespace symsan {

void set_label_info_base(void *base, size_t uniontable_size) {
  g_label_info = (dfsan_label_info *)base;
  g_max_label = uniontable_size / sizeof(dfsan_label_info);
}

TraceSession::TraceSession()
    : label_info_(nullptr), uniontable_size_(0), timeout_ms_(0),
      configured_(false), num_events_(0) {
  if (g_session_alive) {
    throw std::runtime_error(
        "only one symsan::TraceSession may exist per process "
        "(the launcher keeps its configuration in a file-global)");
  }
  g_session_alive = true;
}

TraceSession::~TraceSession() {
  if (label_info_) {
    symsan_destroy();
    label_info_ = nullptr;
    g_label_info = nullptr;
    g_max_label = 0;
  }
  g_session_alive = false;
}

void *TraceSession::init(const char *symsan_bin, size_t uniontable_size) {
  if (label_info_) {
    warn("TraceSession::init called twice\n");
    return label_info_;
  }

  void *base = symsan_init(symsan_bin, uniontable_size);
  if (base == (void *)-1 || base == nullptr) {
    warn("failed to map union table: %s\n", strerror(errno));
    return nullptr;
  }

  label_info_ = base;
  uniontable_size_ = uniontable_size;
  set_label_info_base(base, uniontable_size);
  return base;
}

int TraceSession::configure(const TraceConfig &config) {
  if (!label_info_) {
    warn("TraceSession::configure called before init\n");
    return -1;
  }
  if (config.args.empty()) {
    warn("TraceSession::configure called with no args\n");
    return -1;
  }

  // NOTE: the launcher strdup()s everything we hand it and does not free the
  // previous values, so calling configure() repeatedly leaks a little.  It is
  // meant to be called once, before the first run(); front-ends that learn
  // their argv late (the AFL++ mutator) call it exactly once, lazily.
  int ret = symsan_set_input(config.input.c_str());
  if (ret != 0) return ret;

  std::vector<char *> argv;
  argv.reserve(config.args.size());
  for (const auto &arg : config.args) {
    // symsan_set_args copies each string, so pointing into config is fine
    argv.push_back(const_cast<char *>(arg.c_str()));
  }
  ret = symsan_set_args((int)argv.size(), argv.data());
  if (ret != 0) return ret;

  symsan_set_debug(config.debug);
  symsan_set_bounds_check(config.bounds_check);
  symsan_set_solve_ub(config.solve_ub);
  symsan_set_exit_on_memerror(config.exit_on_memerror);
  symsan_set_trace_file_size(config.trace_file_size);
  symsan_set_force_stdin(config.force_stdin);
  symsan_set_forkserver(config.forkserver);

  // Not fatal if it fails: the launcher then makes a default-sized map on the
  // first run, the target refuses to start if that is too small, and either way
  // the diagnosis belongs to the run.
  if (config.cov_map_size != 0) {
    int ret = symsan_set_cov_map_size(config.cov_map_size);
    if (ret != 0) {
      warn("failed to size the coverage map at %zu bytes (%d)\n",
           config.cov_map_size, ret);
    }
  }

  timeout_ms_ = config.timeout_ms;
  configured_ = true;
  return 0;
}

trace_result_t TraceSession::run(int fd, EventHandler &handler) {
  if (!label_info_ || !configured_) {
    warn("TraceSession::run called before init/configure\n");
    return TRACE_NOT_READY;
  }

  if (symsan_run(fd) != 0) {
    warn("failed to launch target: %s\n", strerror(errno));
    return TRACE_LAUNCH_ERROR;
  }

  pipe_msg msg;
  gep_msg gmsg;
  std::vector<uint8_t> payload;
  bool timedout = false;
  struct timeval start, end;
  gettimeofday(&start, NULL);

  num_events_ = 0;

  while (symsan_read_event(&msg, sizeof(msg), timeout_ms_) == sizeof(msg)) {
    switch (msg.msg_type) {
      // conditional branch
      case cond_type:
        handler.on_cond(msg);
        break;

      case gep_type:
        if (symsan_read_event(&gmsg, sizeof(gmsg), 0) != sizeof(gmsg)) {
          warn("failed to receive gep msg: %s\n", strerror(errno));
          break;
        }
        // double check
        if (msg.label != gmsg.index_label) {
          warn("incorrect gep msg: %d vs %d\n", msg.label, gmsg.index_label);
          break;
        }
        handler.on_gep(msg, gmsg);
        break;

      case memcmp_type: {
        // flags = 0 means there is no content to read: either both operands are
        // symbolic, or the compared size is zero.  See the producer at
        // backend/fastgen.cpp:376-380 -- msg.flags is authoritative, and
        // re-deriving it from the label info (as driver/aflpp/symsan.cpp did)
        // misses the size-zero case and desynchronizes the pipe.
        if (!msg.flags) {
          handler.on_memcmp(msg, nullptr, 0);
          break;
        }
        // drain the payload first, so that a malformed message costs us this
        // one event rather than the rest of the stream
        size_t msg_size = sizeof(memcmp_msg) + msg.result;
        payload.resize(msg_size);
        memcmp_msg *mmsg = (memcmp_msg *)payload.data();
        if (symsan_read_event(mmsg, msg_size, 0) != (ssize_t)msg_size) {
          warn("failed to receive memcmp msg: %s\n", strerror(errno));
          break;
        }
        if (msg.label == 0 || msg.label >= g_max_label) {
          warn("invalid memcmp label: %d\n", msg.label);
          break;
        }
        // double check
        if (msg.label != mmsg->label) {
          warn("incorrect memcmp msg: %d vs %d\n", msg.label, mmsg->label);
          break;
        }
        handler.on_memcmp(msg, mmsg->content, msg.result);
        break;
      }

      case table_type: {
        // Always carries a payload -- unlike memcmp there is no "both operands
        // symbolic" case -- so drain it before any validation, or a rejected
        // table takes the rest of the stream with it.
        size_t msg_size = sizeof(table_msg) + msg.result;
        payload.resize(msg_size);
        table_msg *tmsg = (table_msg *)payload.data();
        if (symsan_read_event(tmsg, msg_size, 0) != (ssize_t)msg_size) {
          warn("failed to receive table msg: %s\n", strerror(errno));
          break;
        }
        // double check: the runtime derives result from the table geometry
        if (tmsg->num_elems * tmsg->elem_size != msg.result) {
          warn("incorrect table msg: %lu x %lu vs %lu\n", tmsg->num_elems,
               tmsg->elem_size, msg.result);
          break;
        }
        handler.on_table(msg, *tmsg, tmsg->content, msg.result);
        break;
      }

      case add_constraint_type:
        handler.on_add_constraint(msg);
        break;

      case memerr_type:
        handler.on_memerr(msg);
        break;

      case minimize_type:
        handler.on_minimize(msg);
        break;

      default:
        handler.on_other(msg);
        break;
    }

    // naive deadloop detection
    num_events_ += 1;
    // only meaningful when a timeout was configured; timeout_ms_ == 0 means
    // "block indefinitely", and the comparison below would then fire after a
    // single second of legitimate work
    if (SYMSAN_UNLIKELY((num_events_ & 0xffffe000) != 0) && timeout_ms_ != 0) {
      gettimeofday(&end, NULL);
      if ((end.tv_sec - start.tv_sec) * 10 > (long)timeout_ms_) {
        // allow 100x slowdown, sec * 1000 > ms * 100
        warn("possible deadloop, break\n");
        timedout = true;
        break;
      }
    }
  }

  if (timedout) {
    // kill the symsan process
    symsan_terminate();
    return TRACE_TIMEOUT;
  }

  return TRACE_OK;
}

int TraceSession::terminate() {
  return symsan_terminate();
}

int TraceSession::get_exit_status(int *status) {
  return symsan_get_exit_status(status);
}

}; // namespace symsan
