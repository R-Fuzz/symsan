/*
  The C ABI declared in include/symsan_c.h.

  Every entry point here is forwarding plus a try/catch.  That is deliberate:
  the moment this file starts making decisions, the FFI front-ends and the C++
  front-ends can behave differently, which is exactly what putting the policy in
  driver/session/concolic-session.cpp was meant to prevent.

  (c) 2023 - 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#include "symsan_c.h"

#include "concolic.h"
#include "session.h"

#include "parse-rgd.h"
#include "solver.h"

#include <stdio.h>
#include <string.h>

#include <exception>
#include <memory>
#include <new>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// error reporting
// ---------------------------------------------------------------------------

// Thread-local so that a multi-threaded front-end does not read another
// thread's failure.  Never freed; one small buffer per thread that ever fails.
thread_local std::string g_last_error;

void set_error(const char *what) {
  g_last_error = what ? what : "unknown error";
}

/// Catch everything at the boundary: letting a C++ exception unwind through a C
/// frame into Rust is undefined behaviour, and the RGD parser does throw --
/// __dfsan::get_label_info raises std::out_of_range on a corrupt label.
///
/// A template rather than a macro so that commas in the body (`int a, b;`, a
/// braced initializer) cannot be mistaken for argument separators.
///
/// @param on_error what to return if @p f throws; also fixes the return type,
///                 so call it as guard<T>(...) when T is not deducible
template <typename T, typename F>
T guard(T on_error, F &&f) {
  try {
    return f();
  } catch (const std::exception &e) {
    set_error(e.what());
    return on_error;
  } catch (...) {
    set_error("unknown C++ exception");
    return on_error;
  }
}

/// Same, for the void-returning entry points.
template <typename F>
void guard_void(F &&f) {
  try {
    f();
  } catch (const std::exception &e) {
    set_error(e.what());
  } catch (...) {
    set_error("unknown C++ exception");
  }
}

// ---------------------------------------------------------------------------
// helpers shared by L1 and L2
// ---------------------------------------------------------------------------

/// Copy a task-id vector out to the caller's fixed-size array.  Returns how
/// many were written, which saturates at cap -- the header tells callers that a
/// full array means ids may have been dropped.
int copy_task_ids(const std::vector<uint64_t> &tasks, uint64_t *out, size_t cap) {
  size_t n = tasks.size() < cap ? tasks.size() : cap;
  if (out && n) {
    memcpy(out, tasks.data(), n * sizeof(uint64_t));
  }
  return (int)n;
}

} // namespace

// ---------------------------------------------------------------------------
// the opaque handles
// ---------------------------------------------------------------------------

/// L1 context.  Bundles the parser with its solver ladder because a task id is
/// only meaningful to the parser that minted it, so splitting them across two
/// handles would only create a way to pair them up wrongly.
struct symsan_rgd {
  std::unique_ptr<rgd::RGDAstParser> parser;
  std::vector<std::shared_ptr<rgd::Solver>> solvers;
};

/// L2 handle.  A struct rather than a typedef so the header can keep it opaque.
struct symsan_session {
  rgd::ConcolicSession session;
  bool initialized = false;
};

namespace {

/// Enforces the one-session-per-process rule from launch.c's file-global
/// config.  Not atomic: two threads racing to create a session is already a
/// bug, and this is a diagnostic rather than a lock.
bool g_session_live = false;

} // namespace

extern "C" {

const char *symsan_last_error(void) {
  return g_last_error.empty() ? "no error" : g_last_error.c_str();
}

// ---------------------------------------------------------------------------
// L1: RGD parser + solver ladder
// ---------------------------------------------------------------------------

symsan_rgd_t *symsan_rgd_create(void *union_table, size_t ut_size,
                                const symsan_rgd_options_t *opts) {
  if (!union_table || ut_size == 0) {
    set_error("symsan_rgd_create: union_table/ut_size required");
    return nullptr;
  }

  return guard<symsan_rgd_t *>(nullptr, [&] {
    // The RGD solvers reach the union table through the free function
    // __dfsan::get_label_info rather than through the parser, so it has to be
    // pointed at the same table.  Doing it here means an L1 user does not have
    // to know that; see the comment in include/session.h.
    symsan::set_label_info_base(union_table, ut_size);

    auto rgd = std::unique_ptr<symsan_rgd>(new symsan_rgd());
    size_t max_ast = (opts && opts->max_ast_size) ? opts->max_ast_size : 200;
    rgd->parser.reset(new rgd::RGDAstParser(
        union_table, ut_size, opts ? opts->solve_nested != 0 : false, max_ast));

    // the ladder order matters: cheapest first, z3 last
    if (!opts || !opts->no_i2s) {
      rgd->solvers.emplace_back(std::make_shared<rgd::I2SSolver>());
    }
    if (opts && opts->use_jigsaw) {
      rgd->solvers.emplace_back(std::make_shared<rgd::JITSolver>());
    }
    if (opts && opts->use_z3) {
      rgd->solvers.emplace_back(std::make_shared<rgd::Z3Solver>());
    }

    return rgd.release();
  });
}

void symsan_rgd_destroy(symsan_rgd_t *rgd) {
  guard_void([&] { delete rgd; });
}

symsan_status_t symsan_rgd_reset_input(symsan_rgd_t *rgd, const uint8_t *buf,
                                       size_t size) {
  if (!rgd || !buf) {
    set_error("symsan_rgd_reset_input: rgd/buf required");
    return SYMSAN_ERR_INVALID;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    std::vector<symsan::input_t> inputs;
    inputs.push_back({buf, size});
    // copy_input=true: the parser outlives this call, and we promised in the
    // header that buf does not have to
    if (rgd->parser->restart(inputs, true) != 0) {
      set_error("parser restart failed");
      return SYMSAN_ERR_FAILED;
    }
    return SYMSAN_OK;
  });
}

int symsan_rgd_parse_cond(symsan_rgd_t *rgd, uint32_t label, int result,
                          int add_nested, uint64_t *tasks_out, size_t tasks_cap) {
  if (!rgd) {
    set_error("symsan_rgd_parse_cond: rgd required");
    return SYMSAN_ERR_INVALID;
  }
  return guard<int>(SYMSAN_ERR_FAILED, [&] {
    std::vector<uint64_t> tasks;
    if (rgd->parser->parse_cond(label, result != 0, add_nested != 0, tasks) != 0) {
      set_error("parse_cond failed");
      return (int)SYMSAN_ERR_FAILED;
    }
    return copy_task_ids(tasks, tasks_out, tasks_cap);
  });
}

int symsan_rgd_parse_gep(symsan_rgd_t *rgd, uint32_t ptr_label, uint64_t ptr,
                         uint32_t index_label, int64_t index, uint64_t num_elems,
                         uint64_t elem_size, int64_t current_offset,
                         int enum_index, uint64_t *tasks_out, size_t tasks_cap) {
  if (!rgd) {
    set_error("symsan_rgd_parse_gep: rgd required");
    return SYMSAN_ERR_INVALID;
  }
  return guard<int>(SYMSAN_ERR_FAILED, [&] {
    std::vector<uint64_t> tasks;
    if (rgd->parser->parse_gep(ptr_label, ptr, index_label, index, num_elems,
                               elem_size, current_offset, enum_index != 0,
                               tasks) != 0) {
      set_error("parse_gep failed");
      return (int)SYMSAN_ERR_FAILED;
    }
    return copy_task_ids(tasks, tasks_out, tasks_cap);
  });
}

symsan_status_t symsan_rgd_add_constraint(symsan_rgd_t *rgd, uint32_t label,
                                          uint64_t result) {
  if (!rgd) {
    set_error("symsan_rgd_add_constraint: rgd required");
    return SYMSAN_ERR_INVALID;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    if (rgd->parser->add_constraints(label, result) != 0) {
      set_error("add_constraints failed");
      return SYMSAN_ERR_FAILED;
    }
    return SYMSAN_OK;
  });
}

symsan_status_t symsan_rgd_record_memcmp(symsan_rgd_t *rgd, uint32_t label,
                                         const uint8_t *buf, size_t size) {
  if (!rgd || (!buf && size)) {
    set_error("symsan_rgd_record_memcmp: rgd/buf required");
    return SYMSAN_ERR_INVALID;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    // record_memcmp copies into its own cache, hence the const_cast
    if (rgd->parser->record_memcmp(label, const_cast<uint8_t *>(buf), size) != 0) {
      set_error("record_memcmp failed");
      return SYMSAN_ERR_FAILED;
    }
    return SYMSAN_OK;
  });
}

symsan_status_t symsan_rgd_record_minimize(symsan_rgd_t *rgd, uint32_t label,
                                           int allow_zero) {
  if (!rgd) {
    set_error("symsan_rgd_record_minimize: rgd required");
    return SYMSAN_ERR_INVALID;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    if (rgd->parser->record_minimize(label, allow_zero != 0) != 0) {
      set_error("record_minimize failed");
      return SYMSAN_ERR_FAILED;
    }
    return SYMSAN_OK;
  });
}

symsan_solver_result_t symsan_rgd_solve_task(symsan_rgd_t *rgd, uint64_t task_id,
                                             const uint8_t *in, size_t in_size,
                                             uint8_t *out, size_t out_cap,
                                             size_t *out_size) {
  if (out_size) *out_size = 0;
  if (!rgd || !in || !out || !out_size) {
    set_error("symsan_rgd_solve_task: rgd/in/out/out_size required");
    return SYMSAN_SOLVER_ERROR;
  }
  if (out_cap < in_size) {
    // every solver writes at least a copy of the input before mutating it
    set_error("symsan_rgd_solve_task: out_cap smaller than in_size");
    return SYMSAN_SOLVER_ERROR;
  }
  return guard(SYMSAN_SOLVER_ERROR, [&] {
    auto task = rgd->parser->retrieve_task(task_id);
    if (!task) {
      set_error("unknown task id");
      return SYMSAN_SOLVER_ERROR;
    }

    // Walk the ladder, cheapest solver first, and stop at the first SAT.  UNSAT
    // from any solver is conclusive for the whole task, so give up immediately
    // rather than paying for the more expensive ones.
    symsan_solver_result_t last = SYMSAN_SOLVER_ERROR;
    for (auto &solver : rgd->solvers) {
      size_t n = 0;
      auto ret = solver->solve(task, in, in_size, out, n);
      if (ret == rgd::SOLVER_SAT) {
        *out_size = n;
        return SYMSAN_SOLVER_SAT;
      } else if (ret == rgd::SOLVER_UNSAT) {
        return SYMSAN_SOLVER_UNSAT;
      }
      last = (ret == rgd::SOLVER_TIMEOUT) ? SYMSAN_SOLVER_TIMEOUT
                                          : SYMSAN_SOLVER_ERROR;
    }
    return last;
  });
}

// ---------------------------------------------------------------------------
// L2: the whole concolic session
// ---------------------------------------------------------------------------

void symsan_config_init(symsan_config_t *cfg) {
  if (!cfg) return;
  memset(cfg, 0, sizeof(*cfg));
  // Take the defaults from the C++ struct rather than repeating the literals,
  // so the two cannot drift.
  rgd::ConcolicConfig def;
  cfg->use_stdin = def.use_stdin;
  cfg->use_i2s = def.use_i2s;
  cfg->use_jigsaw = def.use_jigsaw;
  cfg->use_z3 = def.use_z3;
  cfg->nested_solving = def.nested_solving;
  cfg->trace_bounds = def.trace_bounds;
  cfg->solve_ub = def.solve_ub;
  cfg->exit_on_memerror = def.exit_on_memerror;
  cfg->force_stdin = def.force_stdin;
  cfg->save_solved = def.save_solved;
  cfg->debug = def.debug;
  cfg->forkserver = def.forkserver;
  cfg->validate_coverage = def.validate_coverage;
  cfg->export_taint = def.export_taint;
  cfg->collect_tokens = def.collect_tokens;
  cfg->timeout_ms = def.timeout_ms;
  cfg->max_ast_size = def.max_ast_size;
  cfg->max_local_branch_counter = def.max_local_branch_counter;
  cfg->max_input_size = def.max_input_size;
  cfg->max_tokens = def.max_tokens;
  cfg->max_queue_tasks = def.max_queue_tasks;
  cfg->priority_tasks = def.priority_tasks;
}

symsan_status_t symsan_config_from_env(symsan_config_t *cfg) {
  if (!cfg) {
    set_error("symsan_config_from_env: cfg required");
    return SYMSAN_ERR_INVALID;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    // Run the one implementation of the SYMSAN_* knobs, then copy the answers
    // out.  The strings point into the environment, which is what the header
    // promises -- the struct owns nothing.
    rgd::ConcolicConfig c;
    if (c.from_env() != 0) {
      set_error("SYMSAN_TARGET is not set");
      return SYMSAN_ERR_INVALID;
    }
    cfg->symsan_bin = getenv("SYMSAN_TARGET");
    const char *dir = getenv("SYMSAN_OUTPUT_DIR");
    if (dir) cfg->output_dir = dir;
    cfg->use_i2s = c.use_i2s;
    cfg->use_jigsaw = c.use_jigsaw;
    cfg->use_z3 = c.use_z3;
    cfg->nested_solving = c.nested_solving;
    cfg->trace_bounds = c.trace_bounds;
    cfg->solve_ub = c.solve_ub;
    cfg->exit_on_memerror = c.exit_on_memerror;
    cfg->force_stdin = c.force_stdin;
    cfg->save_solved = c.save_solved;
    cfg->forkserver = c.forkserver;
    const char *bmap = getenv("SYMSAN_BRANCH_MAP");
    if (bmap) cfg->branch_map = bmap;
    cfg->validate_coverage = c.validate_coverage;
    cfg->export_taint = c.export_taint;
    cfg->collect_tokens = c.collect_tokens;
    cfg->max_queue_tasks = c.max_queue_tasks;
    cfg->priority_tasks = c.priority_tasks;
    return SYMSAN_OK;
  });
}

symsan_session_t *symsan_session_create(void) {
  if (g_session_live) {
    set_error("a symsan session is already live in this process; "
              "the launcher keeps its config in a file-global, so fork instead");
    return nullptr;
  }
  return guard<symsan_session_t *>(nullptr, [&] {
    auto *s = new symsan_session();
    g_session_live = true;
    return s;
  });
}

symsan_status_t symsan_session_init(symsan_session_t *s,
                                    const symsan_config_t *cfg) {
  if (!s || !cfg) {
    set_error("symsan_session_init: session/cfg required");
    return SYMSAN_ERR_INVALID;
  }
  if (!cfg->symsan_bin || !cfg->input_file) {
    set_error("symsan_session_init: symsan_bin and input_file are required");
    return SYMSAN_ERR_INVALID;
  }
  if (cfg->argc < 0 || (cfg->argc > 0 && !cfg->argv)) {
    set_error("symsan_session_init: argc/argv disagree");
    return SYMSAN_ERR_INVALID;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    rgd::ConcolicConfig c;
    c.symsan_bin = cfg->symsan_bin;
    if (cfg->output_dir) c.output_dir = cfg->output_dir;
    c.input_file = cfg->input_file;
    for (int i = 0; i < cfg->argc; ++i) {
      // a NULL entry would silently truncate argv inside the launcher, so
      // reject it here where we can still say why
      if (!cfg->argv[i]) {
        set_error("symsan_session_init: argv contains a NULL entry");
        return SYMSAN_ERR_INVALID;
      }
      c.args.emplace_back(cfg->argv[i]);
    }
    c.use_stdin = cfg->use_stdin != 0;
    c.use_i2s = cfg->use_i2s != 0;
    c.use_jigsaw = cfg->use_jigsaw != 0;
    c.use_z3 = cfg->use_z3 != 0;
    c.nested_solving = cfg->nested_solving != 0;
    c.trace_bounds = cfg->trace_bounds != 0;
    c.solve_ub = cfg->solve_ub != 0;
    c.exit_on_memerror = cfg->exit_on_memerror != 0;
    c.force_stdin = cfg->force_stdin != 0;
    c.save_solved = cfg->save_solved != 0;
    c.debug = cfg->debug != 0;
    c.forkserver = cfg->forkserver != 0;
    if (cfg->branch_map) c.branch_map = cfg->branch_map;
    c.validate_coverage = cfg->validate_coverage != 0;
    c.export_taint = cfg->export_taint != 0;
    c.collect_tokens = cfg->collect_tokens != 0;
    c.timeout_ms = cfg->timeout_ms;
    if (cfg->max_ast_size) c.max_ast_size = cfg->max_ast_size;
    if (cfg->max_local_branch_counter) {
      c.max_local_branch_counter = cfg->max_local_branch_counter;
    }
    if (cfg->max_input_size) c.max_input_size = cfg->max_input_size;
    if (cfg->max_tokens) c.max_tokens = cfg->max_tokens;
    // No `if`: 0 is a meaningful value here (unbounded) and also the default,
    // so there is nothing to protect and nothing to guess.
    c.max_queue_tasks = cfg->max_queue_tasks;
    c.priority_tasks = cfg->priority_tasks != 0;

    if (s->session.init(c) != 0) {
      set_error("ConcolicSession::init failed");
      return SYMSAN_ERR_FAILED;
    }
    s->initialized = true;
    return SYMSAN_OK;
  });
}

void symsan_session_destroy(symsan_session_t *s) {
  if (!s) return;
  guard_void([&] {
    delete s;
    g_session_live = false;
  });
}

int symsan_session_trace(symsan_session_t *s, const uint8_t *buf, size_t size) {
  if (!s || (!buf && size)) {
    set_error("symsan_session_trace: session/buf required");
    return SYMSAN_ERR_INVALID;
  }
  if (!s->initialized) {
    set_error("symsan_session_trace: session not initialized");
    return SYMSAN_ERR_NOT_READY;
  }
  return guard<int>(SYMSAN_ERR_FAILED, [&] {
    int n = s->session.trace(buf, size);
    if (n < 0) {
      set_error("ConcolicSession::trace failed");
      return (int)SYMSAN_ERR_FAILED;
    }
    return n;
  });
}

const uint8_t *symsan_session_next_solution(symsan_session_t *s, size_t *size) {
  if (size) *size = 0;
  if (!s || !size) {
    set_error("symsan_session_next_solution: session/size required");
    return nullptr;
  }
  if (!s->initialized) {
    set_error("symsan_session_next_solution: session not initialized");
    return nullptr;
  }
  return guard<const uint8_t *>(nullptr,
                                [&] { return s->session.next_solution(size); });
}

symsan_status_t symsan_session_current_target(const symsan_session_t *s,
                                              symsan_target_t *out) {
  if (!s || !out) {
    set_error("symsan_session_current_target: session/out required");
    return SYMSAN_ERR_INVALID;
  }
  if (!s->initialized) {
    set_error("symsan_session_current_target: session not initialized");
    return SYMSAN_ERR_NOT_READY;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    uint32_t cid = 0, dest = 0;
    bool direction = false;
    if (s->session.current_target(&cid, &direction, &dest) != 0) {
      // Not an error worth a message: a caller polling after the last solution
      // gets here on every loop exit.
      return SYMSAN_ERR_NOT_READY;
    }
    out->cid = cid;
    out->direction = direction ? 1 : 0;
    out->dest_edge = dest;
    return SYMSAN_OK;
  });
}

void symsan_session_report_result(symsan_session_t *s, int interesting) {
  symsan_session_report_target(s, interesting, SYMSAN_TARGET_UNKNOWN);
}

void symsan_session_report_target(symsan_session_t *s, int interesting,
                                  symsan_target_outcome_t outcome) {
  if (!s || !s->initialized) return;
  using TargetOutcome = rgd::ConcolicSession::TargetOutcome;
  TargetOutcome o;
  switch (outcome) {
    case SYMSAN_TARGET_REACHED: o = TargetOutcome::Reached; break;
    case SYMSAN_TARGET_NOT_REACHED: o = TargetOutcome::NotReached; break;
    // Anything the caller invented is Unknown, which is the safe reading: it
    // escalates, i.e. it does what the one-argument form always did.
    default: o = TargetOutcome::Unknown; break;
  }
  guard_void([&] { s->session.report_result(interesting != 0, o); });
}

symsan_status_t symsan_session_set_coverage(symsan_session_t *s,
                                            const uint8_t *map, size_t len) {
  if (!s || (!map && len)) {
    set_error("symsan_session_set_coverage: session/map required");
    return SYMSAN_ERR_INVALID;
  }
  if (!s->initialized) {
    set_error("symsan_session_set_coverage: session not initialized");
    return SYMSAN_ERR_NOT_READY;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    if (s->session.set_coverage(map, len) != 0) {
      set_error("symsan_session_set_coverage: session has no branch map");
      return SYMSAN_ERR_INVALID;
    }
    return SYMSAN_OK;
  });
}

symsan_status_t symsan_session_set_coverage_shared(symsan_session_t *s,
                                                   const uint8_t *map,
                                                   size_t len) {
  if (!s || (!map && len)) {
    set_error("symsan_session_set_coverage_shared: session/map required");
    return SYMSAN_ERR_INVALID;
  }
  if (!s->initialized) {
    set_error("symsan_session_set_coverage_shared: session not initialized");
    return SYMSAN_ERR_NOT_READY;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    if (s->session.set_coverage_shared(map, len) != 0) {
      set_error("symsan_session_set_coverage_shared: session has no branch map");
      return SYMSAN_ERR_INVALID;
    }
    return SYMSAN_OK;
  });
}

symsan_status_t symsan_session_check_coverage(const symsan_session_t *s,
                                              const uint32_t *covered,
                                              size_t n,
                                              symsan_join_report_t *out) {
  if (!s || !out || (!covered && n)) {
    set_error("symsan_session_check_coverage: session/out required");
    return SYMSAN_ERR_INVALID;
  }
  if (!s->initialized) {
    set_error("symsan_session_check_coverage: session not initialized");
    return SYMSAN_ERR_NOT_READY;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    rgd::JoinReport r;
    if (s->session.check_coverage(covered, n, &r) != 0) {
      set_error("symsan_session_check_coverage: needs a branch map and "
                "validate_coverage");
      return SYMSAN_ERR_INVALID;
    }
    out->executed = r.executed;
    out->checked = r.checked;
    out->violations = r.violations;
    out->pruned = r.pruned;
    out->unmapped = r.unmapped;
    return SYMSAN_OK;
  });
}

symsan_status_t symsan_session_input_taint(symsan_session_t *s,
                                           uint8_t *out, size_t len,
                                           size_t *size) {
  if (!s || !size || (!out && len)) {
    set_error("symsan_session_input_taint: session/size required");
    return SYMSAN_ERR_INVALID;
  }
  if (!s->initialized) {
    set_error("symsan_session_input_taint: session not initialized");
    return SYMSAN_ERR_NOT_READY;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    int n = s->session.input_taint(out, len);
    if (n < 0) {
      set_error("symsan_session_input_taint: needs export_taint");
      return SYMSAN_ERR_INVALID;
    }
    *size = (size_t)n;
    return SYMSAN_OK;
  });
}

symsan_status_t symsan_session_take_tokens(symsan_session_t *s,
                                           symsan_token_t *out, size_t max,
                                           size_t *count) {
  if (!s || !count || (!out && max)) {
    set_error("symsan_session_take_tokens: session/count required");
    return SYMSAN_ERR_INVALID;
  }
  if (!s->initialized) {
    set_error("symsan_session_take_tokens: session not initialized");
    return SYMSAN_ERR_NOT_READY;
  }
  return guard(SYMSAN_ERR_FAILED, [&] {
    // rgd::ConcolicSession::Token is layout-identical to symsan_token_t, but
    // copy rather than reinterpret_cast: the two are declared in different
    // headers, and nothing would tell us if one of them gained a field.
    static_assert(sizeof(rgd::ConcolicSession::Token) == sizeof(symsan_token_t),
                  "token structs out of step");
    rgd::ConcolicSession::Token buf[64];
    *count = 0;
    while (*count < max) {
      size_t want = max - *count;
      if (want > 64) want = 64;
      size_t got = s->session.take_tokens(buf, want);
      if (got == 0) break;
      for (size_t i = 0; i < got; ++i) {
        out[*count + i].data = buf[i].data;
        out[*count + i].size = buf[i].size;
      }
      *count += got;
    }
    return SYMSAN_OK;
  });
}

size_t symsan_session_num_tokens(const symsan_session_t *s) {
  if (!s || !s->initialized) return 0;
  return s->session.num_tokens();
}

symsan_status_t symsan_session_stats(const symsan_session_t *s,
                                     symsan_stats_t *out) {
  if (!s || !out) {
    set_error("symsan_session_stats: session/out required");
    return SYMSAN_ERR_INVALID;
  }
  const rgd::ConcolicStats &st = s->session.stats();
  out->total_branches = st.total_branches;
  out->branches_to_solve = st.branches_to_solve;
  out->total_tasks = st.total_tasks;
  out->solved_tasks = st.solved_tasks;
  out->stale_tasks = st.stale_tasks;
  out->evicted_tasks = st.evicted_tasks;
  for (int i = 0; i < rgd::kTargetNoveltyCount; i++)
    out->queued_novelty[i] = st.queued_novelty[i];
  out->solved_branches = st.solved_branches;
  out->mapped_branches = st.mapped_branches;
  out->unmapped_branches = st.unmapped_branches;
  return SYMSAN_OK;
}

void symsan_session_print_stats(const symsan_session_t *s, int fd) {
  if (!s) return;
  guard_void([&] { s->session.print_stats(fd); });
}

size_t symsan_session_num_pending_tasks(const symsan_session_t *s) {
  if (!s || !s->initialized) return 0;
  return guard<size_t>(0, [&] { return s->session.num_pending_tasks(); });
}

size_t symsan_session_num_solvers(const symsan_session_t *s) {
  if (!s || !s->initialized) return 0;
  return s->session.num_solvers();
}

const char *symsan_session_input_file(const symsan_session_t *s) {
  if (!s || !s->initialized) return nullptr;
  return s->session.input_file().c_str();
}

} // extern "C"
