/*
  symsan_c.h -- the C ABI over SymSan's driver session.

  This is the surface non-C++ front-ends bind against: the Rust crate under
  bindings/rust/symsan is generated from this header, and it is a suitable
  target for any other FFI (cffi, cgo, ...).  Everything here is a thin,
  exception-free forwarding layer over the C++ in driver/session/; the policy
  lives there, not here, so that the C++ front-ends (driver/aflpp) and the FFI
  front-ends cannot drift apart.

  There are two layers, and you pick exactly one:

    L1  symsan_rgd_*    primitives.  You drive the launcher yourself (via the
                        plain C API in launch.h, which this library also
                        exports) and feed the events you care about to the RGD
                        parser and solver ladder.  This mirrors what the Python
                        binding exposes for the Z3 stack, and is the layer to
                        use when you want your own event policy.

    L2  symsan_session_* the whole concolic loop.  trace() an input, then pull
                        solved inputs out with next_solution() until it returns
                        NULL.  This is rgd::ConcolicSession, i.e. exactly what
                        the AFL++ custom mutator runs on.  Use this unless you
                        have a reason not to.

  Errors: every function that can fail returns a status (or NULL) and leaves a
  human-readable description in symsan_last_error(), which is thread-local.  No
  C++ exception ever crosses this boundary -- unwinding through a C frame into
  Rust would be undefined behaviour, so every entry point catches.

  Process model: the launcher keeps its configuration in a file-global, so one
  process hosts at most one session (see the comment on symsan::TraceSession).
  symsan_session_create() returns NULL for a second live session rather than
  letting the two quietly corrupt each other.  Fuzzers scale by forking, and the
  union-table shm name already includes getpid(), so this is not a real limit.

  (c) 2023 - 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#ifndef SYMSAN_C_H
#define SYMSAN_C_H

#include <stddef.h>
#include <stdint.h>

/* L1 also needs the launcher primitives -- symsan_init, the symsan_set_ family,
   symsan_run, symsan_read_event, symsan_terminate, symsan_destroy.  They are
   already a C ABI, so rather than wrap them we just pull them in; libsymsan_c
   exports them unchanged. */
#include "launch.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* status codes                                                              */
/* ------------------------------------------------------------------------- */

/** Return value of the fallible functions below. */
typedef enum {
  SYMSAN_OK = 0,
  /** a required argument was NULL, or a value was out of range */
  SYMSAN_ERR_INVALID = -1,
  /** allocation failed */
  SYMSAN_ERR_NOMEM = -2,
  /** the underlying C++ call reported failure; see symsan_last_error() */
  SYMSAN_ERR_FAILED = -3,
  /** a second session was requested while one was already live */
  SYMSAN_ERR_BUSY = -4,
  /** the handle has not been initialized yet */
  SYMSAN_ERR_NOT_READY = -5,
} symsan_status_t;

/** Description of the most recent failure on this thread.
 *  Never NULL; valid until the next failing call on the same thread. */
const char *symsan_last_error(void);

/* ------------------------------------------------------------------------- */
/* L1: RGD parser + solver ladder                                            */
/* ------------------------------------------------------------------------- */

/** Opaque RGD context: one rgd::RGDAstParser plus its solver ladder. */
typedef struct symsan_rgd symsan_rgd_t;

/** Which solvers to put in the ladder, in this order.  i2s comes first -- it is
 *  the cheap one, and the others assume it ran -- and is on unless you say
 *  otherwise, which is why its field is the negative one: a zeroed struct, like
 *  a NULL pointer, means "i2s only". */
typedef struct {
  int use_jigsaw;     /**< add the JIT/gradient-descent solver */
  int use_z3;         /**< add the Z3 solver as a last resort */
  int solve_nested;   /**< carry nested constraints into each task */
  size_t max_ast_size; /**< skip ASTs larger than this; 0 means the default 200 */
  /** drop the input-to-state solver, leaving only whichever of the two above
   *  are set.  Only useful for attributing solves to one solver; a ladder with
   *  nothing in it solves nothing. */
  int no_i2s;
} symsan_rgd_options_t;

/** Result of a solve attempt; mirrors rgd::solver_result_t. */
typedef enum {
  SYMSAN_SOLVER_ERROR = 0,
  SYMSAN_SOLVER_SAT = 1,
  SYMSAN_SOLVER_UNSAT = 2,
  SYMSAN_SOLVER_TIMEOUT = 3,
} symsan_solver_result_t;

/** Build a parser and solver ladder over an already-mapped union table.
 *
 *  @param union_table the pointer symsan_init() returned
 *  @param ut_size     the size passed to symsan_init()
 *  @param opts        may be NULL, meaning i2s only with the default AST limit
 *  @return a context to pass to the calls below, or NULL on failure
 *
 *  Also installs the process-wide union-table base that the solvers resolve
 *  labels against, so you do not have to define __dfsan::get_label_info
 *  yourself the way the C++ drivers used to.
 */
symsan_rgd_t *symsan_rgd_create(void *union_table, size_t ut_size,
                                const symsan_rgd_options_t *opts);

void symsan_rgd_destroy(symsan_rgd_t *rgd);

/** Drop every cache and start over on a new input.
 *
 *  The bytes are copied, so @p buf need not outlive the call.  Call this once
 *  per target run, before feeding it any events.
 */
symsan_status_t symsan_rgd_reset_input(symsan_rgd_t *rgd, const uint8_t *buf,
                                       size_t size);

/** Turn a conditional-branch event into solving tasks.
 *
 *  @param label      pipe_msg::label
 *  @param result     the direction to solve for (usually !pipe_msg::result)
 *  @param add_nested whether to fold in the path constraints; the runtime asks
 *                    for this with the F_ADD_CONS flag
 *  @param tasks_out  receives the ids of the tasks created
 *  @param tasks_cap  capacity of @p tasks_out
 *  @return the number of tasks written, or a negative symsan_status_t.  A
 *          result equal to @p tasks_cap means ids may have been dropped.
 */
int symsan_rgd_parse_cond(symsan_rgd_t *rgd, uint32_t label, int result,
                          int add_nested, uint64_t *tasks_out, size_t tasks_cap);

/** Turn a symbolic-index GEP event into solving tasks.  Arguments map one to
 *  one onto the gep_msg fields; see runtime/dfsan/dfsan.h.
 *  @return as symsan_rgd_parse_cond(). */
int symsan_rgd_parse_gep(symsan_rgd_t *rgd, uint32_t ptr_label, uint64_t ptr,
                         uint32_t index_label, int64_t index, uint64_t num_elems,
                         uint64_t elem_size, int64_t current_offset,
                         int enum_index, uint64_t *tasks_out, size_t tasks_cap);

/** Record a constraint without producing a task (add_constraint_type events). */
symsan_status_t symsan_rgd_add_constraint(symsan_rgd_t *rgd, uint32_t label,
                                          uint64_t result);

/** Record the concrete operand of a memcmp so the solver can match against it. */
symsan_status_t symsan_rgd_record_memcmp(symsan_rgd_t *rgd, uint32_t label,
                                         const uint8_t *buf, size_t size);

/** Record a label whose value should be minimized, e.g. an allocation size. */
symsan_status_t symsan_rgd_record_minimize(symsan_rgd_t *rgd, uint32_t label,
                                           int allow_zero);

/** Run one task through the solver ladder and produce a mutated input.
 *
 *  Task ids come from symsan_rgd_parse_cond()/_parse_gep().  A task can only be
 *  solved once: it is removed from the context by this call.
 *
 *  @param in,in_size   the original input the trace was produced from
 *  @param out          receives the mutated input; must hold at least in_size
 *                      bytes, and more if the solver may grow the input
 *  @param out_cap      capacity of @p out
 *  @param out_size     receives the length actually written on SAT
 *  @return SYMSAN_SOLVER_SAT if @p out was filled in; UNSAT if no solver in the
 *          ladder could satisfy the task; TIMEOUT if they all gave up; ERROR on
 *          a bad handle or unknown task id.
 */
symsan_solver_result_t symsan_rgd_solve_task(symsan_rgd_t *rgd, uint64_t task_id,
                                             const uint8_t *in, size_t in_size,
                                             uint8_t *out, size_t out_cap,
                                             size_t *out_size);

/* ------------------------------------------------------------------------- */
/* L2: the whole concolic session                                            */
/* ------------------------------------------------------------------------- */

/** Opaque handle to an rgd::ConcolicSession. */
typedef struct symsan_session symsan_session_t;

/** Everything a session needs to know up front.
 *
 *  This struct borrows every string it points at: symsan_session_init() copies
 *  what it needs, so the caller may free them as soon as it returns.  Nothing
 *  here is ever freed by this library -- which is also why it is safe to point
 *  the fields straight at getenv() results.
 *
 *  Initialize with symsan_config_init() before setting fields, so that new
 *  fields added later keep their defaults instead of holding stack garbage.
 */
typedef struct {
  /** path to the symsan-instrumented target (required) */
  const char *symsan_bin;
  /** where solved inputs are written when save_solved is set; NULL means "." */
  const char *output_dir;
  /** file the session stages each traced input into (required).  Wherever the
   *  target expects a filename in argv, that argv entry must be this path. */
  const char *input_file;
  /** argv for the target; argv[0] is conventionally the target path */
  const char *const *argv;
  int argc;
  /** non-zero if the target reads its input from stdin rather than input_file */
  int use_stdin;

  /* solver ladder, run in this order; see also use_i2s at the end */
  int use_jigsaw;
  int use_z3;
  int nested_solving;

  /* tracing */
  int trace_bounds;
  int solve_ub;          /**< implies trace_bounds */
  int exit_on_memerror;  /**< default 1 */
  int force_stdin;
  int save_solved;
  int debug;
  /** per-run timeout in milliseconds; also arms the deadloop guard */
  unsigned timeout_ms;

  /* limits */
  size_t max_ast_size;             /**< default 200 */
  uint8_t max_local_branch_counter;/**< default 128 */
  size_t max_input_size;           /**< default 1 MiB */

  /** AFL++ AFL_LLVM_DOCUMENT_IDS output for the fuzzer's build of the same
   *  target, or NULL.  Given one, the session can tell that a branch the fuzzer
   *  already covered is not worth solving; feed it the coverage map with
   *  symsan_session_set_coverage().  See include/branch_map.h and
   *  patches/aflpp-document-ids.patch. */
  const char *branch_map;

  /** Keep one instance of the target alive and fork it per input, instead of
   *  exec'ing it again for every run.  Saves the execv, the dynamic link and
   *  the shadow/union mapping each time.  Only applies to file input, and only
   *  to targets whose backend has a fork server -- otherwise it is silently
   *  ignored and the per-run exec is used, so it is always safe to set. */
  int forkserver;

  /** Record which branch directions each trace takes, so that
   *  symsan_session_check_coverage() can hold the branch map against ground
   *  truth.  Off by default: it costs a hash insert per branch, and is a
   *  diagnostic rather than something a fuzzing run needs.
   *
   *  (New fields go at the end, so that a caller built against an older header
   *  keeps a valid prefix.) */
  int validate_coverage;

  /** Run the input-to-state solver, the first rung of the ladder.  Default 1,
   *  like exit_on_memerror -- turning it off only makes sense when measuring
   *  what one of the other solvers can do on its own.  Belongs next to
   *  use_jigsaw/use_z3 above and is here for the reason just given. */
  int use_i2s;

  /** Record which input offsets each branch reads, so that
   *  symsan_session_input_taint() can say which bytes are still worth
   *  mutating.  Off by default: it makes every branch pay for its dependency
   *  scan, even the ones that are never solved, and only a front-end running
   *  its own input-to-state pass has a use for the answer. */
  int export_taint;
} symsan_config_t;

/** Fill @p cfg with the defaults.  Always call this first. */
void symsan_config_init(symsan_config_t *cfg);

/** Overlay the SYMSAN_* environment variables onto @p cfg.
 *
 *  Reads SYMSAN_TARGET, SYMSAN_OUTPUT_DIR, SYMSAN_NO_I2S, SYMSAN_USE_JIGSAW,
 *  SYMSAN_USE_Z3,
 *  SYMSAN_USE_NESTED, SYMSAN_TRACE_BOUNDS, SYMSAN_SOLVE_UB,
 *  SYMSAN_DONT_EXIT_ON_MEMERROR, SYMSAN_FORCE_STDIN, SYMSAN_SAVE_SOLVED,
 *  SYMSAN_FORKSRV and
 *  SYMSAN_BRANCH_MAP -- the same knobs the AFL++ mutator honours, so front-ends
 *  stay consistent without each re-reading getenv().
 *
 *  Leaves input_file, argv/argc and use_stdin alone; those are the front-end's
 *  business.  The strings point into the environment and stay valid as long as
 *  it is not modified.
 *
 *  @return SYMSAN_OK, or SYMSAN_ERR_INVALID if SYMSAN_TARGET is not set
 */
symsan_status_t symsan_config_from_env(symsan_config_t *cfg);

/** Allocate a session.  Returns NULL if one is already live in this process
 *  (see the process-model note at the top). */
symsan_session_t *symsan_session_create(void);

/** Map the union table, build the parser and solver ladder, open the input
 *  file.  Call exactly once per session.
 *
 *  Kept separate from create() because some front-ends only learn their argv
 *  after startup -- the AFL++ mutator builds it from afl->argv on the first
 *  fuzz round.
 */
symsan_status_t symsan_session_init(symsan_session_t *s,
                                    const symsan_config_t *cfg);

/** Free the session and release the launcher.  NULL is accepted. */
void symsan_session_destroy(symsan_session_t *s);

/** Trace @p buf: stage it into the input file, run the target on it, and turn
 *  the resulting branches into solving tasks.  Any tasks left over from the
 *  previous input are discarded.
 *
 *  @return the number of tasks queued, or a negative symsan_status_t
 */
int symsan_session_trace(symsan_session_t *s, const uint8_t *buf, size_t size);

/** Next solved input for the tasks queued by trace(), or NULL when there are
 *  none left.  The buffer belongs to the session and is invalidated by the next
 *  call to next_solution() or trace(), so copy it if you need to keep it.
 *
 *  The intended shape is:
 *
 *  ```c
 *  symsan_session_trace(s, buf, len);
 *  size_t n;
 *  const uint8_t *sol;
 *  while ((sol = symsan_session_next_solution(s, &n)) != NULL) {
 *    int interesting = run_and_evaluate(sol, n);
 *    symsan_session_report_result(s, interesting);
 *  }
 *  ```
 *
 *  (Fenced and tagged `c` rather than indented: bindgen carries these comments
 *  into the generated Rust, where rustdoc would otherwise try to compile an
 *  indented block as a Rust doctest.)
 */
const uint8_t *symsan_session_next_solution(symsan_session_t *s, size_t *size);

/** Tell the session whether the last solution turned out to be interesting.
 *
 *  On non-zero, the branch counts as solved and the remaining solvers in the
 *  ladder are not tried for it.  On zero, next_solution() escalates to the next
 *  solver for the same task.
 *
 *  Reporting honestly is the point of this call: the AFL++ mutator had to guess
 *  by comparing queue-entry filenames, whereas a front-end that can see its own
 *  execution result knows.
 */
void symsan_session_report_result(symsan_session_t *s, int interesting);

/** Give the session a snapshot of the fuzzer's coverage map, so that it stops
 *  solving for branches the fuzzer has already reached.
 *
 *  @p map is indexed by AFL++ edge id and read as "non-zero means covered", so
 *  either a hit-count map or a history map works.  It is copied, and only the
 *  branches the branch map resolves are affected -- everything else keeps
 *  today's behaviour.  Pass NULL to forget the previous snapshot.
 *
 *  Call before trace().  Returns SYMSAN_ERR_INVALID if the session was
 *  initialized without a branch_map, since then there is no way to know which
 *  entry of @p map belongs to which branch.
 */
symsan_status_t symsan_session_set_coverage(symsan_session_t *s,
                                            const uint8_t *map, size_t len);

/** What symsan_session_check_coverage() found.  See include/cov.h. */
typedef struct {
  /** distinct branch directions the last trace took */
  size_t executed;
  /** of those, the ones the branch map resolved to exactly one edge id */
  size_t checked;
  /** of the checked ones, those whose edge the fuzzer's build did *not* record.
   *  Any non-zero value is a bug: either the map names the wrong edge, or the
   *  two builds took different paths on the same bytes. */
  size_t violations;
  /** directions resolving to several edge ids, because the branch was inlined */
  size_t ambiguous;
  /** of those, the ones where *none* of the edge ids was recorded */
  size_t ambiguous_violations;
  /** directions the branch map had nothing to say about.  Expected to be
   *  non-zero -- AFL++ prunes blocks -- and merely costs opportunities. */
  size_t unmapped;
} symsan_join_report_t;

/** Hold the branch map against ground truth for the input just traced.
 *
 *  Where symsan_session_set_coverage() *uses* the map, this *checks* it.  The
 *  mapped/unmapped counters in symsan_stats_t only say how much of the map
 *  lands; a map that resolved every branch to the wrong edge would report a
 *  perfect ratio while silently suppressing every solve.  This call can tell
 *  the difference, because it is given a ground truth.
 *
 *  @p covered is the set of AFL++ edge ids the *fuzzer's* build of the same
 *  target recorded for the same bytes -- a corpus entry's tracked indices, or
 *  the output of afl-showmap.  Every direction the trace took should resolve to
 *  an edge in there.
 *
 *  Needs both a branch_map and validate_coverage set at init(); returns
 *  SYMSAN_ERR_INVALID otherwise.
 */
symsan_status_t symsan_session_check_coverage(const symsan_session_t *s,
                                              const uint32_t *covered,
                                              size_t n,
                                              symsan_join_report_t *out);

/** Which bytes of the input just traced are still worth mutating.
 *
 *  Writes one byte per input offset into @p out:
 *
 *    0 untainted -- no branch on this path read it
 *    1 open      -- some branch target that depends on it is still unflipped
 *    2 settled   -- a branch read it, and every target depending on it has been
 *                   reached, so there is nothing left to find there
 *
 *  For a fuzzer that also runs its own input-to-state pass: it can hold the
 *  settled bytes still and spend the pass on the open ones.  The answer is
 *  computed per data-flow group rather than per byte, so bytes a constraint
 *  couples together -- the four bytes of a 32-bit compare, say -- always come
 *  back with the same class.
 *
 *  Call it after draining symsan_session_next_solution(): a target counts as
 *  flipped only once symsan_session_report_result() has said its solution was
 *  interesting, so asking earlier reports more open bytes than there are.
 *
 *  @p size receives the traced input size even when it exceeds @p len, in which
 *  case only the first @p len offsets were written.  Needs export_taint set at
 *  init(); returns SYMSAN_ERR_INVALID otherwise.
 */
symsan_status_t symsan_session_input_taint(symsan_session_t *s,
                                           uint8_t *out, size_t len,
                                           size_t *size);

/** Counters mirroring rgd::ConcolicStats. */
typedef struct {
  uint64_t total_branches;
  uint64_t branches_to_solve;
  uint64_t total_tasks;
  uint64_t solved_tasks;
  uint64_t solved_branches;
  /** branch directions the branch map could and could not resolve to fuzzer
   *  edge ids; both 0 when no branch map is in use */
  uint64_t mapped_branches;
  uint64_t unmapped_branches;
} symsan_stats_t;

symsan_status_t symsan_session_stats(const symsan_session_t *s,
                                     symsan_stats_t *out);

/** Write the counters, the task-size histogram and each solver's own stats to
 *  @p fd. */
void symsan_session_print_stats(const symsan_session_t *s, int fd);

/** Tasks still queued for the current input. */
size_t symsan_session_num_pending_tasks(const symsan_session_t *s);

/** Length of the solver ladder.  trace() times this bounds how many times
 *  next_solution() can return a buffer. */
size_t symsan_session_num_solvers(const symsan_session_t *s);

/** The file trace() stages inputs into, so a front-end can wire it into argv.
 *  Owned by the session; NULL before init(). */
const char *symsan_session_input_file(const symsan_session_t *s);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !SYMSAN_C_H */
