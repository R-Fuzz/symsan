#ifndef CONFIG_H_
#define CONFIG_H_
#define MAX_NUM_MINIMAL_OPTIMA_ROUND 32
// Per-task attempt budget.  A full-set QF_BV sweep (seed 1, 6636 files) showed
// the attempts-to-solve distribution has a long tail: raising the cap from 1000
// to 10000 recovers ~97% of the budget-limited solves (+260 on the set) and then
// plateaus.  It is nearly free for the common case -- most tasks solve in well
// under 1000 attempts and stop early -- so the higher cap only spends more on the
// hard tail.  Overridable at runtime via JIGSAW_MAX_EXEC (smttest --budget).
#define MAX_EXEC_TIMES 10000
// Compile-time switch for jigsaw's search-diagnostic scaffolding: the phase/solve
// tracing (JIGSAW_DEBUG, JIGSAW_REPORT_ITERS env vars), the step tracer
// (JIGSAW_TRACE / JIGSAW_TARGET), and the A/B search-strategy toggles
// (JIGSAW_NO_JITTER / JIGSAW_NO_STAGNATION / JIGSAW_STAG_RESTART).  Default 0 so
// production builds carry NONE of these runtime getenv branches and always use
// the winning strategy; set to 1 to reproduce the strategy experiments.
#define JIGSAW_SEARCH_DEBUG 0
// Max rounds the input-to-state pass is iterated to a fixpoint.  A single i2s
// snap can newly-unsatisfy a coupled equality (e.g. X==assemble(bytes) while
// X==const pins X), which a later round can then snap.  Bounded to guarantee
// termination even if lateral (non-worsening) snaps cycle.
#define I2S_MAX_ROUNDS 8
// Max bisection probes when descend's doubling line search overshoots a minimum
// (f grew between step/2 and step). Bounded so backtracking stays cheap relative
// to the high-throughput search budget.
#define BACKTRACK_MAX 5
// Near-miss local jitter: when a local-optimum escape happens with a small total
// distance, run a bounded local random search (small deltas / bit flips on the
// bytes of unsatisfied constraints) instead of a random restart -- it hops the
// tiny barriers that flat/misleading gradients leave GD stuck at.
#define NEAR_MISS_F0 1024
#define NEAR_MISS_ROUNDS 64
// Per-task cap on jitter invocations; past this the escape falls back to the
// cheap restart so jitter can't exhaust the attempt budget and starve descent.
#define NEAR_MISS_MAX_CALLS 4
#endif
