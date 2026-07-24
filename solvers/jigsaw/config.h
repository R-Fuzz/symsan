#ifndef CONFIG_H_
#define CONFIG_H_
#define MAX_NUM_MINIMAL_OPTIMA_ROUND 32
#define MAX_EXEC_TIMES 1000
// Max rounds the input-to-state pass is iterated to a fixpoint.  A single i2s
// snap can newly-unsatisfy a coupled equality (e.g. X==assemble(bytes) while
// X==const pins X), which a later round can then snap.  Bounded to guarantee
// termination even if lateral (non-worsening) snaps cycle.
#define I2S_MAX_ROUNDS 8
// Max bisection probes when descend's doubling line search overshoots a minimum
// (f grew between step/2 and step). Bounded so backtracking stays cheap relative
// to the high-throughput search budget.
#define BACKTRACK_MAX 5
#endif
