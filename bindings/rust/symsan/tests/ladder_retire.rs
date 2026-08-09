//! A rung that answered is finished with the task, whatever the front-end made
//! of the answer.
//!
//! This is the default policy. The next rung would be handed the *same*
//! constraint set, so a second satisfying assignment to a system whose first
//! one did not flip the branch is not going to flip it either -- the
//! constraints are stale or incomplete, the path changes under the new bytes,
//! or the direction is infeasible. And in a hybrid fuzzer a solution that did
//! not flip is not a failure to retry: it went to the fuzzer, which is free to
//! make something of it.
//!
//! What that leaves as the only reason to climb is a rung that produced
//! *nothing*: `SOLVER_DECLINE` or `SOLVER_TIMEOUT`. So the number of calls the
//! second rung receives is exactly the number of tasks the first rung did not
//! answer:
//!
//! ```text
//!     jigsaw calls == i2s calls - i2s sat - i2s unsat
//! ```
//!
//! (`unsat` drops the task outright and never escalates.) That identity closed
//! to the call on a 600 s libxml2 campaign -- 137796 == 524068 - 386272 - 0 --
//! and it is what this pins. `ladder_climb.rs` is the same scenario with
//! `escalate_unkept_solutions` on, where the identity is a different one.
//!
//! A file of its own for the usual reason: one [`symsan::Session`] per process,
//! one process per test binary.

mod common;

#[test]
fn an_answered_rung_does_not_escalate() {
    let stats = common::drive_ladder("ladder-retire", false);

    let unanswered = stats.solver_calls[0] - stats.solver_sat[0] - stats.solver_unsat[0];
    assert_eq!(
        stats.solver_calls[1], unanswered,
        "rung 0 was called {} times and answered {} of them (SAT) plus {} \
         UNSAT, so {unanswered} tasks should have climbed -- rung 1 saw {}",
        stats.solver_calls[0], stats.solver_sat[0], stats.solver_unsat[0], stats.solver_calls[1]
    );

    // The point of the identity, stated the other way round: `drive_ladder`
    // reported every solution uninteresting, and not one of those tasks reached
    // the second rung.
    assert!(
        stats.solver_calls[1] < stats.solver_sat[0],
        "{} unkept solutions and {} calls to the next rung: the answers are \
         still escalating",
        stats.solver_sat[0],
        stats.solver_calls[1]
    );
}
