//! `escalate_unkept_solutions` puts back the old unconditional climb.
//!
//! The control for `ladder_retire.rs`. With the flag on, a task leaves a rung
//! unless that rung's answer was *kept* -- so everything that is not retired
//! climbs, and the identity becomes
//!
//! ```text
//!     jigsaw calls == i2s calls - i2s unsat - i2s retired
//! ```
//!
//! which on a 600 s libxml2 campaign closed as 434707 == 435990 - 0 - 1283.
//! Since the front-end kept 0.3% of i2s's answers there, that is very nearly
//! "every task runs every rung", which is what the flag exists to demonstrate
//! and to let anyone measure again.
//!
//! It matters that this arm still *works*: the flag is a measurement tool, and
//! a measurement tool that silently stopped escalating would make the default
//! look free.
//!
//! A file of its own for the usual reason: one [`symsan::Session`] per process,
//! one process per test binary.

mod common;

#[test]
fn escalate_unkept_solutions_climbs_after_an_unkept_answer() {
    let stats = common::drive_ladder("ladder-climb", true);

    let not_retired = stats.solver_calls[0] - stats.solver_unsat[0] - stats.solver_retired[0];
    assert_eq!(
        stats.solver_calls[1], not_retired,
        "rung 0 was called {} times, {} of them UNSAT and {} retired, so \
         {not_retired} tasks should have climbed -- rung 1 saw {}",
        stats.solver_calls[0], stats.solver_unsat[0], stats.solver_retired[0], stats.solver_calls[1]
    );

    // And the difference from the default, which is the whole flag: the SAT
    // answers nobody kept are in that count. `drive_ladder` asserts there was
    // at least one, so this is not vacuously true.
    assert!(
        stats.solver_calls[1] >= stats.solver_sat[0],
        "{} answers went unkept but rung 1 was called only {} times",
        stats.solver_sat[0],
        stats.solver_calls[1]
    );
}
