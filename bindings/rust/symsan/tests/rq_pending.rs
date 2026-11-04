//! A trace that queues no task can still have apply-at-site inputs to hand out.
//!
//! With tokens on, `trace()` turns each compare where the input's bytes and the
//! constant they were compared against differ ("create" vs "CREATE") into a
//! same-length buffer with the constant written over them, and
//! `next_solution()` returns those after the solver ladder.  Whether the trace
//! queued any *task* is a different question -- a re-traced path has none --
//! and the LibAFL stage used to drain `next_solution()` only when it had, so it
//! lost every apply-at-site input from an already-seen path: the next `trace()`
//! replaces them.  `rq_pending()` is what the stage now asks instead.
//!
//! A file of its own for the usual reason: one [`symsan::Session`] per process,
//! one process per test binary.

mod common;

use std::path::{Path, PathBuf};

use symsan::{Config, Session};

const SEED: &[u8] = b"create..ab";
const SMASHED: &[u8] = b"CREATE..ab";

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/casefold.c")
}

/// Every buffer `next_solution()` still has, reporting each one boring.
fn drain(session: &mut Session) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(s) = session.next_solution() {
        out.push(s);
        session.report_result(false);
        assert!(out.len() < 1000, "next_solution() does not terminate");
    }
    out
}

#[test]
fn a_trace_with_no_tasks_still_hands_out_apply_at_site_inputs() {
    let dir = common::scratch_dir("rq-pending");
    // -O0 keeps the six compares six branches.
    let target = common::build_symsan(&dir, &source(), "casefold", &["-O0"]);
    let input_file = dir.join("cur_input");
    let input_file = input_file.to_str().unwrap();

    let config = Config::new(target.to_str().unwrap(), input_file)
        .args([target.to_str().unwrap(), input_file])
        .use_stdin(false)
        .collect_tokens(true)
        .timeout_ms(10_000);
    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    // ---- first trace: new branches, so tasks, and the smash --------------
    let tasks = session.trace(SEED).expect("trace failed");
    assert!(tasks > 0, "the first trace of {SEED:?} queued no task");
    assert!(
        session.rq_pending() > 0,
        "the first trace saw \"create\" compared against \"CREATE\" and built \
         no apply-at-site input"
    );
    let first = drain(&mut session);
    assert!(
        first.iter().any(|s| s == SMASHED),
        "draining the first trace never produced {SMASHED:?}"
    );
    assert_eq!(session.rq_pending(), 0, "drained, yet rq_pending() is nonzero");

    // ---- cover the other side of every compare ---------------------------
    //
    // With no branch map the session's coverage is its own: a branch is worth a
    // task until some trace has taken its other direction (EdgeCovManager).
    // Failing the walk at each byte in turn takes every compare both ways.
    for i in 0..6 {
        let mut other = SEED.to_vec();
        other[i] = b'x';
        session.trace(&other).expect("trace failed");
        drain(&mut session);
    }

    // ---- the seed again: nothing new to solve, the same smash ------------
    let tasks = session.trace(SEED).expect("re-trace failed");
    assert_eq!(
        tasks, 0,
        "re-tracing the same input queued {tasks} tasks; this test needs a \
         trace with none"
    );
    // The case the stage's `tasks != 0` gate dropped.
    assert!(
        session.rq_pending() > 0,
        "a trace with no tasks built no apply-at-site input, though the input \
         still says \"create\" where the target compares \"CREATE\""
    );
    let second = drain(&mut session);
    assert!(
        second.iter().any(|s| s == SMASHED),
        "with no tasks queued, next_solution() returned {second:?}, not {SMASHED:?}"
    );
    assert_eq!(session.rq_pending(), 0);
}
