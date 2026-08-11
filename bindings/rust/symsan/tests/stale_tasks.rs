//! A queued task whose target the fuzzer covered mid-batch is dropped, not
//! solved.
//!
//! `is_branch_interesting` runs while the trace is still arriving, so every one
//! of an entry's tasks is filtered against the coverage of a moment that has
//! passed by the time a solver sees it. A fuzzer hands each solution straight
//! back to the target, inside the same loop that is still pulling tasks out --
//! so the most common reason a target stops being worth solving for is one of
//! this same entry's *earlier* answers. The parse-time filter cannot see that
//! coming, and re-solving what we just covered was 47% of the solutions in a
//! libpng campaign.
//!
//! Two things have to hold for the drop to work, and this file pins both:
//! the session must read the fuzzer's map where it lives rather than a copy
//! (`set_coverage_shared`), and `next_pending_task()` must re-ask before the
//! solver runs. Phase C is the control that separates them -- with a copied
//! snapshot the very same mutation changes nothing, which is the bug this
//! replaces.
//!
//! Needs AFL++; skips with an explanation when it cannot find one. A file of
//! its own for the usual reason: one [`Session`] per process, one process per
//! test binary.

mod common;

use std::path::{Path, PathBuf};

use symsan::{Config, Session};

use common::MAP_SIZE;

/// `tests/data/taint_loop.c` compares this many leading bytes, one per
/// iteration of a single static branch.  Eight independent tasks out of one
/// trace is what this test needs: something to drop after the first is served.
const LOOP_BYTES: usize = 8;
const SEED_LEN: usize = 16;

/// Same reason as `loop_coverage.rs`: at -O2 the loop is fully unrolled and the
/// branch becomes a `select`, and then there is nothing here to test.
const CFLAGS: &[&str] = &["-O0"];

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/taint_loop.c")
}

/// Pull solutions until the session runs out, reporting nothing interesting.
/// Returns how many came back.
fn drain(session: &mut Session) -> usize {
    let mut n = 0;
    while session.next_solution().is_some() {
        n += 1;
        session.report_result(false);
        // The ladder is finite, but a bug in the walk would spin here forever.
        assert!(n < 1000, "next_solution() does not terminate");
    }
    n
}

#[test]
fn a_target_covered_mid_batch_drops_its_pending_tasks() {
    let Some(afl_clang_lto) = common::find_afl_tool("afl-clang-lto") else {
        eprintln!("skipping: no afl-clang-lto found (set AFL_PATH to an AFLplusplus checkout)");
        return;
    };

    let dir = common::scratch_dir("stale-tasks");
    let built = common::build(&afl_clang_lto, &dir, &source(), "taint_loop", CFLAGS);
    let (map_path, target) = (built.bmap, built.symsan);
    let input_file = dir.join("cur_input");
    let input_file = input_file.to_str().unwrap();

    let config = Config::new(target.to_str().unwrap(), input_file)
        .args([target.to_str().unwrap(), input_file])
        .use_stdin(false)
        .jigsaw(true)
        .z3(true)
        .timeout_ms(10_000)
        .branch_map(map_path.to_str().unwrap());

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    let mut seed = vec![b'A'; SEED_LEN];
    seed[0] = b'Z';

    // The buffer stands in for `MapFeedbackMetadata::history_map`: the fuzzer
    // owns it, writes to it as each solution is evaluated, and the session only
    // ever reads it.  Lent once here; nothing re-publishes it below, because
    // nothing moves it.
    let mut host = vec![0u8; MAP_SIZE];
    unsafe { session.set_coverage_shared(host.as_ptr(), host.len()) }
        .expect("set_coverage_shared failed on a session with a branch map");

    // ---- A: the control -- nothing gets covered, nothing gets dropped ------

    let n = session.trace(&seed).expect("trace failed");
    assert_eq!(
        n, LOOP_BYTES,
        "expected one task per compared byte; with {n} the build is not the \
         shape this test is about"
    );
    let baseline = drain(&mut session);
    assert!(baseline > 0, "{n} tasks produced no solutions at all");
    assert_eq!(
        session.stats().stale_tasks,
        0,
        "nothing was ever covered, so nothing should have been dropped as \
         already covered"
    );

    // ---- B: the fuzzer covers everything after the first solution ----------

    let n = session.trace(&seed).expect("re-trace failed");
    assert_eq!(n, LOOP_BYTES, "re-tracing the same input produced {n} tasks");

    assert!(
        session.next_solution().is_some(),
        "the first task produced no solution, so there is nothing to be \
         covered by"
    );
    session.report_result(false);

    // Read before the mutation and after the first task has been claimed: what
    // is left in the queue is exactly what the gate should now refuse, and
    // counting it this way does not assume how many tasks that first solution
    // consumed.
    let pending = session.pending_tasks();
    assert!(pending > 0, "no tasks left to drop after the first solution");

    // This is the fuzzer running the solution we just handed it and folding the
    // result into its history map. 255 is above every hit-count class, so every
    // remaining target now reads as covered.
    host.fill(255);

    let before = session.stats().stale_tasks;
    let produced = drain(&mut session);
    let dropped = session.stats().stale_tasks - before;
    assert_eq!(
        dropped, pending as u64,
        "{pending} tasks were queued against targets the fuzzer has since \
         covered; {dropped} were dropped"
    );
    assert!(
        produced < baseline,
        "dropping {dropped} tasks still produced {produced} solutions, against \
         {baseline} with nothing covered -- the gate is not reaching the solver"
    );

    // ---- C: the control for B -- a copied snapshot cannot see the write ----
    //
    // Same trace, same mutation, same moment. The only difference is that the
    // session was handed a copy, so the fuzzer's later writes land somewhere
    // the session is not looking. This is what the code did before, and it is
    // the reason `set_coverage` alone was not enough: the filter and the gate
    // both read a world that stopped updating when the trace began.

    host.fill(0);
    session
        .set_coverage(&host)
        .expect("set_coverage failed on a session with a branch map");

    let n = session.trace(&seed).expect("re-trace failed");
    assert_eq!(n, LOOP_BYTES, "re-tracing the same input produced {n} tasks");
    assert!(session.next_solution().is_some(), "no first solution in phase C");
    session.report_result(false);

    let before = session.stats().stale_tasks;
    host.fill(255);
    let produced = drain(&mut session);
    assert_eq!(
        session.stats().stale_tasks,
        before,
        "the session is still reading `host` after set_coverage() copied it; \
         the copy is the whole point of that entry point"
    );
    assert_eq!(
        produced + 1,
        baseline,
        "with a snapshot the batch should run to completion exactly as in \
         phase A, got {produced} solutions after the first against {baseline}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
