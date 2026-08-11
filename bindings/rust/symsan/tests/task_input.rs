//! A task is solved against the bytes it was traced with, not the bytes the
//! session happens to hold.
//!
//! A `SearchTask`'s `Read`s are offsets into one particular input. For as long
//! as the queue was drained to exhaustion inside the trace that filled it,
//! "the task's input" and "the session's current input" were the same buffer
//! and nothing could tell them apart. A scheduler that keeps tasks across
//! traces breaks that: the queue outlives the seed. Solving such a task against
//! whatever was traced most recently is not a worse answer to the same
//! question, it is an answer to a different one -- offset 3 of another file is
//! not the byte the constraint is about.
//!
//! So the test traces two seeds *without draining in between* and then drains.
//! The seeds differ in length and in filler, and `taint_loop.c` never reads
//! past its eighth byte, so the untouched tail of each solution says which seed
//! it was built from. Before `SearchTask::input`, every solution here came back
//! with the second seed's shape.
//!
//! No AFL++ needed: with no branch map the session uses `EdgeCovManager`, and
//! the direction these tasks target (`buf[i] == 'Z'`) is one neither seed
//! takes, so nothing is dropped as already covered and the two traces cannot
//! interfere through coverage.
//!
//! A file of its own for the usual reason: one [`Session`] per process, one
//! process per test binary.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use symsan::{Config, Session};

/// `tests/data/taint_loop.c` compares this many leading bytes, one per
/// iteration of a single static branch -- so one task per byte, per trace.
const LOOP_BYTES: usize = 8;

/// The two seeds. Different lengths *and* different filler: either one alone
/// would catch the bug, and together they say which seed a solution came from
/// without depending on how many bytes the solver chose to move.
const A_LEN: usize = 16;
const A_FILL: u8 = b'A';
const B_LEN: usize = 24;
const B_FILL: u8 = b'B';

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/taint_loop.c")
}

fn build_target(out_dir: &Path) -> PathBuf {
    let out = out_dir.join("taint_loop.fg");
    let ko_clang = Path::new(symsan::BUILD_DIR).join("bin/ko-clang");
    assert!(
        ko_clang.is_file(),
        "{} is missing; run `cd b4 && make -j && make install` first",
        ko_clang.display()
    );

    let status = Command::new(&ko_clang)
        .env("KO_CC", "clang-18")
        .env("KO_USE_FASTGEN", "1")
        // Same reason as `loop_coverage.rs`: this test is about one static
        // branch traversed eight times, and at -O2 the loop is fully unrolled
        // and the compare becomes a `select` with no branch at all -- the trace
        // comes back with nothing in it.  `-O0` on the command line is not
        // enough: ko-clang runs its own pipeline, and only KO_DONT_OPTIMIZE
        // turns that off.
        .env("KO_DONT_OPTIMIZE", "1")
        .arg("-O0")
        .arg(source())
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to run ko-clang");
    assert!(status.success(), "ko-clang failed");
    out
}

/// Which seed a solution was built from, read off the bytes `taint_loop.c`
/// never looks at. `None` if it matches neither, which is the failure this
/// test exists to report.
fn origin(solution: &[u8]) -> Option<char> {
    let tail = |len: usize, fill: u8| {
        solution.len() == len && solution[LOOP_BYTES..].iter().all(|&b| b == fill)
    };
    if tail(A_LEN, A_FILL) {
        Some('A')
    } else if tail(B_LEN, B_FILL) {
        Some('B')
    } else {
        None
    }
}

#[test]
fn a_task_outliving_its_trace_is_solved_against_its_own_input() {
    let dir = common::scratch_dir("task-input");
    let target = build_target(&dir);
    let input_file = dir.join("cur_input");
    let input_file = input_file.to_str().unwrap();

    let config = Config::new(target.to_str().unwrap(), input_file)
        .args([target.to_str().unwrap(), input_file])
        .use_stdin(false)
        .jigsaw(true)
        .z3(true)
        .timeout_ms(10_000);

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    let a = vec![A_FILL; A_LEN];
    let b = vec![B_FILL; B_LEN];

    // Two traces, no drain in between: at the end of this the queue holds the
    // first seed's tasks *and* the second's, and only the first seed's can tell
    // the two apart.
    let n = session.trace(&a).expect("trace failed");
    assert_eq!(
        n, LOOP_BYTES,
        "expected one task per compared byte; with {n} the build is not the \
         shape this test is about"
    );
    let n = session.trace(&b).expect("trace failed");
    assert_eq!(n, LOOP_BYTES, "the second trace produced {n} tasks");
    assert_eq!(
        session.pending_tasks(),
        2 * LOOP_BYTES,
        "the second trace should have added to the queue, not replaced it"
    );

    let (mut from_a, mut from_b, mut orphans) = (0usize, 0usize, Vec::new());
    while let Some(solution) = session.next_solution() {
        match origin(&solution) {
            Some('A') => from_a += 1,
            Some('B') => from_b += 1,
            // Keep going and report them all at the end: the count is what says
            // whether this is one odd solver answer or every solution in the
            // batch wearing the wrong seed.
            _ => orphans.push(solution),
        }
        session.report_result(false);
        assert!(
            from_a + from_b + orphans.len() < 1000,
            "next_solution() does not terminate"
        );
    }

    assert!(
        orphans.is_empty(),
        "{} of {} solutions match neither seed's untouched tail; first is {} \
         bytes: {:?}",
        orphans.len(),
        from_a + from_b + orphans.len(),
        orphans[0].len(),
        &orphans[0][..orphans[0].len().min(32)]
    );
    assert!(
        from_a > 0,
        "{from_b} solutions came back built on the second seed and none on the \
         first, whose {LOOP_BYTES} tasks were queued first -- the solver is \
         being handed the session's current input rather than the task's"
    );
    assert!(from_b > 0, "no solutions at all for the second seed's tasks");

    std::fs::remove_dir_all(&dir).ok();
}
