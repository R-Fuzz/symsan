//! End-to-end test of the safe binding: build an instrumented target, trace an
//! input, and check that a solved input really does flip the branch.
//!
//! # Why this is all one `#[test]`
//!
//! SymSan allows exactly one [`Session`] per *process* (see the crate docs).
//! `cargo test` runs the `#[test]` functions of one test binary on several
//! threads of a single process, so two session-creating tests in this file
//! would collide -- and not deterministically, which is the worst kind.
//!
//! Cargo compiles each file under `tests/` into its own binary, so the way to
//! get a second session test is a second file, not a second function here.
//! Everything session-shaped therefore lives in `end_to_end` below, and the
//! tests that need no session are unit tests inside `src/lib.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

use symsan::{Config, Session};

/// Build `tests/data/branch.c` with `ko-clang`.
///
/// `KO_USE_FASTGEN=1` selects out-of-process solving -- the target ships its
/// constraints down a pipe to us instead of solving them itself, which is the
/// mode this whole API is about.  `KO_CC` picks the host compiler ko-clang
/// drives; per CLAUDE.md this build wants clang-18.
fn build_target(out_dir: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/branch.c");
    let out = out_dir.join("branch.fg");

    let ko_clang = Path::new(symsan::BUILD_DIR).join("bin/ko-clang");
    assert!(
        ko_clang.is_file(),
        "{} is missing; run `cd b4 && make -j && make install` first",
        ko_clang.display()
    );

    let status = Command::new(&ko_clang)
        .env("KO_CC", "clang-18")
        .env("KO_USE_FASTGEN", "1")
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to run ko-clang");
    assert!(status.success(), "ko-clang failed on {}", src.display());

    out
}

/// Build the same source with a plain compiler, to use as an oracle.
///
/// Checking solutions against the *uninstrumented* program is the point: asking
/// the instrumented one would just be asking SymSan to confirm itself.
fn build_oracle(out_dir: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/branch.c");
    let out = out_dir.join("branch.plain");

    let status = Command::new("clang-18")
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to run clang-18");
    assert!(status.success(), "clang-18 failed on {}", src.display());

    out
}

/// Run the oracle on `input` and return its exit code: 0 = neither check
/// passed, 1 = the `x` check passed, 2 = both did.
fn oracle(bin: &Path, scratch: &Path, input: &[u8]) -> i32 {
    std::fs::write(scratch, input).expect("failed to stage the oracle input");
    Command::new(bin)
        .arg(scratch)
        .output()
        .expect("failed to run the oracle")
        .status
        .code()
        .expect("oracle was killed by a signal")
}

/// A scratch directory of our own, so concurrent test binaries -- and
/// concurrent runs of this one -- do not fight over file names.
fn scratch_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/symsan-test")
        .join(format!("pid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("failed to create the scratch dir");
    dir
}

#[test]
fn end_to_end() {
    let dir = scratch_dir();
    let target = build_target(&dir);
    let plain = build_oracle(&dir);
    let oracle_input = dir.join("oracle_input");

    // The session stages every traced input into this file, and the target
    // reads argv[1]. They have to be the same path or the target reads stale
    // bytes -- hence the path appearing twice below.
    let input_file = dir.join("cur_input");
    let input_file = input_file.to_str().unwrap();

    let config = Config::new(target.to_str().unwrap(), input_file)
        .args([target.to_str().unwrap(), input_file])
        .use_stdin(false)
        .jigsaw(true)
        .z3(true)
        // Small target, so cap the run: a hang here should fail the test
        // rather than wedge CI.
        .timeout_ms(10_000);

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    assert_eq!(
        session.input_file(),
        Path::new(input_file),
        "the session should report back the input file it was configured with"
    );
    assert!(
        session.num_solvers() >= 2,
        "expected at least i2s + jigsaw in the ladder, got {}",
        session.num_solvers()
    );

    // ---- round 1: a seed that fails the very first check -------------------

    let seed = b"AAAAAAAAAAAAAAAA".to_vec();
    assert_eq!(oracle(&plain, &oracle_input, &seed), 0, "seed should take the Bad path");

    let n = session.trace(&seed).expect("trace failed");
    assert!(n > 0, "tracing the seed produced no solving tasks");
    assert_eq!(session.pending_tasks(), n, "pending_tasks disagrees with trace()");

    // Drain the solutions, remembering the one that got furthest. Reporting
    // `false` every time is deliberate here: it makes the session escalate
    // through the whole ladder instead of stopping at the first solver that
    // works, so one round exercises all of them.
    let mut best = (0, Vec::new());
    let mut solutions = 0;
    while let Some(solution) = session.next_solution() {
        solutions += 1;
        assert!(!solution.is_empty(), "solver returned an empty buffer");
        let verdict = oracle(&plain, &oracle_input, &solution);
        if verdict > best.0 {
            best = (verdict, solution);
        }
        session.report_result(false);
        // The ladder is finite, but a bug in the walk would make this loop
        // forever; bound it well above tasks * solvers.
        assert!(solutions < 1000, "next_solution() does not terminate");
    }

    assert!(solutions > 0, "{n} tasks produced no solutions at all");
    assert!(
        best.0 >= 1,
        "none of the {solutions} solutions got past the first check"
    );

    let stats = session.stats();
    assert!(stats.total_branches > 0, "no branches recorded");
    assert_eq!(stats.total_tasks, n as u64, "task count disagrees with trace()");
    assert!(stats.solved_tasks > 0, "no tasks reported as solved");
    // We reported `false` for everything, so nothing should count as a solved
    // *branch* -- that counter tracks what the front-end confirmed, not what a
    // solver claimed.
    assert_eq!(stats.solved_branches, 0, "solved_branches ignored report_result");

    // ---- round 2: feed the solution back in, as a fuzzer would -------------
    //
    // The second check is unreachable in round 1 -- the target never executed
    // it, so no constraint for it exists. Re-tracing the input that got past
    // the first check is what exposes it. This is the loop SymSanStage runs,
    // in miniature.

    let n2 = session.trace(&best.1).expect("re-trace failed");
    assert!(n2 > 0, "re-tracing the round-1 solution produced no tasks");

    let mut solved_all = false;
    let mut solutions2 = 0;
    while let Some(solution) = session.next_solution() {
        solutions2 += 1;
        let verdict = oracle(&plain, &oracle_input, &solution);
        // This time report honestly, which is the whole point of the API:
        // a truthful `true` stops the ladder escalating on a task already won.
        let interesting = verdict > best.0;
        session.report_result(interesting);
        if verdict == 2 {
            solved_all = true;
            break;
        }
        assert!(solutions2 < 1000, "next_solution() does not terminate");
    }
    assert!(
        solved_all,
        "re-tracing did not reach the second check in {solutions2} solutions"
    );
    assert!(
        session.stats().solved_branches > 0,
        "report_result(true) did not register a solved branch"
    );

    // ---- coverage sharing needs a branch map --------------------------------
    //
    // This config has none, so there is no way to know which entry of a
    // coverage map belongs to which branch. Saying so is better than silently
    // ignoring the snapshot and leaving the caller to wonder why nothing
    // changed. tests/branch_map.rs covers the case where a map *is* present.
    match session.set_coverage(&[0u8; 64]) {
        Err(symsan::Error::Invalid(_)) => {}
        Err(e) => panic!("expected Error::Invalid without a branch map, got {e}"),
        Ok(()) => panic!("set_coverage succeeded without a branch map"),
    }

    // ---- process model ------------------------------------------------------

    // One session per process: the second create must fail, not silently hand
    // back a broken handle.
    match Session::new() {
        Err(symsan::Error::Busy(_)) => {}
        Err(e) => panic!("expected Error::Busy for a second session, got {e}"),
        Ok(_) => panic!("a second session was allowed"),
    }

    // ...and dropping the first must release the slot again.
    drop(session);
    let second = Session::new().expect("dropping a session should free the process slot");
    drop(second);

    std::fs::remove_dir_all(&dir).ok();
}
