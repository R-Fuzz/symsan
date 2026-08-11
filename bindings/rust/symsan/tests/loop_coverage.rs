//! A branch inside a loop stays solvable -- across iterations, and across
//! traces.
//!
//! `EdgeCovManager` keys its record on the branch *address* and keeps it for the
//! life of the session, so a loop over the input is solvable exactly twice:
//! once for each direction, ever. The remaining iterations, and every later
//! trace, ask `is_branch_interesting` and are told no. `fgtest` never sees this
//! -- fresh process per input -- but a fuzzer holds one session for its whole
//! run, which is where a target like fuzzer-challenges' `test-crc32` stalls.
//!
//! Given the fuzzer's own branch map, `SharedMapCovManager` answers the question
//! the fuzzer would answer instead, and the answer depends on hit *counts*, not
//! just on whether an edge was ever walked -- `MaxMapFeedback` compares
//! `HitcountsMapObserver`'s buckets, so the second traversal of an edge is a
//! different observation from the first. The three phases below pin exactly
//! that: the map overrules our own stale record, hit counts distinguish
//! iterations, and an edge the fuzzer has already saturated still stops us.
//!
//! Needs AFL++; skips with an explanation when it cannot find one, so a
//! checkout without it still gets a green `cargo test`. A file of its own for
//! the usual reason: one [`Session`] per process, one process per test binary.

mod common;

use std::path::{Path, PathBuf};

use symsan::{Config, Session};

use common::MAP_SIZE;

/// `tests/data/taint_loop.c` compares this many leading bytes, one per
/// iteration of a single static branch, and never reads the rest.
const LOOP_BYTES: usize = 8;
const SEED_LEN: usize = 16;

/// This test is about one static branch traversed eight times, not eight
/// branches traversed once, so the loop must survive to the binary: at -O2 it
/// is fully unrolled, and the increment becomes a `select` with no branch at
/// all.  One flag does it for both arms now, because both arms come out of the
/// same compile -- it used to need `-O0` on one side and `KO_DONT_OPTIMIZE` on
/// the other, and nothing but care kept the two in step.
const CFLAGS: &[&str] = &["-O0"];

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/taint_loop.c")
}

#[test]
fn a_loop_branch_stays_solvable() {
    let Some(afl_clang_lto) = common::find_afl_tool("afl-clang-lto") else {
        eprintln!("skipping: no afl-clang-lto found (set AFL_PATH to an AFLplusplus checkout)");
        return;
    };

    let dir = common::scratch_dir("loop-coverage");
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

    // One 'Z' and seven not, so a single trace takes the branch both ways --
    // which is exactly what fills in `EdgeCovManager`'s two bits and makes it
    // answer "covered" forever after.
    let mut seed = vec![b'A'; SEED_LEN];
    seed[0] = b'Z';

    // ---- A: the fuzzer has covered nothing ---------------------------------

    session
        .set_coverage(&vec![0u8; MAP_SIZE])
        .expect("set_coverage failed on a session with a branch map");
    session.trace(&seed).expect("trace failed");
    let a = session.stats();
    assert_eq!(
        a.total_branches, LOOP_BYTES as u64,
        "the loop should report one branch per byte it compares; with {} the \
         build is not the shape this test is about",
        a.total_branches
    );
    assert!(
        a.unmapped_branches == 0,
        "{} of {} branch lookups missed the map, so this run would be testing \
         the fallback rather than the map",
        a.unmapped_branches,
        a.mapped_branches + a.unmapped_branches
    );
    assert_eq!(
        a.branches_to_solve, LOOP_BYTES as u64,
        "with nothing covered every iteration is worth solving. Letting our own \
         record veto gets 1: iteration 0 takes the branch one way and is solved \
         for the other, and from iteration 1 on both of its two bits are set."
    );

    // ---- B: the same input again, same snapshot ----------------------------
    //
    // Nothing about the world changed, so the answer must not either. Our own
    // record did change -- both directions of this branch are now in it -- and
    // letting that veto is what used to make the second trace produce nothing.

    session.trace(&seed).expect("re-trace failed");
    let b = session.stats();
    assert_eq!(
        b.branches_to_solve - a.branches_to_solve,
        LOOP_BYTES as u64,
        "re-tracing the same input with the same coverage produced {} solvable \
         branches instead of {LOOP_BYTES}; the session-lifetime record is \
         overruling the fuzzer's",
        b.branches_to_solve - a.branches_to_solve
    );

    // ---- C: every edge walked once -----------------------------------------
    //
    // Iteration 1 would land the flipped edge in hit-count class 1, which the
    // snapshot already claims, so it is not worth solving. Iterations 2..8 land
    // in classes 2 and 4, which it does not. Asking `host_[e] == 0` instead --
    // "walked at all?" -- collapses all eight to "covered" and is what pins a
    // loop shut once the fuzzer has been round it once.

    session.set_coverage(&vec![1u8; MAP_SIZE]).expect("set_coverage failed");
    session.trace(&seed).expect("re-trace failed");
    let c = session.stats();
    assert_eq!(
        c.branches_to_solve - b.branches_to_solve,
        LOOP_BYTES as u64 - 1,
        "with every edge at one hit, the {} iterations past the first should \
         still be solvable, got {}",
        LOOP_BYTES - 1,
        c.branches_to_solve - b.branches_to_solve
    );

    // ---- D: every edge saturated -------------------------------------------
    //
    // 255 hits is AFL's top bucket, which no number of iterations can beat, so
    // the count-class test has to come back "covered" for all of them. The
    // control for C: without it, a relaxation that always says "new" would pass
    // every assertion above.

    session.set_coverage(&vec![255u8; MAP_SIZE]).expect("set_coverage failed");
    session.trace(&seed).expect("re-trace failed");
    let d = session.stats();
    assert_eq!(
        d.branches_to_solve, c.branches_to_solve,
        "the fuzzer has hit every edge 255 times; {} iterations were still \
         reported worth solving",
        d.branches_to_solve - c.branches_to_solve
    );

    std::fs::remove_dir_all(&dir).ok();
}
