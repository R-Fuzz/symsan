//! A byte is settled by the *fuzzer's* coverage too, not just by ours.
//!
//! `input_taint.rs` covers the two ways a session can settle a byte on its own:
//! it solved the branch and the solution was accepted, or a later trace took
//! the branch the other way. This file covers the third, and the one that makes
//! the feature fire on a real run -- the branch map says the target is an edge
//! the fuzzer has already covered, so there is nothing left for anybody to
//! flip there.
//!
//! Two traces of the very same input, differing only in the coverage snapshot
//! handed to [`Session::set_coverage`], so the map is the only thing that can
//! account for the change. It also pins the counter discipline: asking about a
//! target again at export time must not move `mapped_branches`, which is a
//! census of the branches the *trace* saw.
//!
//! Needs AFL++; skips with an explanation when it cannot find one, so a
//! checkout without it still gets a green `cargo test`. A file of its own for
//! the usual reason: one [`Session`] per process, one process per test binary.

mod common;

use std::path::{Path, PathBuf};

use symsan::{Config, Session, TaintClass};

use common::MAP_SIZE;

/// Byte ranges of `tests/data/branch.c`: `x` gates the path, `y` is compared
/// only once `x` matches.
const X: std::ops::Range<usize> = 0..4;
const Y: std::ops::Range<usize> = 8..12;
const SEED_LEN: usize = 16;

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/branch.c")
}

fn render(classes: &[TaintClass]) -> String {
    classes
        .iter()
        .map(|c| match c {
            TaintClass::Untainted => '.',
            TaintClass::Open => 'o',
            TaintClass::Settled => 'S',
        })
        .collect()
}

fn assert_all(classes: &[TaintClass], range: std::ops::Range<usize>, want: TaintClass, why: &str) {
    for i in range.clone() {
        assert_eq!(
            classes[i],
            want,
            "byte {i} of {range:?} should be {want:?} -- {why}\n  got: {}",
            render(classes)
        );
    }
}

#[test]
fn the_fuzzers_coverage_settles_bytes() {
    let Some(afl_clang_lto) = common::find_afl_tool("afl-clang-lto") else {
        eprintln!("skipping: no afl-clang-lto found (set AFL_PATH to an AFLplusplus checkout)");
        return;
    };

    let dir = common::scratch_dir("input-taint-map");
    let built = common::build(&afl_clang_lto, &dir, &source(), "branch", &[]);
    let (map_path, target) = (built.bmap, built.symsan);
    let plain = common::build_oracle(&dir, &source(), "branch");
    let oracle_input = dir.join("oracle_input");
    let input_file = dir.join("cur_input");
    let input_file = input_file.to_str().unwrap();

    let config = Config::new(target.to_str().unwrap(), input_file)
        .args([target.to_str().unwrap(), input_file])
        .use_stdin(false)
        .jigsaw(true)
        .z3(true)
        .timeout_ms(10_000)
        .branch_map(map_path.to_str().unwrap())
        .export_taint(true);

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    // ---- get to the inner branch -------------------------------------------
    //
    // Only the inner `if (y == ...)` has edge ids for both directions -- AFL++
    // prunes blocks that dominate all their successors, which on this target is
    // the outer branch's taken side (see include/branch_map.h). So the A/B below
    // has to be run on an input that reaches it, which means solving the outer
    // check first. Reporting `false` throughout: this phase is setup, and a
    // flipped target would settle bytes for a reason other than the map.

    session
        .set_coverage(&vec![0u8; MAP_SIZE])
        .expect("set_coverage failed on a session with a branch map");

    let seed = vec![b'A'; SEED_LEN];
    let n = session.trace(&seed).expect("trace failed");
    assert!(n > 0, "tracing the seed with an empty coverage map produced no tasks");

    let mut best = (0, Vec::new());
    let mut solutions = 0;
    while let Some(solution) = session.next_solution() {
        solutions += 1;
        let verdict = common::oracle(&plain, &oracle_input, &solution);
        if verdict > best.0 {
            best = (verdict, solution);
        }
        session.report_result(false);
        assert!(solutions < 1000, "next_solution() does not terminate");
    }
    assert!(
        best.0 >= 1,
        "none of the {solutions} solutions got past the first check"
    );

    // ---- A: the fuzzer has covered nothing ---------------------------------

    session.set_coverage(&vec![0u8; MAP_SIZE]).expect("set_coverage failed");
    session.trace(&best.1).expect("re-trace failed");

    let before = session.stats();
    let uncovered = session.input_taint().expect("input_taint failed");
    let after = session.stats();
    assert_eq!(
        (after.mapped_branches, after.unmapped_branches),
        (before.mapped_branches, before.unmapped_branches),
        "input_taint() moved the join counters; they are a census of the \
         branches the trace saw, and re-asking must not add to them"
    );

    assert_eq!(uncovered.len(), SEED_LEN, "one class per input byte");
    assert_all(
        &uncovered,
        Y,
        TaintClass::Open,
        "the inner branch is unsolved and, by this snapshot, unreached",
    );
    // The outer branch is decided by the map too. Only its *taken* side was
    // pruned by AFL++; the side this trace did not take has an edge id, so the
    // snapshot answers for it -- and this snapshot claims nothing is covered.
    // That the session itself walked both directions, across the seed trace and
    // this one, no longer overrules that: a branch the map can name is the
    // fuzzer's call, which is the whole point of sharing coverage. (Before that
    // rule, our own session-lifetime record won here and these bytes came back
    // Settled.) Asserted so a failure shows which half moved.
    assert_all(
        &uncovered,
        X,
        TaintClass::Open,
        "the snapshot claims no edge is covered, and the direction this trace \
         did not take has one",
    );

    // ---- B: the same trace, with the fuzzer claiming everything ------------

    session.set_coverage(&vec![1u8; MAP_SIZE]).expect("set_coverage failed");
    let n2 = session.trace(&best.1).expect("re-trace failed");
    assert_eq!(
        n2, 0,
        "re-tracing produced {n2} tasks even though every edge is marked covered"
    );

    let covered = session.input_taint().expect("input_taint failed");
    assert_all(
        &covered,
        Y,
        TaintClass::Settled,
        "the fuzzer's map says the inner branch's other direction is already an \
         edge it has walked",
    );
    assert!(
        !covered.contains(&TaintClass::Open),
        "with every edge covered there is nothing left for a fuzzer to flip\n  \
         got: {}",
        render(&covered)
    );
    assert_all(
        &covered,
        4..8,
        TaintClass::Untainted,
        "a covered map does not make unread bytes interesting",
    );

    std::fs::remove_dir_all(&dir).ok();
}
