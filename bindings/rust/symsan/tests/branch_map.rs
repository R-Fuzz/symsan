//! End-to-end test of the shared branch namespace: build the same source both
//! ways out of one AFL++ LTO link, so a SymSan branch id *is* one of AFL++'s
//! edge ids, and check that a branch the fuzzer has already covered stops
//! producing solving tasks.
//!
//! This is a second file rather than a second `#[test]` in `session.rs` for the
//! reason documented there: one [`Session`] per process, one process per test
//! binary. It also gives us the A/B, since `session.rs` asserts that re-tracing
//! the round-1 solution *does* produce tasks when no branch map is in play.
//!
//! Needs AFL++; skips with an explanation when it cannot find one, so a
//! checkout without it still gets a green `cargo test`.

mod common;

use symsan::{Config, Session};

use common::MAP_SIZE;

fn source() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/branch.c")
}

#[test]
fn shared_coverage() {
    let Some(afl_clang_lto) = common::find_afl_tool("afl-clang-lto") else {
        eprintln!("skipping: no afl-clang-lto found (set AFL_PATH to an AFLplusplus checkout)");
        return;
    };

    let dir = common::scratch_dir("branch-map");
    let built = common::build(&afl_clang_lto, &dir, &source(), "branch", &[]);
    let map_path = built.bmap;
    let target = built.symsan;

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
        .branch_map(map_path.to_str().unwrap());

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    // ---- round 1: nothing covered yet --------------------------------------
    //
    // An all-zero snapshot says "the fuzzer has covered nothing", so the map
    // can only ever agree that a branch is worth solving. That makes this round
    // a clean measurement of the *join rate* on its own.

    session
        .set_coverage(&vec![0u8; MAP_SIZE])
        .expect("set_coverage failed on a session with a branch map");

    let seed = b"AAAAAAAAAAAAAAAA".to_vec();
    let n = session.trace(&seed).expect("trace failed");
    assert!(n > 0, "tracing the seed with an empty coverage map produced no tasks");

    let stats = session.stats();
    eprintln!(
        "join rate: {} mapped, {} unmapped",
        stats.mapped_branches, stats.unmapped_branches
    );
    assert!(
        stats.mapped_branches + stats.unmapped_branches > 0,
        "the shared-map manager was never consulted; is branch_map plumbed through?"
    );
    // Deliberately not "all mapped", and not even "any mapped" this early:
    // AFL++ prunes blocks that dominate all their successors, and on this
    // target the only branch round 1 asks about is the outer `if (x == ...)`
    // taken false -- whose true side is exactly what got pruned, and so has no
    // edge to look up. See include/branch_map.h. The map is asserted after
    // round 2, which reaches the inner branch, where both directions have ids.

    // Solve far enough to reach the inner branch, exactly as session.rs does.
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

    // ---- round 2: everything covered ---------------------------------------
    //
    // Re-tracing the round-1 solution is what exposes the inner branch, and
    // session.rs asserts that without a branch map this produces tasks. Here
    // the fuzzer claims to have covered every edge already, so the same trace
    // should produce none: the inner branch is new to *us* but not to the
    // fuzzer, and re-solving it would be wasted work.

    let before = session.stats();
    session
        .set_coverage(&vec![1u8; MAP_SIZE])
        .expect("set_coverage failed");

    let n2 = session.trace(&best.1).expect("re-trace failed");
    let after = session.stats();
    eprintln!(
        "after round 2: {} mapped, {} unmapped, {n2} tasks",
        after.mapped_branches, after.unmapped_branches
    );

    assert!(
        after.mapped_branches > before.mapped_branches,
        "the second trace joined nothing ({} lookups, all missed) -- the two \
         builds disagree about branch names",
        after.unmapped_branches - before.unmapped_branches
    );
    assert_eq!(
        n2, 0,
        "re-tracing produced {n2} tasks even though every edge is marked \
         covered ({} branches to solve, up from {})",
        after.branches_to_solve, before.branches_to_solve
    );
    assert_eq!(
        after.branches_to_solve, before.branches_to_solve,
        "a fully covered map still found branches worth solving"
    );

    std::fs::remove_dir_all(&dir).ok();
}
