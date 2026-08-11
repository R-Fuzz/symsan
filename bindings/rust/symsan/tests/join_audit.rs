//! Does the branch map point at the *right* edges?
//!
//! `branch_map.rs` checks that the map is used -- that a covered branch stops
//! producing tasks. It cannot check that the map is *correct*: one resolving
//! every branch to some other branch's edge id would pass it just as well,
//! while in a real run it would silently suppress solving. `mapped_branches`
//! would still look healthy, because a wrong answer is still an answer.
//!
//! Telling the two apart needs ground truth, and `afl-showmap` on the fuzzer's
//! own build of the same source is exactly that: the edge ids that build
//! recorded for one input. Every branch direction the SymSan trace took should
//! resolve to one of them.
//!
//! Needs AFL++; skips with an explanation when it cannot find one, so a
//! checkout without it still gets a green `cargo test`.
//!
//! A separate file from `branch_map.rs` for the usual reason: one [`Session`]
//! per process, one process per test binary.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use symsan::{Config, Session};

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/branch.c")
}

/// Run the fuzzer's build under `afl-showmap` and return the edge ids it hit.
///
/// The default output is one `<edge id>:<hit count>` line per covered edge.
/// Base 10 explicitly -- the ids are zero-padded to six digits, which base 0
/// would read as octal.
fn showmap(afl_showmap: &Path, target: &Path, input: &Path, out_dir: &Path) -> Vec<u32> {
    let out = out_dir.join("showmap.out");
    let status = Command::new(afl_showmap)
        .env("AFL_QUIET", "1")
        .arg("-o")
        .arg(&out)
        .arg("--")
        .arg(target)
        .arg(input)
        .status()
        .expect("failed to run afl-showmap");
    assert!(status.success(), "afl-showmap failed");

    std::fs::read_to_string(&out)
        .expect("failed to read the showmap output")
        .lines()
        .filter_map(|line| line.split(':').next())
        .filter_map(|id| id.trim().parse::<u32>().ok())
        .collect()
}

#[test]
fn join_matches_ground_truth() {
    let (Some(afl_clang_lto), Some(afl_showmap)) = (
        common::find_afl_tool("afl-clang-lto"),
        common::find_afl_tool("afl-showmap"),
    ) else {
        eprintln!(
            "skipping: no afl-clang-lto/afl-showmap found (set AFL_PATH to an \
             AFLplusplus checkout)"
        );
        return;
    };

    let dir = common::scratch_dir("join-audit");
    let built = common::build(&afl_clang_lto, &dir, &source(), "branch", &[]);
    let (afl_bin, map_path, target) = (built.afl, built.bmap, built.symsan);

    // The same bytes go to both builds -- the whole point is to compare what
    // the two of them say about one execution.
    let seed = b"AAAAAAAAAAAAAAAA".to_vec();
    let seed_file = dir.join("seed");
    std::fs::write(&seed_file, &seed).expect("failed to write the seed");
    let covered = showmap(&afl_showmap, &afl_bin, &seed_file, &dir);
    assert!(
        !covered.is_empty(),
        "afl-showmap recorded no edges at all; the coverage build is broken"
    );

    let input_file = dir.join("cur_input");
    let input_file = input_file.to_str().unwrap();
    let config = Config::new(target.to_str().unwrap(), input_file)
        .args([target.to_str().unwrap(), input_file])
        .use_stdin(false)
        .timeout_ms(10_000)
        .branch_map(map_path.to_str().unwrap())
        .validate_coverage(true);

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");
    session.trace(&seed).expect("trace failed");

    let report = session
        .check_coverage(&covered)
        .expect("check_coverage failed on a session with a branch map");
    eprintln!("join audit: {report:?} against {} fuzzer edges", covered.len());

    // Unmapped directions are expected -- AFL++ prunes blocks that dominate
    // their successors -- so the assertion is about the ones it *did* map.
    assert!(
        report.checked > 0,
        "the map resolved none of the {} directions the trace took, so this \
         proves nothing; the two builds disagree about branch names",
        report.executed
    );
    assert!(
        report.is_consistent(),
        "the branch map points at edges the fuzzer's build never recorded: {report:?}"
    );

    // ...and the same check against a ground truth of "nothing was covered"
    // has to fail, or the assertion above was vacuous. Re-checking rather than
    // re-tracing, because the directions the trace took are still on file and
    // a second Session cannot exist in this process.
    let empty = session
        .check_coverage(&[])
        .expect("check_coverage failed on an empty coverage set");
    assert_eq!(
        empty.violations, empty.checked,
        "every checked direction should contradict an empty coverage set: {empty:?}"
    );
    assert!(
        empty.violations > 0,
        "the audit found nothing to contradict, so it cannot detect a wrong map"
    );

    std::fs::remove_dir_all(&dir).ok();
}
