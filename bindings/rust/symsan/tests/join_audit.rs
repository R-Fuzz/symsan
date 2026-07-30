//! Does the branch map point at the *right* edges?
//!
//! `branch_map.rs` checks that the join is used -- that a covered branch stops
//! producing tasks. It cannot check that the join is *correct*: a map resolving
//! every branch to some other branch's edge id would pass it just as well,
//! while in a real run it would silently suppress solving. `mapped_branches`
//! would still look healthy, because a wrong answer is still an answer.
//!
//! Telling the two apart needs ground truth, and `afl-showmap` on the fuzzer's
//! own build of the same source is exactly that: the edge ids that build
//! recorded for one input. Every branch direction the SymSan trace took should
//! resolve to one of them.
//!
//! Needs a patched AFL++ (`patches/aflpp-document-ids.patch`); skips with an
//! explanation when it cannot find one, so a checkout without AFL++ still gets
//! a green `cargo test`.
//!
//! A separate file from `branch_map.rs` for the usual reason: one [`Session`]
//! per process, one process per test binary.

use std::path::{Path, PathBuf};
use std::process::Command;

use symsan::{Config, Session};

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/branch.c")
}

/// Where to find one of AFL++'s tools: `$AFL_PATH`, then the sibling checkout
/// this repo is usually cloned next to, then `$PATH`.
fn find_afl_tool(name: &str) -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("AFL_PATH") {
        let p = PathBuf::from(dir).join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    let sibling = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../aflpp").join(name);
    if sibling.is_file() {
        return Some(sibling);
    }
    let out = Command::new("which").arg(name).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    path.is_file().then_some(path)
}

/// Build the coverage target and its id map. `-g` is required: without debug
/// locations there is nothing to join on.
fn build_afl_target(afl_clang_lto: &Path, out_dir: &Path) -> (PathBuf, PathBuf) {
    let out = out_dir.join("branch.afl");
    let map = out_dir.join("branch.map");
    // AFL++ appends to the id file, so a leftover from an earlier run would
    // still be in there claiming edge ids this binary never assigned.
    let _ = std::fs::remove_file(&map);

    let status = Command::new(afl_clang_lto)
        .env("AFL_LLVM_DOCUMENT_IDS", &map)
        .env("AFL_QUIET", "1")
        .arg("-g")
        .arg(source())
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to run afl-clang-lto");
    assert!(status.success(), "afl-clang-lto failed");

    (out, map)
}

fn build_symsan_target(out_dir: &Path) -> PathBuf {
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
        .arg(source())
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to run ko-clang");
    assert!(status.success(), "ko-clang failed");

    out
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

fn scratch_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/symsan-join-audit")
        .join(format!("pid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("failed to create the scratch dir");
    dir
}

#[test]
fn join_matches_ground_truth() {
    let (Some(afl_clang_lto), Some(afl_showmap)) =
        (find_afl_tool("afl-clang-lto"), find_afl_tool("afl-showmap"))
    else {
        eprintln!(
            "skipping: no afl-clang-lto/afl-showmap found (set AFL_PATH to an \
             AFLplusplus checkout with patches/aflpp-document-ids.patch applied)"
        );
        return;
    };

    let dir = scratch_dir();
    let (afl_bin, map_path) = build_afl_target(&afl_clang_lto, &dir);

    let map_text = std::fs::read_to_string(&map_path).unwrap_or_default();
    if !map_text.contains(" src=") {
        eprintln!(
            "skipping: {} has no src= fields, so {} is an unpatched AFL++ \
             (apply patches/aflpp-document-ids.patch)",
            map_path.display(),
            afl_clang_lto.display()
        );
        std::fs::remove_dir_all(&dir).ok();
        return;
    }

    let target = build_symsan_target(&dir);

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
