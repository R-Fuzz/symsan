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
//! Needs a patched AFL++ (`patches/aflpp-document-ids.patch`); skips with an
//! explanation when it cannot find one, so a checkout without AFL++ still gets
//! a green `cargo test`. A file of its own for the usual reason: one
//! [`Session`] per process, one process per test binary.

use std::path::{Path, PathBuf};
use std::process::Command;

use symsan::{Config, Session, TaintClass};

/// AFL++'s coverage map size, and therefore how long a snapshot we hand the
/// session.
const MAP_SIZE: usize = 65536;

/// Byte ranges of `tests/data/branch.c`: `x` gates the path, `y` is compared
/// only once `x` matches.
const X: std::ops::Range<usize> = 0..4;
const Y: std::ops::Range<usize> = 8..12;
const SEED_LEN: usize = 16;

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/branch.c")
}

/// Where to find `afl-clang-lto`: `$AFL_PATH`, then the sibling checkout this
/// repo is usually cloned next to, then `$PATH`.
fn find_afl_clang_lto() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("AFL_PATH") {
        let p = PathBuf::from(dir).join("afl-clang-lto");
        if p.is_file() {
            return Some(p);
        }
    }
    let sibling = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../aflpp/afl-clang-lto");
    if sibling.is_file() {
        return Some(sibling);
    }
    let out = Command::new("which").arg("afl-clang-lto").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    path.is_file().then_some(path)
}

/// Build the coverage target and its id map. `-g` is required: without debug
/// locations there is nothing to join on.
fn build_afl_target(afl_clang_lto: &Path, out_dir: &Path) -> PathBuf {
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

    map
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

fn build_oracle(out_dir: &Path) -> PathBuf {
    let out = out_dir.join("branch.plain");
    let status = Command::new("clang-18")
        .arg(source())
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to run clang-18");
    assert!(status.success(), "clang-18 failed");
    out
}

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

fn scratch_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/symsan-input-taint-map")
        .join(format!("pid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("failed to create the scratch dir");
    dir
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
    let Some(afl_clang_lto) = find_afl_clang_lto() else {
        eprintln!(
            "skipping: no afl-clang-lto found (set AFL_PATH to an AFLplusplus \
             checkout with patches/aflpp-document-ids.patch applied)"
        );
        return;
    };

    let dir = scratch_dir();
    let map_path = build_afl_target(&afl_clang_lto, &dir);

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
    let plain = build_oracle(&dir);
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
    // the outer branch's taken side (see patches/README.md). So the A/B below
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
        let verdict = oracle(&plain, &oracle_input, &solution);
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
