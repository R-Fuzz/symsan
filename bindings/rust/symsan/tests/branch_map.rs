//! End-to-end test of the shared branch namespace: build the same source with
//! AFL++'s LTO instrumentation *and* with ko-clang, join the two by source
//! location, and check that a branch the fuzzer has already covered stops
//! producing solving tasks.
//!
//! This is a second file rather than a second `#[test]` in `session.rs` for the
//! reason documented there: one [`Session`] per process, one process per test
//! binary. It also gives us the A/B, since `session.rs` asserts that re-tracing
//! the round-1 solution *does* produce tasks when no branch map is in play.
//!
//! Needs a patched AFL++ (`patches/aflpp-document-ids.patch`); skips with an
//! explanation when it cannot find one, so a checkout without AFL++ still gets
//! a green `cargo test`.

use std::path::{Path, PathBuf};
use std::process::Command;

use symsan::{Config, Session};

/// AFL++'s coverage map size, and therefore how long a snapshot we hand the
/// session. Any length works -- an edge id past the end reads as "not covered"
/// -- but matching the real thing is what the fuzzer will actually pass.
const MAP_SIZE: usize = 65536;

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
fn build_afl_target(afl_clang_lto: &Path, out_dir: &Path) -> (PathBuf, PathBuf) {
    let out = out_dir.join("branch.afl");
    let map = out_dir.join("branch.map");
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
        .join("../target/symsan-branch-map")
        .join(format!("pid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("failed to create the scratch dir");
    dir
}

#[test]
fn shared_coverage() {
    let Some(afl_clang_lto) = find_afl_clang_lto() else {
        eprintln!(
            "skipping: no afl-clang-lto found (set AFL_PATH to an AFLplusplus \
             checkout with patches/aflpp-document-ids.patch applied)"
        );
        return;
    };

    let dir = scratch_dir();
    let (_afl_bin, map_path) = build_afl_target(&afl_clang_lto, &dir);

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
    // taken false -- whose true side is exactly what got pruned. See
    // patches/README.md. The join is asserted after round 2, which reaches the
    // inner branch, where both directions do have ids.

    // Solve far enough to reach the inner branch, exactly as session.rs does.
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
