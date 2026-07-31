//! Does [`Session::input_taint`] say the right thing about each input byte?
//!
//! The classification is what lets a fuzzer split the work with SymSan: a byte
//! whose every branch target has been reached can be held still, and the
//! fuzzer's own input-to-state pass then skips every comparison it feeds. A
//! wrong `Settled` freezes a byte that still matters, and nothing downstream
//! would ever notice -- hence this test, which pins all three classes and both
//! ways a byte can become settled.
//!
//! Three phases of one session, because the interesting cases are *sequences*:
//!
//! 1. traced, nothing solved yet -- the branch's bytes are `Open`;
//! 2. solved and accepted -- the same bytes turn `Settled`;
//! 3. re-traced with the solution, which takes the branch the other way -- its
//!    bytes are `Settled` again, this time with no solving involved at all.
//!
//! Phase 3 is the case an implementation keyed on solve outcome gets wrong:
//! nothing was solved in that trace, yet there is nothing left to flip.
//!
//! A file of its own, not a `#[test]` in `session.rs`, for the reason
//! documented there: one [`Session`] per process, one process per test binary.

use std::path::{Path, PathBuf};
use std::process::Command;

use symsan::{Config, Session, TaintClass};

/// Byte ranges of `tests/data/branch.c`: `x` is compared against a magic value,
/// `y` is compared only once `x` matches, and the rest is never read.
const X: std::ops::Range<usize> = 0..4;
const Y: std::ops::Range<usize> = 8..12;
const SEED_LEN: usize = 16;

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/branch.c")
}

fn build_target(out_dir: &Path) -> PathBuf {
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

/// Build the same source with a plain compiler, to use as an oracle: asking the
/// instrumented build whether a solution works would just be asking SymSan to
/// confirm itself.
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

/// Run the oracle on `input`: 0 = neither check passed, 1 = the `x` check
/// passed, 2 = both did.
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
        .join("../target/symsan-input-taint")
        .join(format!("pid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("failed to create the scratch dir");
    dir
}

/// Render a classification as `.` / `o` / `S` per byte, so a failure message
/// shows the whole picture rather than the one offset that tripped.
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
fn classifies_every_byte() {
    let dir = scratch_dir();
    let target = build_target(&dir);
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
        .export_taint(true);

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    // ---- phase 1: traced, nothing solved -----------------------------------

    let seed = vec![b'A'; SEED_LEN];
    assert_eq!(oracle(&plain, &oracle_input, &seed), 0, "seed should take the Bad path");

    let n = session.trace(&seed).expect("trace failed");
    assert!(n > 0, "tracing the seed produced no solving tasks");

    let classes = session.input_taint().expect("input_taint failed");
    assert_eq!(classes.len(), SEED_LEN, "one class per input byte");
    assert_all(
        &classes,
        X,
        TaintClass::Open,
        "the branch reading x is unflipped and unsolved",
    );
    // The negative that matters most: nothing has been solved, so nothing may
    // be frozen. An implementation that classified by "SymSan built a task for
    // it" rather than by coverage would report these settled here.
    assert!(
        !classes.contains(&TaintClass::Settled),
        "no byte can be settled before a single solution was accepted\n  got: {}",
        render(&classes)
    );
    // y is only compared once x matches, so this trace never reached it.
    assert_all(&classes, Y, TaintClass::Untainted, "y is not read on this path");
    assert_all(
        &classes,
        4..8,
        TaintClass::Untainted,
        "these bytes are never read at all",
    );

    // ---- phase 2: solved and accepted --------------------------------------

    let mut best = (0, Vec::new());
    let mut solutions = 0;
    while let Some(solution) = session.next_solution() {
        solutions += 1;
        let verdict = oracle(&plain, &oracle_input, &solution);
        // Honest reporting is the whole point here: `true` is what marks the
        // target reached, and input_taint() reads exactly that.
        let interesting = verdict > best.0;
        if interesting {
            best = (verdict, solution);
        }
        session.report_result(interesting);
        assert!(solutions < 1000, "next_solution() does not terminate");
    }
    assert!(
        best.0 >= 1,
        "none of the {solutions} solutions got past the first check"
    );

    let classes = session.input_taint().expect("input_taint failed");
    assert_all(
        &classes,
        X,
        TaintClass::Settled,
        "the branch reading x was solved and the solution accepted",
    );
    assert_all(
        &classes,
        4..8,
        TaintClass::Untainted,
        "solving x says nothing about bytes nothing reads",
    );

    // ---- phase 3: settled without solving ----------------------------------
    //
    // Re-tracing the solution takes the outer branch the *other* way, so both
    // of its directions have now been executed and there is nothing left to
    // flip -- even though this trace solved nothing. Deliberately asserted
    // before draining a single solution.

    let n2 = session.trace(&best.1).expect("re-trace failed");
    assert!(n2 > 0, "re-tracing the solution produced no tasks");

    let classes = session.input_taint().expect("input_taint failed");
    assert_all(
        &classes,
        X,
        TaintClass::Settled,
        "this trace took the outer branch the other way, reaching both targets",
    );
    assert_all(
        &classes,
        Y,
        TaintClass::Open,
        "the inner branch is reached now, and neither solved nor covered",
    );
    assert_all(
        &classes,
        12..16,
        TaintClass::Untainted,
        "these bytes are never read at all",
    );

    // ---- the gate ----------------------------------------------------------
    //
    // Without export_taint there is nothing to report, and saying so beats
    // handing back an all-zero answer that reads as "nothing is tainted".
    let mut bare = Config::new(target.to_str().unwrap(), input_file);
    bare = bare.args([target.to_str().unwrap(), input_file]).use_stdin(false);
    drop(session);
    let mut off = Session::new().expect("dropping a session should free the process slot");
    off.init(&bare).expect("failed to initialize the second session");
    match off.input_taint() {
        Err(symsan::Error::Invalid(_)) => {}
        Err(e) => panic!("expected Error::Invalid without export_taint, got {e}"),
        Ok(c) => panic!("input_taint succeeded without export_taint: {}", render(&c)),
    }

    std::fs::remove_dir_all(&dir).ok();
}
