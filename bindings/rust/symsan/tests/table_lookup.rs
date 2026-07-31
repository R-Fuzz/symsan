//! A load from a constant lookup table is symbolic, and the solver ladder
//! handles it end to end through the safe binding.
//!
//! Two things are under test, and they pull in opposite directions:
//!
//! 1. i2s solves it. The compared value never appears in the input -- only the
//!    index into the table does -- so this cannot be a value match; the solver
//!    has to walk the AST, scan the shipped table bytes for the wanted output
//!    and drive the index expression to its position. Each target byte pins one
//!    nibble of one input byte, so the two halves have to agree rather than
//!    overwrite each other.
//!
//! 2. jigsaw and z3 *decline* it, by design -- no symbolic arrays. Reporting
//!    `false` for every solution below makes the session escalate through the
//!    whole ladder rather than stopping at i2s, so this run puts both declines
//!    on the path. The assertion that matters is not that they produce nothing
//!    (expected) but that the session survives them and still yields i2s's
//!    answer: a decline must not abort the walk or the run.
//!
//! A file of its own for the usual reason: one [`Session`] per process, one
//! process per test binary (see `tests/session.rs`).

use std::path::{Path, PathBuf};
use std::process::Command;

/// `tests/data/table_lookup.c` reads this many bytes and hex-encodes each.
const INPUT_SIZE: usize = 8;

/// The one input whose hex encoding is "4142434445464748".
const ANSWER: &[u8] = b"ABCDEFGH";

use symsan::{Config, Session};

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/table_lookup.c")
}

/// Build the target with `ko-clang`. `KO_USE_FASTGEN=1` selects out-of-process
/// solving, which is the mode this API is about; `KO_CC` picks the host
/// compiler, clang-18 per CLAUDE.md.
fn build_target(out_dir: &Path) -> PathBuf {
    let out = out_dir.join("table_lookup.fg");

    let ko_clang = Path::new(symsan::BUILD_DIR).join("bin/ko-clang");
    assert!(
        ko_clang.is_file(),
        "{} is missing; run `cd b4 && make -j && make install` first",
        ko_clang.display()
    );

    let status = Command::new(&ko_clang)
        .env("KO_CC", "clang-18")
        .env("KO_USE_FASTGEN", "1")
        // ko-clang defaults to -O3, which constant-folds the encoding loop into
        // something with no table load left to label.
        .env("KO_DONT_OPTIMIZE", "1")
        .arg(source())
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to run ko-clang");
    assert!(status.success(), "ko-clang failed on {}", source().display());

    out
}

/// Build the same source with a plain compiler, to use as an oracle. Checking
/// solutions against the *uninstrumented* program is the point: asking the
/// instrumented one would just be asking SymSan to confirm itself.
fn build_oracle(out_dir: &Path) -> PathBuf {
    let out = out_dir.join("table_lookup.plain");

    let status = Command::new("clang-18")
        .arg("-O0")
        .arg(source())
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to run clang-18");
    assert!(status.success(), "clang-18 failed on {}", source().display());

    out
}

/// Run the oracle on `input` and return its exit code: 0 = no match, 1 = match.
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
        .join("../target/symsan-table-lookup")
        .join(format!("pid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("failed to create the scratch dir");
    dir
}

#[test]
fn a_lookup_table_is_solvable() {
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
        // both on, so the declines are exercised rather than skipped
        .jigsaw(true)
        .z3(true)
        // Small target, so cap the run: a hang here should fail the test rather
        // than wedge CI.
        .timeout_ms(10_000);

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    let seed = vec![b'a'; INPUT_SIZE];
    assert_eq!(
        oracle(&plain, &oracle_input, &seed),
        0,
        "the seed should not already satisfy the check"
    );

    let n = session.trace(&seed).expect("trace failed");
    assert!(
        n > 0,
        "tracing produced no solving tasks: the strncmp is still concrete, so \
         the table load is not being labelled at all"
    );

    // Report `false` throughout so the session escalates past i2s into jigsaw
    // and z3 instead of stopping at the first solver that works.
    let mut winner = None;
    let mut solutions = 0;
    while let Some(solution) = session.next_solution() {
        solutions += 1;
        assert!(!solution.is_empty(), "solver returned an empty buffer");
        if oracle(&plain, &oracle_input, &solution) == 1 && winner.is_none() {
            winner = Some(solution);
        }
        session.report_result(false);
        // The ladder is finite, but a bug in the walk would make this loop
        // forever; bound it well above tasks * solvers.
        assert!(solutions < 1000, "next_solution() does not terminate");
    }

    let winner = winner.unwrap_or_else(|| {
        panic!("none of the {solutions} solutions from {n} tasks satisfied the check")
    });
    assert_eq!(
        winner, ANSWER,
        "the encoding has exactly one preimage, so anything else means the \
         check was satisfied by accident"
    );

    std::fs::remove_dir_all(&dir).ok();
}
