//! A branch SymSan declined to *solve* still leaves its bytes worth mutating.
//!
//! `on_cond` throttles a branch it has already seen `max_local_branch_counter`
//! times on this input, so a loop over the input produces a handful of solving
//! tasks and then nothing. The bytes the throttled iterations read must still
//! come back tainted and `Open`: the dependency is recorded before the throttle
//! runs, and the other direction of those iterations is still unreached.
//!
//! This is the negative for the ordering inside `on_cond`. Record the
//! dependency after the throttle instead and the test target's last six bytes
//! come back `Untainted` -- which a fuzzer would read as "nothing here", and
//! stop mutating the very bytes that decide the loop.
//!
//! A file of its own for the usual reason: one [`Session`] per process, one
//! process per test binary. It needs its own [`Config`] anyway, since the
//! throttle has to be turned down to bite on a loop this short.

use std::path::{Path, PathBuf};
use std::process::Command;

use symsan::{Config, Session, TaintClass};

/// `tests/data/taint_loop.c` compares this many leading bytes, one per
/// iteration of a single static branch, and never reads the rest.
const LOOP_BYTES: usize = 8;
const SEED_LEN: usize = 16;
/// How many iterations get past the throttle: `on_cond` lets a branch through
/// while its per-input counter is `<=` the limit, so a limit of 1 admits two.
const THROTTLE: u8 = 1;
const ADMITTED: u64 = THROTTLE as u64 + 1;

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/taint_loop.c")
}

fn build_target(out_dir: &Path) -> PathBuf {
    let out = out_dir.join("taint_loop.fg");
    let ko_clang = Path::new(symsan::BUILD_DIR).join("bin/ko-clang");
    assert!(
        ko_clang.is_file(),
        "{} is missing; run `cd b4 && make -j && make install` first",
        ko_clang.display()
    );

    let status = Command::new(&ko_clang)
        .env("KO_CC", "clang-18")
        .env("KO_USE_FASTGEN", "1")
        // ko-clang defaults to -O3, which unrolls this loop -- and the throttle
        // counts *per static branch*, so eight copies of the branch would never
        // trip it. -O3 also turns the increment into a `select` and removes the
        // branch entirely. Unoptimized is the only build that has the shape this
        // test is about.
        .env("KO_DONT_OPTIMIZE", "1")
        .arg(source())
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to run ko-clang");
    assert!(status.success(), "ko-clang failed");
    out
}

fn scratch_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/symsan-input-taint-throttle")
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

#[test]
fn throttled_branches_keep_their_bytes_open() {
    let dir = scratch_dir();
    let target = build_target(&dir);
    let input_file = dir.join("cur_input");
    let input_file = input_file.to_str().unwrap();

    let config = Config::new(target.to_str().unwrap(), input_file)
        .args([target.to_str().unwrap(), input_file])
        .use_stdin(false)
        .jigsaw(true)
        .z3(true)
        .timeout_ms(10_000)
        .max_local_branch_counter(THROTTLE)
        .export_taint(true);

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    // No byte is 'Z', so every iteration takes the branch the same way and the
    // other direction stays unreached throughout.
    let seed = vec![b'A'; SEED_LEN];
    session.trace(&seed).expect("trace failed");

    let stats = session.stats();
    assert_eq!(
        stats.total_branches, LOOP_BYTES as u64,
        "the loop should report one branch per byte it compares"
    );
    assert_eq!(
        stats.branches_to_solve, ADMITTED,
        "the throttle should have admitted {ADMITTED} of the {LOOP_BYTES} \
         iterations; with {} the test proves nothing about the rest",
        stats.branches_to_solve
    );

    let classes = session.input_taint().expect("input_taint failed");
    assert_eq!(classes.len(), SEED_LEN, "one class per input byte");
    for i in 0..LOOP_BYTES {
        assert_eq!(
            classes[i],
            TaintClass::Open,
            "byte {i} is read by iteration {i}, which is {} -- either way its \
             target is unreached\n  got: {}",
            if (i as u64) < ADMITTED { "solved for" } else { "throttled away" },
            render(&classes)
        );
    }
    for i in LOOP_BYTES..SEED_LEN {
        assert_eq!(
            classes[i],
            TaintClass::Untainted,
            "byte {i} is past the loop and never read\n  got: {}",
            render(&classes)
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}
