//! Solving for undefined behaviour, and keeping it out of the coverage books.
//!
//! Two things are being checked here, and they pull in opposite directions.
//!
//! **That it happens at all.** [`Config::solve_ub`] is off by default, and
//! nothing else in the tree turns it on for a real target, so the whole path --
//! the flag reaching the child's `TAINT_OPTIONS`, the runtime raising a check on
//! a tainted divisor, the session building a task for it, a solver satisfying it
//! -- has never been exercised end to end from Rust. The proof is the plain
//! build dying on one of the solutions: an x86 integer division by zero traps,
//! so SIGFPE is the target telling us the input really is undefined, not us
//! telling ourselves.
//!
//! **That it stays out of the coverage bookkeeping.** A UB check is not a branch
//! in the program. Its cid is an `enum undefined_check_ids` value -- one of
//! sixteen, shared by every division in the program, and below
//! [`common::AFL_ID_BASE`] for exactly this reason -- and its address is taken
//! inside the taint runtime, so neither key names the site. There is no edge
//! behind either direction either, so the branch map holds no entry and a lookup
//! would land on the unmapped degrade path. `ConcolicSession::on_cond` therefore
//! routes these around the coverage manager entirely, and `unmapped_branches`
//! staying at zero while UB checks are firing is what that looks like from
//! outside. Before that change the same run had them in the ratio, which is the
//! diagnostic for whether the map covers the code being traced -- with
//! `solve_ub` on there are enough checks to swamp it.
//!
//! Needs AFL++, for the two-arm build that gives the ordinary branch a real edge
//! id to be mapped by; skips with an explanation when it cannot find one.
//!
//! Its own file for the usual reason: one [`Session`] per process, one process
//! per test binary.

mod common;

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use symsan::{Config, Session};

use common::MAP_SIZE;

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/undefined.c")
}

/// What an integer division by zero costs on x86: the CPU raises #DE and the
/// kernel delivers SIGFPE. Written out rather than taken from a `libc`
/// dependency the crate does not otherwise have, for one number that has been 8
/// since the first edition of POSIX.
const SIGFPE: i32 = 8;

/// Run the plain build on @p input and report the signal that killed it, if
/// any. `None` covers both a clean exit and a non-zero one: the target's exit
/// code says nothing here, only whether the hardware objected.
fn fault(bin: &Path, scratch: &Path, input: &[u8]) -> Option<i32> {
    std::fs::write(scratch, input).expect("failed to stage the oracle input");
    Command::new(bin)
        .arg(scratch)
        .output()
        .expect("failed to run the oracle")
        .status
        .signal()
}

#[test]
fn undefined_behaviour_is_solved_but_not_counted_as_coverage() {
    let Some(afl_clang_lto) = common::find_afl_tool("afl-clang-lto") else {
        eprintln!("skipping: no afl-clang-lto found (set AFL_PATH to an AFLplusplus checkout)");
        return;
    };

    let dir = common::scratch_dir("solve-ub");
    let built = common::build(&afl_clang_lto, &dir, &source(), "undefined", &[]);
    let plain = common::build_oracle(&dir, &source(), "undefined");
    let oracle_input = dir.join("oracle_input");
    let input_file = dir.join("cur_input");
    let input_file = input_file.to_str().unwrap();

    let config = Config::new(built.symsan.to_str().unwrap(), input_file)
        .args([built.symsan.to_str().unwrap(), input_file])
        .use_stdin(false)
        .jigsaw(true)
        .z3(true)
        .solve_ub(true)
        .timeout_ms(10_000)
        .branch_map(built.bmap.to_str().unwrap());

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    // An all-zero snapshot: the fuzzer has covered nothing, so the map can only
    // ever agree that the ordinary branch is worth solving. What is being
    // measured is which branches get looked up, not what the answer was.
    session
        .set_coverage(&vec![0u8; MAP_SIZE])
        .expect("set_coverage failed on a session with a branch map");

    // A divisor of 0x41414141, so tracing the seed does not itself divide by
    // zero -- the check has to be *solved* for, which is the point.
    let seed = b"AAAAAAAA".to_vec();
    let n = session.trace(&seed).expect("trace failed");
    assert!(n > 0, "tracing the seed produced no tasks at all");

    let mut solutions = 0;
    let mut faulted = 0;
    while let Some(solution) = session.next_solution() {
        solutions += 1;
        let signal = fault(&plain, &oracle_input, &solution);
        if signal == Some(SIGFPE) {
            faulted += 1;
        }
        session.report_result(signal.is_some());
        assert!(solutions < 1000, "next_solution() does not terminate");
    }

    let stats = session.stats();
    eprintln!(
        "{} branches, {} tasks, {} solutions, {faulted} of them undefined; \
         {} mapped, {} unmapped",
        stats.total_branches,
        stats.total_tasks,
        solutions,
        stats.mapped_branches,
        stats.unmapped_branches
    );

    assert!(
        faulted > 0,
        "none of the {solutions} solutions divided by zero; solve_ub reached \
         neither the runtime nor a solver"
    );

    // Non-vacuity for the assertion below, and stated separately so a failure
    // says which half broke: the ordinary branch *was* looked up in the map and
    // *was* found there, so a UB check landing in the same books would have to
    // show up as unmapped rather than being invisible.
    assert!(
        stats.mapped_branches > 0,
        "the branch map resolved nothing, so an unmapped count of zero would \
         mean the map was never consulted rather than never consulted about a \
         UB check"
    );
    assert_eq!(
        stats.unmapped_branches, 0,
        "a branch the map could not answer for was looked up in it anyway; on \
         this target the only such branches are the UB checks, which are \
         supposed to bypass the coverage manager"
    );
    // The census the manager kept is therefore *smaller* than the number of
    // conditions the trace reported -- the gap being the checks it never saw.
    assert!(
        stats.total_branches > stats.mapped_branches + stats.unmapped_branches,
        "every condition went through the coverage manager, so no UB check was \
         raised on this trace and the assertion above is about nothing"
    );

    std::fs::remove_dir_all(&dir).ok();
}
