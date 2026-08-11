//! The fork server path: one target process, forked per input, instead of an
//! `execv` every run.
//!
//! Two things are worth checking and neither is visible from a single trace.
//! The first is that the server is really there -- a target whose backend has
//! no fork server, or a spawn that fails, silently falls back to exec'ing per
//! run, which is correct but would make this test vacuous.  We catch that by
//! looking for the server process itself: on the exec path the traced process
//! is our direct child and is reaped before `trace()` returns, so *nothing* of
//! ours is left running between traces, while the fork server is by definition
//! still there.
//!
//! The second is that repeated runs stay in step.  The event pipe is no longer
//! torn down between runs, so a byte left behind by one child turns up as a
//! phantom event at the head of the next trace; tracing the same seed several
//! times and demanding the same answer is what would catch it.
//!
//! This is a separate file from `session.rs` because SymSan allows one
//! [`Session`] per *process*, and cargo compiles each file under `tests/` into
//! its own binary.  See the module docs there.

use std::path::{Path, PathBuf};
use std::process::Command;

use symsan::{Config, Session};

/// Build `tests/data/branch.c` with `ko-clang`, as `session.rs` does.
fn build_target(out_dir: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/branch.c");
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
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to run ko-clang");
    assert!(status.success(), "ko-clang failed on {}", src.display());

    out
}

/// Our own live child processes, zombies excluded.
///
/// `/proc/<pid>/stat` puts `comm` in parentheses and lets it contain spaces and
/// even `)`, so the fields after it are parsed from the *last* `") "` rather
/// than by splitting the whole line.
fn live_children() -> Vec<i32> {
    let me = std::process::id() as i32;
    let mut out = Vec::new();

    for entry in std::fs::read_dir("/proc").expect("/proc is not mounted") {
        let Ok(entry) = entry else { continue };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        // The process can exit between readdir() and open(), which is not an
        // error -- it just means it is not one of the children we are after.
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some((_, rest)) = stat.rsplit_once(") ") else { continue };
        let mut fields = rest.split_whitespace();
        let state = fields.next().unwrap_or("");
        let ppid = fields.next().unwrap_or("0").parse::<i32>().unwrap_or(0);
        if ppid == me && state != "Z" {
            out.push(pid);
        }
    }

    out
}

fn scratch_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/symsan-test")
        .join(format!("forksrv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("failed to create the scratch dir");
    dir
}

#[test]
fn forkserver_traces_are_repeatable() {
    let dir = scratch_dir();
    let target = build_target(&dir);

    let input_file = dir.join("cur_input");
    let input_file = input_file.to_str().unwrap();

    assert!(
        live_children().is_empty(),
        "the test process already has children; the server check below would \
         not mean anything"
    );

    let config = Config::new(target.to_str().unwrap(), input_file)
        .args([target.to_str().unwrap(), input_file])
        .use_stdin(false)
        .jigsaw(true)
        .forkserver(true)
        .timeout_ms(10_000);

    let mut session = Session::new().expect("failed to create a session");
    session.init(&config).expect("failed to initialize the session");

    let seed = b"AAAAAAAAAAAAAAAA".to_vec();

    // Round 1 also establishes the baseline the later rounds are compared
    // against: what matters is that the number does not drift, not what it is.
    let expected = session.trace(&seed).expect("trace failed");
    assert!(expected > 0, "tracing the seed produced no solving tasks");

    let children = live_children();
    assert_eq!(
        children.len(),
        1,
        "expected exactly the fork server to be alive after a trace, found {children:?}; \
         if this is empty the launcher fell back to exec'ing per run"
    );
    let server = children[0];

    // Draining the solutions matters as much as the count: it is the path that
    // reads the union table the child wrote, so a fork that left the table in
    // the wrong state shows up here rather than as a bad task count.
    let mut solutions = 0;
    while session.next_solution().is_some() {
        solutions += 1;
        session.report_result(false);
        assert!(solutions < 1000, "next_solution() does not terminate");
    }
    assert!(solutions > 0, "{expected} tasks produced no solutions at all");

    // Rounds 2..4: same input, same answer, same server.  A desynchronized
    // event pipe would show up as a different task count, and a server that
    // died and was silently replaced would show up as a different pid.
    for round in 2..=4 {
        let n = session.trace(&seed).expect("re-trace failed");
        assert_eq!(
            n, expected,
            "round {round} of the same seed produced {n} tasks, not {expected}; \
             the event pipe is out of step between runs"
        );

        let mut round_solutions = 0;
        while session.next_solution().is_some() {
            round_solutions += 1;
            session.report_result(false);
            assert!(round_solutions < 1000, "next_solution() does not terminate");
        }
        assert_eq!(
            round_solutions, solutions,
            "round {round} produced {round_solutions} solutions, not {solutions}"
        );

        assert_eq!(
            live_children(),
            vec![server],
            "round {round} did not reuse the same fork server"
        );
    }

    // Dropping the session has to take the server with it; otherwise every
    // fuzzer that opens and closes a session leaks a process.
    drop(session);
    assert!(
        live_children().is_empty(),
        "the fork server outlived the session"
    );
}
