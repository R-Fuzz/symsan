//! Building a target both ways out of one link.
//!
//! Several tests here need the same pair of binaries: the fuzzer's coverage
//! build of some source, and SymSan's concolic build of *the same* source, with
//! a branch map tying them together. They used to be two independent compiles
//! joined afterwards by source location, and every one of them carried its own
//! copy of the recipe. They are now two arms of a single `afl-clang-lto` link,
//! and the recipe is long enough that four copies of it would be four things to
//! keep in step.
//!
//! Why one link. `-Wl,--save-temps=precodegen` makes lld write out the merged
//! module as it stands after AFL++'s LTO pass has numbered the edges. Running
//! TaintPass over *that* module -- rather than over a second, separate compile
//! -- is what makes a SymSan branch id literally be one of AFL++'s edge ids,
//! instead of something that has to be matched up to one. There is no join left
//! to get wrong, and no way for the two arms to drift.
//!
//! A `common/mod.rs` rather than a `common.rs`, so cargo treats it as a module
//! of each test binary and not as a test binary of its own.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Where AFL++ is told to start numbering edges: `symsan::AFL_ID_BASE`
/// (`include/branch_id.h`). Everything below it is reserved for the branch ids
/// SymSan's runtime makes up for itself -- bounds checks, UB checks -- so that
/// `cid < AFL_ID_BASE` is a complete test for "not an edge".
pub const AFL_ID_BASE: u32 = 4096;

/// AFL++'s coverage map size, and therefore how long a snapshot a test hands
/// the session. Any length works -- an edge id past the end reads as "not
/// covered" -- but matching the real thing is what the fuzzer will pass.
pub const MAP_SIZE: usize = 65536;

/// Where to find one of AFL++'s tools: `$AFL_PATH`, then the sibling checkout
/// this repo is usually cloned next to, then `$PATH`.
pub fn find_afl_tool(name: &str) -> Option<PathBuf> {
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

/// A per-test scratch directory, keyed by pid so two test binaries running
/// concurrently cannot tread on each other.
pub fn scratch_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target")
        .join(format!("symsan-{tag}"))
        .join(format!("pid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("failed to create the scratch dir");
    dir
}

/// The three artefacts of one link: the fuzzer's binary, SymSan's, and the map
/// between them.
pub struct Target {
    /// The AFL++ coverage build -- what `afl-showmap` runs.
    pub afl: PathBuf,
    /// The concolic build, for [`symsan::Config::new`].
    pub symsan: PathBuf,
    /// TaintPass's `.bmap`, for [`symsan::Config::branch_map`].
    pub bmap: PathBuf,
}

fn run(what: &str, cmd: &mut Command) {
    let status = cmd.status().unwrap_or_else(|e| panic!("failed to run {what}: {e}"));
    assert!(status.success(), "{what} failed");
}

/// Build @p source both ways. @p cflags go to the one compile the two arms
/// share, so an option like `-O0` applies to both by construction rather than
/// by remembering to pass its equivalent twice.
///
/// `-g` is not required any more -- nothing joins on source location -- but it
/// costs nothing and makes a failing test's output readable.
pub fn build(afl_clang_lto: &Path, out_dir: &Path, source: &Path, stem: &str, cflags: &[&str]) -> Target {
    let afl = out_dir.join(format!("{stem}.afl"));
    let bmap = out_dir.join(format!("{stem}.bmap"));
    // lld derives this from the output path.
    let merged = out_dir.join(format!("{stem}.afl.0.5.precodegen.bc"));
    let tainted = out_dir.join(format!("{stem}.taint.bc"));
    let object = out_dir.join(format!("{stem}.taint.o"));
    let symsan = out_dir.join(format!("{stem}.fg"));
    // A leftover from an earlier run would otherwise be instrumented, or read,
    // in place of the one this build was supposed to produce.
    for stale in [&merged, &bmap, &tainted, &object] {
        let _ = std::fs::remove_file(stale);
    }

    run(
        "afl-clang-lto",
        Command::new(afl_clang_lto)
            .env("AFL_LLVM_LTO_STARTID", AFL_ID_BASE.to_string())
            .env("AFL_QUIET", "1")
            .arg("-g")
            .arg("-flto")
            .arg("-fuse-ld=lld")
            .arg("-Wl,--save-temps=precodegen")
            .args(cflags)
            .arg(source)
            .arg("-o")
            .arg(&afl),
    );
    assert!(
        merged.is_file(),
        "{} was not produced; does this lld support --save-temps=precodegen?",
        merged.display()
    );

    // The same flags ko-clang's add_taint_pass() would have chosen, spelled out
    // because no driver does the post-LTO pipeline yet. The Magma fuzzer's
    // instrument.sh has the same list; both follow ko_clang.c.
    let lib = Path::new(symsan::BUILD_DIR).join("lib/symsan");
    let pass = lib.join("TaintPass.so");
    assert!(
        pass.is_file(),
        "{} is missing; run `cd b4 && make -j && make install` first",
        pass.display()
    );
    run(
        "opt",
        Command::new("opt-18")
            .arg(format!("-load-pass-plugin={}", pass.display()))
            .arg("-passes=taint")
            .arg(format!("-taint-abilist={}", lib.join("dfsan_abilist.txt").display()))
            .arg(format!("-taint-abilist={}", lib.join("zlib_abilist.txt").display()))
            // =1 rather than auto-detect: if the module ever arrives without
            // AFL++'s instrumentation, that is this pipeline breaking, and it
            // should say so instead of quietly falling back to source hashes
            // the fuzzer cannot look up.
            .arg("-taint-with-afl=1")
            .arg(format!("-taint-branch-map={}", bmap.display()))
            .arg(&merged)
            .arg("-o")
            .arg(&tainted),
    );
    run(
        "llc",
        Command::new("llc-18")
            .arg("-relocation-model=pic")
            .arg("-filetype=obj")
            .arg(&tainted)
            .arg("-o")
            .arg(&object),
    );

    // The final link goes through the real ko-clang, so the runtime archive,
    // the dynamic list and taint.ld come along exactly as in a normal build.
    let ko_clang = Path::new(symsan::BUILD_DIR).join("bin/ko-clang");
    assert!(
        ko_clang.is_file(),
        "{} is missing; run `cd b4 && make -j && make install` first",
        ko_clang.display()
    );
    run(
        "ko-clang",
        Command::new(&ko_clang)
            .env("KO_CC", "clang-18")
            .env("KO_USE_FASTGEN", "1")
            .arg(&object)
            .arg("-o")
            .arg(&symsan),
    );

    Target { afl, symsan, bmap }
}

/// Build @p source with plain clang, as an oracle: run it on a solution and its
/// exit code says how far the input got.
pub fn build_oracle(out_dir: &Path, source: &Path, stem: &str) -> PathBuf {
    let out = out_dir.join(format!("{stem}.plain"));
    run("clang-18", Command::new("clang-18").arg(source).arg("-o").arg(&out));
    out
}

/// Run the oracle on @p input, staged through @p scratch, and return its exit
/// code.
pub fn oracle(bin: &Path, scratch: &Path, input: &[u8]) -> i32 {
    std::fs::write(scratch, input).expect("failed to stage the oracle input");
    Command::new(bin)
        .arg(scratch)
        .output()
        .expect("failed to run the oracle")
        .status
        .code()
        .expect("oracle was killed by a signal")
}
