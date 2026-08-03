//! Example LibAFL fuzzer driven by SymSan.
//!
//! Structurally this is LibAFL's `forkserver_simple` example with one extra
//! stage: [`SymSanStage`] runs SymSan's concolic execution over each new corpus
//! entry and feeds the solved inputs back to the fuzzer. It replaces the AFL++
//! custom mutator in `driver/aflpp/`.
//!
//! # Two builds of the target
//!
//! Coverage and concolic execution need different instrumentation, so you need
//! the program compiled twice:
//!
//! ```text
//! # the one the forkserver runs, for coverage feedback
//! afl-clang-fast -o target.afl target.c
//!
//! # the one SymSan traces, for constraints
//! KO_CC=clang-18 KO_USE_FASTGEN=1 <symsan>/b4/bin/ko-clang -o target.symsan target.c
//! ```
//!
//! Then:
//!
//! ```text
//! symsan-fuzz -i ./seeds -o ./out --symsan ./target.symsan -- ./target.afl @@
//! ```
//!
//! `@@` means "the input file", as in AFL. It is expanded twice, to two
//! different paths: the forkserver's own scratch file, and the stage's.
//!
//! # The cmplog baseline
//!
//! `--cmplog` turns on LibAFL's own cmplog pipeline against a third build:
//!
//! ```text
//! AFL_LLVM_CMPLOG=1 afl-clang-fast -o target.cmplog target.c
//! symsan-fuzz -i ./seeds -o ./out --cmplog ./target.cmplog -- ./target.afl @@
//! ```
//!
//! It exists so that "what does concolic execution buy?" has an answer measured
//! against the cheap technique that solves many of the same branches, rather
//! than against plain havoc. The two flags are independent -- pass either, both,
//! or neither, which puts all four arms of that comparison in one binary and
//! rules out the fuzzer itself as a variable between them.
//!
//! # Single core
//!
//! This example runs one fuzzer in one process, which is also the natural unit
//! for SymSan (one session per process). Scaling out means LibAFL's `Launcher`,
//! which forks a process per core -- each would get its own stage and its own
//! session, and the per-pid shared-memory names already keep them apart.

mod credit;

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use libafl::{
    Error, HasMetadata,
    corpus::{CachedOnDiskCorpus, Corpus, DynamicCorpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{
        HasObservers, StdChildArgs,
        forkserver::{ForkserverExecutor, SHM_CMPLOG_ENV_VAR},
    },
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{
        HavocScheduledMutator, Tokens, havoc_mutations, token_mutations::AflppRedQueen,
        tokens_mutations,
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{
        ColorizationStage, IfStage, OptionalStage,
        mutational::{MultiMutationalStage, StdMutationalStage},
    },
    state::{HasCorpus, HasCurrentTestcase, StdState},
};
use libafl_bolts::{
    AsSliceMut, StdTargetArgs, Truncate,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{Handled, Merge, tuple_list},
};
use libafl_symsan::{
    SymSanColorizationStage, SymSanStage, symsan_cmplog_worthwhile,
    symsan_needs_stock_colorization,
};

use crate::credit::CreditedStage;
use libafl_targets::{
    AflppCmpLogMap,
    cmps::{observers::AflppCmpLogObserver, stages::AflppCmplogTracingStage},
};
use nix::sys::signal::Signal;

/// Size of the AFL-style coverage map shared with the forkserver, when
/// `AFL_MAP_SIZE` does not say otherwise.
const DEFAULT_MAP_SIZE: usize = 65536;

/// Default for `--corpus-cache`: how many corpus entries the on-disk corpus
/// keeps in memory.
///
/// Every entry is on disk either way; this only decides how often one has to be
/// read back. A libpng campaign reaches a few hundred entries in ten minutes,
/// so at this size nothing is evicted in a short run and a long one keeps its
/// working set -- the scheduler comes back to recent entries far more often
/// than to old ones.
const CORPUS_CACHE: usize = 4096;

/// The corpus, chosen at startup by `--in-memory-corpus`.
///
/// `DynamicCorpus` is LibAFL's two-variant enum rather than a `dyn Corpus`, so
/// the choice costs a match per access and nothing in the type system: one
/// monomorphised fuzzing loop serves both.
type FuzzCorpus =
    DynamicCorpus<CachedOnDiskCorpus<BytesInput>, InMemoryCorpus<BytesInput>, BytesInput>;

/// Size of the AFL-style coverage map shared with the forkserver.
///
/// A constant is the wrong shape for this even though 64K is right for most
/// targets: the map size is a property of the *build*, not of the fuzzer. A
/// target whose instrumentation allocated more edges than we did does not fail
/// loudly -- afl-cc's runtime reports its size in the forkserver handshake and
/// LibAFL then refuses to start, or, with `AFL_LLVM_MAP_DYNAMIC`, coverage
/// simply folds into whatever we gave it. Either way the answer is a number
/// only whoever built the target knows.
///
/// `AFL_MAP_SIZE` is that number, spelled the way AFL++ and every AFL-family
/// tool already spells it, so a harness that sets it for `afl-fuzz` needs no
/// second knob for us. Unset, unparseable or zero all mean the default.
fn map_size() -> usize {
    match std::env::var("AFL_MAP_SIZE") {
        Ok(s) => match s.trim().parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                log::warn!("ignoring unusable AFL_MAP_SIZE={s:?}; using {DEFAULT_MAP_SIZE}");
                DEFAULT_MAP_SIZE
            }
        },
        Err(_) => DEFAULT_MAP_SIZE,
    }
}

/// Whether an afl-cc target wants persistent mode and/or a deferred forkserver.
///
/// afl-cc bakes a marker string into any target that defers its forkserver
/// (`__AFL_INIT()`, which is what every libFuzzer harness linked against
/// `libAFLDriver.a` does) or that runs a persistent loop (`__AFL_LOOP()`).
/// The markers say what the target *can* do; whether it does it is decided by
/// two environment variables its runtime reads at startup, and nothing sets
/// those for us. `afl-fuzz` scans the binary for the markers and calls
/// `setenv` itself (`src/afl-fuzz-init.c`, "Deferred forkserver binary
/// detected"), so a target that works under `afl-fuzz` gives no warning that
/// the fuzzer was carrying half the arrangement.
///
/// Skipping the scan is not a slower path, it is a silently broken one. With
/// `__AFL_DEFER_FORKSRV` unset, the runtime's constructor starts the
/// forkserver before `main`, so every forked child re-decides "am I running
/// under AFL?" *after* the fork -- by which point the environment says no --
/// and takes the standalone branch: read `argv[1]` as a corpus file, exit.
/// The handshake succeeds, executions are counted, no signal is raised, and
/// the coverage map comes back empty for every input, which the fuzzer reports
/// as an uninstrumented target rather than as its own missing `setenv`.
///
/// Returns `(persistent, deferred)`.
fn afl_target_modes(program: impl AsRef<Path>) -> (bool, bool) {
    const PERSIST_SIG: &[u8] = b"##SIG_AFL_PERSISTENT##";
    const DEFER_SIG: &[u8] = b"##SIG_AFL_DEFER_FORKSRV##";

    let program = program.as_ref();
    let contains = |data: &[u8], sig: &[u8]| data.windows(sig.len()).any(|w| w == sig);

    let (mut persistent, mut deferred) = match std::fs::read(program) {
        Ok(data) => (contains(&data, PERSIST_SIG), contains(&data, DEFER_SIG)),
        Err(e) => {
            log::warn!(
                "cannot scan {} for AFL target modes ({e}); assuming neither",
                program.display()
            );
            (false, false)
        }
    };

    // The same overrides afl-fuzz honours, for a target whose markers were
    // stripped or that was instrumented by something other than afl-cc.
    persistent |= std::env::var_os("AFL_PERSISTENT").is_some();
    deferred |= std::env::var_os("AFL_DEFER_FORKSRV").is_some();

    log::info!(
        "{}: persistent={persistent} deferred_forkserver={deferred}",
        program.display()
    );
    (persistent, deferred)
}

#[derive(Debug, Parser)]
#[command(
    name = "symsan-fuzz",
    about = "LibAFL fuzzer with a SymSan concolic execution stage"
)]
struct Opt {
    /// Directory of initial seed inputs.
    #[arg(short = 'i', long = "input", required = true)]
    in_dir: PathBuf,

    /// Directory for the corpus (`queue/`) and the crashes (`crashes/`).
    #[arg(short = 'o', long = "output", default_value = "./out")]
    out_dir: PathBuf,

    /// The SymSan-instrumented build of the target (`ko-clang`,
    /// `KO_USE_FASTGEN=1`). Omit it to run without the concolic stage, which is
    /// useful for an A/B against plain havoc fuzzing.
    #[arg(long = "symsan")]
    symsan_bin: Option<PathBuf>,

    /// The cmplog-instrumented build of the target
    /// (`AFL_LLVM_CMPLOG=1 afl-clang-fast`). Given one, LibAFL's own cmplog
    /// pipeline runs: colorization, then a trace through this binary, then
    /// AFL++'s RedQueen. It is independent of `--symsan`; give both, either or
    /// neither, which is what puts all four arms of the comparison in one
    /// binary.
    #[arg(long = "cmplog")]
    cmplog_bin: Option<PathBuf>,

    /// Run cmplog at full strength even when SymSan has already been over the
    /// entry.
    ///
    /// With both `--symsan` and `--cmplog`, the two do the same job twice by
    /// default -- so by default SymSan's taint is handed to cmplog: bytes whose
    /// branches SymSan already flipped are held still, which makes RedQueen
    /// skip the comparisons they feed, and colorization costs two executions
    /// instead of one per two input bytes. An entry SymSan finished off skips
    /// the cmplog group entirely.
    ///
    /// Pass this to turn that off and get stock LibAFL cmplog, which is the
    /// honest baseline to measure the filter against. It has no effect without
    /// both binaries.
    #[arg(long = "no-symsan-cmplog-filter", default_value = "false")]
    no_symsan_cmplog_filter: bool,

    /// Per-execution timeout for the forkserver, in milliseconds.
    #[arg(short = 't', long = "timeout", default_value = "1200")]
    timeout: u64,

    /// Timeout for one SymSan trace, in milliseconds. Concolic execution is far
    /// slower than a plain run, hence the separate, larger budget.
    #[arg(long = "symsan-timeout", default_value = "60000")]
    symsan_timeout: u32,

    /// Stop after this many solved inputs per corpus entry; 0 means no limit.
    #[arg(long = "symsan-budget", default_value = "0")]
    symsan_budget: usize,

    /// Branch map for the SymSan target, as written by TaintPass with
    /// `-taint-branch-map=<file>`. Given one, the concolic stage can see which
    /// branches the fuzzer has already covered and stops solving for them.
    #[arg(long = "branch-map")]
    branch_map: Option<PathBuf>,

    /// Audit the branch map instead of trusting it: on every traced entry,
    /// check that the edges the map claims for the branches SymSan executed are
    /// edges the fuzzer's own build actually recorded. A wrong map otherwise
    /// fails silently -- the stage just stops solving. Slow; a setup check for
    /// a new target, not something to leave on.
    #[arg(long = "validate-branch-map", default_value = "false")]
    validate_branch_map: bool,

    /// Exec the SymSan target once per trace instead of forking it from a
    /// long-lived server. Slower, but the way out if the target keeps state
    /// across `main()` that a fork would wrongly share.
    #[arg(long = "symsan-no-forkserver", default_value = "false")]
    symsan_no_forkserver: bool,

    /// Drop the input-to-state solver from the ladder. It is the cheapest rung
    /// and cracks most branches on its own, so this is for measuring what the
    /// others contribute, not for fuzzing.
    #[arg(long = "symsan-no-i2s", default_value = "false")]
    symsan_no_i2s: bool,

    /// Drop the JIT/gradient-descent solver from the ladder.
    #[arg(long = "symsan-no-jigsaw", default_value = "false")]
    symsan_no_jigsaw: bool,

    /// Add Z3 to the ladder as a last resort. Off by default: it solves what
    /// the other two cannot, but it is also the only one that can spend
    /// seconds on a single task, which a fuzzing loop pays for in exec rate.
    #[arg(long = "symsan-z3", default_value = "false")]
    symsan_z3: bool,

    /// Also solve for undefined behaviour: division by zero, shift past the
    /// width, signed overflow, a truncation or sign change that loses data, an
    /// out-of-bounds index. These are not coverage -- nothing in the fuzzer's
    /// map moves when one is satisfied -- so they are solved for their own
    /// sake, and an input that satisfies one is kept only if the target then
    /// does something the fuzzer notices. Off by default because the check
    /// rides along with every tainted arithmetic operation, not with every
    /// branch, so it is the one switch here that changes what a trace costs by
    /// an order of magnitude rather than a fraction.
    ///
    /// Implies allocation-bounds tracking. Note that the *bounds* checks
    /// additionally need the target built with `-mllvm -taint-solve-ub=true`
    /// (`KO_SOLVE_UB=1`), which emits the calls this flag then enables; the
    /// arithmetic ones are raised by the runtime and need no such rebuild.
    #[arg(long = "symsan-solve-ub", default_value = "false")]
    symsan_solve_ub: bool,

    /// Keep the corpus in memory only, instead of writing it to
    /// `<output>/queue`. The queue is what lets a trace be replayed after the
    /// fact, so this is for a run whose corpus is of no interest afterwards --
    /// or one whose output directory is somewhere writing it would hurt.
    /// Crashes are written either way.
    #[arg(long = "in-memory-corpus", default_value = "false")]
    in_memory_corpus: bool,

    /// How many corpus entries to hold in memory when the corpus is on disk.
    /// Entries past this are read back from `<output>/queue` when the scheduler
    /// asks for them; no entry is ever lost, so this trades memory for reads.
    /// Ignored with `--in-memory-corpus`.
    #[arg(long = "corpus-cache", default_value_t = CORPUS_CACHE)]
    corpus_cache: usize,

    /// Show the target's stdout and stderr.
    #[arg(short = 'd', long = "debug-child", default_value = "false")]
    debug_child: bool,

    /// Signal used to stop the child.
    #[arg(short = 's', long = "signal", value_parser = str::parse::<Signal>, default_value = "SIGKILL")]
    signal: Signal,

    /// The coverage-instrumented target and its arguments, after `--`.
    /// A bare `@@` is replaced with the input file.
    #[arg(name = "target", num_args(1..), last = true, required = true, allow_hyphen_values = true)]
    target: Vec<String>,
}

pub fn main() -> Result<(), libafl::Error> {
    env_logger::init();
    let opt = Opt::parse();

    let (executable, target_args) = opt
        .target
        .split_first()
        .expect("clap guarantees at least one element");

    // Only meaningful when both pipelines are in play: there is nothing to
    // filter cmplog with if SymSan is not running, and nothing to filter if
    // cmplog is not. Decided here because it has to be known before the
    // observer is handed to the executor, several sections below.
    let cmplog_filter =
        opt.symsan_bin.is_some() && opt.cmplog_bin.is_some() && !opt.no_symsan_cmplog_filter;

    // --- coverage plumbing --------------------------------------------------
    //
    // Straight out of LibAFL's forkserver_simple example: a shared memory map
    // the afl-cc instrumentation writes edge hits into, wrapped in an observer
    // the feedbacks read.

    let map_size = map_size();
    let mut shmem_provider = UnixShMemProvider::new()?;
    let mut shmem = shmem_provider.new_shmem(map_size)?;
    // SAFETY: writing to our own environment before any thread is spawned.
    unsafe {
        shmem.write_to_env("__AFL_SHM_ID")?;
    }
    let shmem_buf = shmem.as_slice_mut();

    // The name is load-bearing beyond display: MaxMapFeedback inherits it and
    // files its history map under it, which is how the SymSan stage finds that
    // map again when it is sharing coverage.
    let edges_observer_name = "shared_mem";
    // SAFETY: the map outlives the observer -- `shmem` is alive for all of main.
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new(edges_observer_name, shmem_buf))
            .track_indices()
    };
    let time_observer = TimeObserver::new("time");

    // "Interesting" = new edge coverage. This is also what decides what the
    // SymSan stage is told about its solutions: the stage asks the fuzzer to
    // evaluate them, and the fuzzer consults exactly these feedbacks.
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer)
    );

    // A crash that also brings new coverage is a distinct solution worth saving.
    let mut objective = feedback_and_fast!(
        CrashFeedback::new(),
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );

    std::fs::create_dir_all(&opt.out_dir)?;

    // On disk by default, in AFL's spelling, because an in-memory corpus cannot
    // be debugged after the fact: the interesting question about a campaign is
    // usually "what did SymSan do with *that* input", and answering it needs the
    // input.  Cached rather than plain on-disk so the hot path -- the scheduler
    // handing the same entry back for another round -- still reads from memory;
    // `--corpus-cache` bounds that cache, not the corpus.
    let corpus = if opt.in_memory_corpus {
        FuzzCorpus::corpus2(InMemoryCorpus::new())
    } else {
        FuzzCorpus::corpus1(CachedOnDiskCorpus::new(
            opt.out_dir.join("queue"),
            opt.corpus_cache,
        )?)
    };

    let mut state = StdState::new(
        // `from_entropy` rather than a fixed seed: two instances started in the
        // same second should not explore identically.
        StdRand::new(),
        corpus,
        OnDiskCorpus::new(opt.out_dir.join("crashes"))?,
        &mut feedback,
        &mut objective,
    )?;

    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // --- the executor -------------------------------------------------------

    let observer_ref = edges_observer.handle();
    // Built here, before `build()` takes the observer by value: colorization
    // needs it to tell "this byte changed nothing" from "this byte changed the
    // path". Cheap to construct and unused unless --cmplog was given.
    let colorization = ColorizationStage::new(&edges_observer);
    // Its cheaper stand-in, for when SymSan has already worked out which bytes
    // matter. `None` unless both pipelines are on, in which case the stock
    // stage above still runs behind it whenever this one cannot answer.
    let symsan_colorization = cmplog_filter
        .then(|| tuple_list!(SymSanColorizationStage::new(&edges_observer)));
    let mut tokens = Tokens::new();
    let (persistent, deferred) = afl_target_modes(executable);
    let mut executor = ForkserverExecutor::builder()
        .program(executable)
        .debug_child(opt.debug_child)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        .is_persistent(persistent)
        .is_deferred_frksrv(deferred)
        // Handles `@@` for us, allocating the forkserver's own input file.
        .parse_afl_cmdline(target_args.to_vec())
        .coverage_map_size(map_size)
        .timeout(Duration::from_millis(opt.timeout))
        .kill_signal(opt.signal)
        .build(tuple_list!(time_observer, edges_observer))?;

    // afl-cc targets can report a smaller map than we allocated.
    if let Some(dynamic_map_size) = executor.coverage_map_size() {
        executor.observers_mut()[&observer_ref]
            .as_mut()
            .truncate(dynamic_map_size);
    }

    // --- seeds --------------------------------------------------------------

    if state.must_load_initial_inputs() {
        let corpus_dirs = vec![opt.in_dir.clone()];
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!("failed to load the initial corpus from {corpus_dirs:?}: {err:?}")
            });
        println!("imported {} inputs from disk", state.corpus().count());
    }
    state.add_metadata(tokens);

    // --- stages -------------------------------------------------------------

    let mutator =
        HavocScheduledMutator::with_max_stack_pow(havoc_mutations().merge(tokens_mutations()), 6);

    // `tuple_list!` builds a distinct *type* per arrangement of stages, and
    // that type is baked in at compile time -- which is how LibAFL avoids
    // dynamic dispatch in the hot loop. So "optional stage" cannot be an `if`
    // around the tuple: two optional stages would be four arms, each with its
    // own `fuzz_loop` call. `OptionalStage` is LibAFL's answer -- one type
    // either way, holding `Option<inner tuple>` and doing nothing when it is
    // `None`, at the cost of one branch per entry, which is nothing next to a
    // target execution.

    // The branch map names branches in the *coverage* build, so it belongs next
    // to that binary; pick it up from there when `--branch-map` was not given.
    // Without a map the stage falls back to SymSan's own address-keyed,
    // session-lifetime table, which cannot tell the second traversal of a loop
    // branch from the first -- a real loss of solving power, and one that used
    // to happen silently. Hence both the default and the log lines below.
    let branch_map = opt.branch_map.clone().or_else(|| {
        let guess = PathBuf::from(format!("{executable}.map"));
        guess.is_file().then_some(guess)
    });

    let symsan_stages = match &opt.symsan_bin {
        Some(bin) => {
            let mut builder = SymSanStage::builder()
                .target(bin)
                // The stage does its own `@@` expansion against its own input
                // file, so it gets the raw arguments rather than the ones the
                // forkserver builder already rewrote.
                .args(target_args.iter().cloned())
                .input_file(opt.out_dir.join(format!(".symsan_input_{}", std::process::id())))
                .timeout_ms(opt.symsan_timeout)
                .max_solutions_per_input(opt.symsan_budget)
                .forkserver(!opt.symsan_no_forkserver)
                .i2s(!opt.symsan_no_i2s)
                .jigsaw(!opt.symsan_no_jigsaw)
                .z3(opt.symsan_z3)
                .solve_ub(opt.symsan_solve_ub)
                .cmplog_filter(cmplog_filter);
            if let Some(map) = &branch_map {
                // The observer above is named "shared_mem", which is also the
                // name MaxMapFeedback::new() inherits and files its history map
                // under -- so the stage's default is already right, but say it
                // rather than leave the coupling implicit.
                builder = builder
                    .branch_map(map)
                    .coverage_map_name(edges_observer_name)
                    .validate_coverage(opt.validate_branch_map);
                println!(
                    "symsan: sharing the fuzzer's coverage via {}{}",
                    map.display(),
                    if opt.branch_map.is_some() { "" } else { " (auto-detected)" }
                );
                if opt.validate_branch_map {
                    // The observer tracks indices (see `.track_indices()`
                    // above), so every corpus entry already carries the edge
                    // set the audit needs -- nothing is re-executed for it.
                    println!("symsan: auditing the branch map (RUST_LOG=error to see verdicts)");
                }
            } else {
                // Say which coverage is deciding what to solve, always. An
                // A/B that accidentally ran without the map is otherwise
                // indistinguishable from one that ran with it.
                println!(
                    "symsan: no branch map ({executable}.map absent); using SymSan's own \
                     per-session coverage, so each branch is solvable once per session"
                );
                if opt.validate_branch_map {
                    println!("symsan: --validate-branch-map ignored without a branch map");
                }
            }
            let symsan = builder.build()?;
            println!("symsan: tracing with {}", bin.display());
            // Which rungs are in play decides both what gets solved and what a
            // run costs, so print it: an A/B between two ladders is otherwise
            // two logs that look identical.
            let ladder: Vec<&str> = [
                (!opt.symsan_no_i2s, "i2s"),
                (!opt.symsan_no_jigsaw, "jigsaw"),
                (opt.symsan_z3, "z3"),
            ]
            .iter()
            .filter_map(|&(on, name)| on.then_some(name))
            .collect();
            if ladder.is_empty() {
                // Tracing still runs, and still costs what tracing costs, but
                // no task can ever be solved. Say so rather than let it look
                // like a target nothing works on.
                println!("symsan: no solver enabled; tracing only");
            } else {
                println!("symsan: solvers {}", ladder.join(" -> "));
            }
            if opt.symsan_solve_ub {
                // Same reason as the ladder line: this one changes both what a
                // trace costs and what it solves for, so a log without it is
                // indistinguishable from a log with it.
                println!("symsan: also solving for undefined behaviour");
            }
            Some(tuple_list!(CreditedStage::new("symsan", symsan)))
        }
        None => {
            println!("symsan: disabled (pass --symsan <binary> to enable)");
            None
        }
    };

    // --- the cmplog baseline ------------------------------------------------
    //
    // LibAFL's own cmplog pipeline, wired the way its
    // fuzzers/forkserver/fuzzbench_forkserver_cmplog example wires it, so that
    // "SymSan versus cmplog" compares SymSan against a cmplog somebody else
    // tuned rather than against one written to lose:
    //
    //   colorization -- replace input bytes with random ones that keep the
    //                   coverage identical, so what is left is the bytes the
    //                   comparisons actually depend on;
    //   tracing      -- run the cmplog build, which logs both operands of every
    //                   comparison into a shared map;
    //   RedQueen     -- for each logged pair, put the other operand where the
    //                   colorized bytes say this one came from.
    //
    // It is the same idea as SymSan's i2s rung, reached by observation instead
    // of by symbolic execution: no solver, no constraint, just "this comparison
    // wanted that value, and these input bytes reach it".
    //
    // The map itself has to be held one scope out: the observer borrows it, so
    // it has to outlive the stages, and it is declared before them so that it is
    // dropped after them.
    let mut cmplog_shmem_holder = None;
    let cmplog_stages = match &opt.cmplog_bin {
        Some(bin) => {
            let cmplog_shmem =
                cmplog_shmem_holder.insert(shmem_provider.uninit_on_shmem::<AflppCmpLogMap>()?);
            // SAFETY: still single-threaded, and the map outlives the executor
            // that is about to be told its id.
            unsafe {
                cmplog_shmem.write_to_env(SHM_CMPLOG_ENV_VAR)?;
            }
            // SAFETY: the shmem is alive for the rest of main, and only the
            // observer built from it reads it.
            let cmpmap = unsafe { AflppCmpLogMap::from_shmem(cmplog_shmem) };

            let cmplog_observer = AflppCmpLogObserver::new("cmplog", cmpmap, true);
            let cmplog_ref = cmplog_observer.handle();

            // Scanned separately: it is a separate build, and one of the two
            // could have been produced without the driver.
            let (cmplog_persistent, cmplog_deferred) = afl_target_modes(bin);
            let cmplog_executor = ForkserverExecutor::builder()
                .program(bin)
                .debug_child(opt.debug_child)
                .shmem_provider(&mut shmem_provider)
                .is_persistent(cmplog_persistent)
                .is_deferred_frksrv(cmplog_deferred)
                .parse_afl_cmdline(target_args.to_vec())
                .coverage_map_size(map_size)
                // A cmplog run logs every comparison it reaches, so it is
                // slower than a plain one by a wide margin; the same x10 the
                // upstream example uses.
                .timeout(Duration::from_millis(opt.timeout * 10))
                .kill_signal(opt.signal)
                .build(tuple_list!(cmplog_observer))?;

            let tracing = AflppCmplogTracingStage::new(cmplog_executor, cmplog_ref);
            let rq: MultiMutationalStage<_, _, BytesInput, _, _, _> =
                MultiMutationalStage::new(AflppRedQueen::with_cmplog_options(true, true));

            // Once per entry, not once per scheduling: colorization and the
            // trace cost real executions, and the answer does not change when
            // the same entry comes round again. Upstream picks the second
            // scheduling rather than the first, so an entry has to prove it is
            // worth coming back to before it earns the trace.
            //
            // With the filter on there is a second reason to skip: SymSan may
            // have left nothing behind worth mutating, in which case the trace
            // and RedQueen would both run for nothing.
            let run_once_per_entry =
                move |_fuzzer: &mut _,
                      _executor: &mut _,
                      state: &mut StdState<FuzzCorpus, _, _, _>,
                      _mgr: &mut _|
                      -> Result<bool, Error> {
                    if state.current_testcase()?.scheduled_count() != 1 {
                        return Ok(false);
                    }
                    if cmplog_filter {
                        return symsan_cmplog_worthwhile(state);
                    }
                    Ok(true)
                };

            // The stock colorization stage, kept behind the SymSan one as the
            // way out: it runs whenever the cheap stage had no answer, and
            // unconditionally when the filter is off, which is what keeps
            // `--cmplog` on its own the same pipeline it always was.
            let needs_stock_colorization =
                move |_fuzzer: &mut _,
                      _executor: &mut _,
                      state: &mut StdState<FuzzCorpus, _, _, _>,
                      _mgr: &mut _|
                      -> Result<bool, Error> {
                    if cmplog_filter {
                        return symsan_needs_stock_colorization(state);
                    }
                    Ok(true)
                };

            println!("cmplog: tracing with {}", bin.display());
            if cmplog_filter {
                println!(
                    "cmplog: filtered by SymSan's taint \
                     (--no-symsan-cmplog-filter for the stock pipeline)"
                );
            }
            // Credited as one stage: of the four inside, only RedQueen can add
            // anything, so the count is RedQueen's however the `IfStage` gates
            // it.
            Some(tuple_list!(CreditedStage::new(
                "cmplog",
                IfStage::new(
                    run_once_per_entry,
                    tuple_list!(
                        OptionalStage::new(symsan_colorization),
                        IfStage::new(needs_stock_colorization, tuple_list!(colorization)),
                        tracing,
                        rq
                    )
                )
            )))
        }
        None => {
            println!("cmplog: disabled (pass --cmplog <binary> to enable)");
            None
        }
    };

    // Order: SymSan first, so a newly scheduled entry is traced before havoc
    // starts rewriting it and the constraints describe the entry as it was
    // found interesting. Then cmplog, then havoc.
    let mut stages = tuple_list!(
        OptionalStage::new(symsan_stages),
        OptionalStage::new(cmplog_stages),
        CreditedStage::new("havoc", StdMutationalStage::new(mutator))
    );
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}
