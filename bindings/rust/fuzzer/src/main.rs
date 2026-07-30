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
//! # Single core
//!
//! This example runs one fuzzer in one process, which is also the natural unit
//! for SymSan (one session per process). Scaling out means LibAFL's `Launcher`,
//! which forks a process per core -- each would get its own stage and its own
//! session, and the per-pid shared-memory names already keep them apart.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use libafl::{
    HasMetadata,
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{HasObservers, StdChildArgs, forkserver::ForkserverExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{HavocScheduledMutator, Tokens, havoc_mutations, tokens_mutations},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
};
use libafl_bolts::{
    AsSliceMut, StdTargetArgs, Truncate,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{Handled, Merge, tuple_list},
};
use libafl_symsan::SymSanStage;
use nix::sys::signal::Signal;

/// Size of the AFL-style coverage map shared with the forkserver.
const MAP_SIZE: usize = 65536;

#[derive(Debug, Parser)]
#[command(
    name = "symsan-fuzz",
    about = "LibAFL fuzzer with a SymSan concolic execution stage"
)]
struct Opt {
    /// Directory of initial seed inputs.
    #[arg(short = 'i', long = "input", required = true)]
    in_dir: PathBuf,

    /// Directory for crashes.
    #[arg(short = 'o', long = "output", default_value = "./out")]
    out_dir: PathBuf,

    /// The SymSan-instrumented build of the target (`ko-clang`,
    /// `KO_USE_FASTGEN=1`). Omit it to run without the concolic stage, which is
    /// useful for an A/B against plain havoc fuzzing.
    #[arg(long = "symsan")]
    symsan_bin: Option<PathBuf>,

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

    /// Branch-id map for the coverage target, as written by a patched AFL++
    /// with `AFL_LLVM_DOCUMENT_IDS=<file> afl-clang-lto -g`. Given one, the
    /// concolic stage can see which branches the fuzzer has already covered
    /// and stops solving for them.
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

    // --- coverage plumbing --------------------------------------------------
    //
    // Straight out of LibAFL's forkserver_simple example: a shared memory map
    // the afl-cc instrumentation writes edge hits into, wrapped in an observer
    // the feedbacks read.

    let mut shmem_provider = UnixShMemProvider::new()?;
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE)?;
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

    let mut state = StdState::new(
        // `from_entropy` rather than a fixed seed: two instances started in the
        // same second should not explore identically.
        StdRand::new(),
        InMemoryCorpus::<BytesInput>::new(),
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
    let mut tokens = Tokens::new();
    let mut executor = ForkserverExecutor::builder()
        .program(executable)
        .debug_child(opt.debug_child)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        // Handles `@@` for us, allocating the forkserver's own input file.
        .parse_afl_cmdline(target_args.to_vec())
        .coverage_map_size(MAP_SIZE)
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

    // The two arms differ only in whether the concolic stage is present, but
    // they cannot share a variable: `tuple_list!` builds a distinct *type* per
    // arrangement of stages, and that type is baked in at compile time. This is
    // how LibAFL avoids dynamic dispatch in the hot loop -- the cost is that
    // "optional stage" means two code paths, not an `if`.
    match opt.symsan_bin {
        Some(bin) => {
            let mut builder = SymSanStage::builder()
                .target(&bin)
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
                .z3(opt.symsan_z3);
            if let Some(map) = &opt.branch_map {
                // The observer above is named "shared_mem", which is also the
                // name MaxMapFeedback::new() inherits and files its history map
                // under -- so the stage's default is already right, but say it
                // rather than leave the coupling implicit.
                builder = builder
                    .branch_map(map)
                    .coverage_map_name(edges_observer_name)
                    .validate_coverage(opt.validate_branch_map);
                println!("symsan: sharing coverage via {}", map.display());
                if opt.validate_branch_map {
                    // The observer tracks indices (see `.track_indices()`
                    // above), so every corpus entry already carries the edge
                    // set the audit needs -- nothing is re-executed for it.
                    println!("symsan: auditing the branch map (RUST_LOG=error to see verdicts)");
                }
            } else if opt.validate_branch_map {
                println!("symsan: --validate-branch-map ignored without --branch-map");
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

            // SymSan first: trace a newly scheduled entry before havoc starts
            // rewriting it, so the constraints describe the entry as it was
            // found interesting.
            let mut stages = tuple_list!(symsan, StdMutationalStage::new(mutator));
            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        }
        None => {
            println!("symsan: disabled (pass --symsan <binary> to enable)");
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));
            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        }
    }

    Ok(())
}
