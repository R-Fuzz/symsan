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

    /// Exec the SymSan target once per trace instead of forking it from a
    /// long-lived server. Slower, but the way out if the target keeps state
    /// across `main()` that a fork would wrongly share.
    #[arg(long = "symsan-no-forkserver", default_value = "false")]
    symsan_no_forkserver: bool,

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

    // SAFETY: the map outlives the observer -- `shmem` is alive for all of main.
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
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
            let symsan = SymSanStage::builder()
                .target(&bin)
                // The stage does its own `@@` expansion against its own input
                // file, so it gets the raw arguments rather than the ones the
                // forkserver builder already rewrote.
                .args(target_args.iter().cloned())
                .input_file(opt.out_dir.join(format!(".symsan_input_{}", std::process::id())))
                .timeout_ms(opt.symsan_timeout)
                .max_solutions_per_input(opt.symsan_budget)
                .forkserver(!opt.symsan_no_forkserver)
                .build()?;
            println!("symsan: tracing with {}", bin.display());

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
