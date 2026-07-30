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

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use libafl::{
    Error, HasMetadata,
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
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
use libafl_symsan::SymSanStage;
use libafl_targets::{
    AflppCmpLogMap,
    cmps::{observers::AflppCmpLogObserver, stages::AflppCmplogTracingStage},
};
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

    /// The cmplog-instrumented build of the target
    /// (`AFL_LLVM_CMPLOG=1 afl-clang-fast`). Given one, LibAFL's own cmplog
    /// pipeline runs: colorization, then a trace through this binary, then
    /// AFL++'s RedQueen. It is independent of `--symsan`; give both, either or
    /// neither, which is what puts all four arms of the comparison in one
    /// binary.
    #[arg(long = "cmplog")]
    cmplog_bin: Option<PathBuf>,

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
    // Built here, before `build()` takes the observer by value: colorization
    // needs it to tell "this byte changed nothing" from "this byte changed the
    // path". Cheap to construct and unused unless --cmplog was given.
    let colorization = ColorizationStage::new(&edges_observer);
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

    // `tuple_list!` builds a distinct *type* per arrangement of stages, and
    // that type is baked in at compile time -- which is how LibAFL avoids
    // dynamic dispatch in the hot loop. So "optional stage" cannot be an `if`
    // around the tuple: two optional stages would be four arms, each with its
    // own `fuzz_loop` call. `OptionalStage` is LibAFL's answer -- one type
    // either way, holding `Option<inner tuple>` and doing nothing when it is
    // `None`, at the cost of one branch per entry, which is nothing next to a
    // target execution.

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
            Some(tuple_list!(symsan))
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

            let cmplog_executor = ForkserverExecutor::builder()
                .program(bin)
                .debug_child(opt.debug_child)
                .shmem_provider(&mut shmem_provider)
                .parse_afl_cmdline(target_args.to_vec())
                .coverage_map_size(MAP_SIZE)
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
            let run_once_per_entry =
                |_fuzzer: &mut _,
                 _executor: &mut _,
                 state: &mut StdState<InMemoryCorpus<BytesInput>, _, _, _>,
                 _mgr: &mut _|
                 -> Result<bool, Error> {
                    Ok(state.current_testcase()?.scheduled_count() == 1)
                };

            println!("cmplog: tracing with {}", bin.display());
            Some(tuple_list!(IfStage::new(
                run_once_per_entry,
                tuple_list!(colorization, tracing, rq)
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
        StdMutationalStage::new(mutator)
    );
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}
