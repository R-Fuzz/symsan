//! A LibAFL [`Stage`] that drives SymSan's concolic execution.
//!
//! # What the stage does
//!
//! Once per corpus entry:
//!
//! 1. run the SymSan-instrumented build of the target on that entry, recording
//!    the symbolic constraints its branches imposed on the input;
//! 2. solve each constraint the other way round, producing mutated inputs;
//! 3. hand each mutated input to the fuzzer for a normal evaluation, and tell
//!    SymSan whether it turned out to be interesting.
//!
//! Step 3 is where a LibAFL stage beats the AFL++ custom mutator this replaces.
//! A custom mutator never learns what happened to the bytes it returned, so the
//! old driver had to *infer* it by comparing queue-entry filenames after the
//! fact. A stage calls the evaluator itself and gets an `ExecuteInputResult`
//! back, so [`Session::report_result`] is told the truth. That matters
//! concretely: on `false` the session escalates the same task to the next, more
//! expensive solver in the ladder; on `true` it stops, because the branch is
//! already won.
//!
//! # Two builds of the target
//!
//! The stage needs a second build of the program, made with `ko-clang` and
//! `KO_USE_FASTGEN=1`. It is *not* the binary your executor runs: that one is
//! built with `afl-cc` for coverage. They are separate processes with separate
//! instrumentation, and both are required. This mirrors how the AFL++ mutator
//! took its target from `$SYMSAN_TARGET`.
//!
//! # Sharing the work with cmplog
//!
//! A fuzzer that runs SymSan *and* AFL++ cmplog runs two input-to-state
//! techniques over the same entry, each unaware of the other. Turn on
//! [`SymSanStageBuilder::cmplog_filter`] and the second one is told what the
//! first already did: [`SymSanStage`] publishes a [`SymSanTaintMetadata`] per
//! traced entry, [`SymSanColorizationStage`] turns it into a colorized input in
//! two executions rather than `1 + 2 * input_len`, and
//! [`symsan_cmplog_worthwhile`] skips the whole cmplog group for an entry
//! SymSan finished off. What cmplog still sees is the comparisons SymSan could
//! not crack. See [`SymSanColorizationStage`] for why freezing a byte is all it
//! takes, and for the two kinds of comparison this cannot filter.
//!
//! # One stage per process
//!
//! [`SymSanStage`] owns a [`Session`], and SymSan permits one per process. With
//! LibAFL's `Launcher` each core is a separate process, so one stage per
//! fuzzer instance is exactly right -- but do not put two in the same
//! `tuple_list!`.
//!
//! # Example
//!
//! ```no_run
//! use libafl_symsan::SymSanStage;
//!
//! # fn main() -> Result<(), libafl::Error> {
//! // `@@` is replaced with the stage's own input file, AFL-style. Leave it out
//! // and the target is fed on stdin instead.
//! let symsan = SymSanStage::builder()
//!     .target("./target.symsan")
//!     .args(["@@"])
//!     .input_file("/tmp/.symsan_input")
//!     .timeout_ms(10_000)
//!     .build()?;
//!
//! // Put it first in the tuple, so a freshly scheduled entry is traced before
//! // the mutational stage starts churning on it:
//! //
//! //     let mut stages = tuple_list!(symsan, StdMutationalStage::new(mutator));
//! # Ok(())
//! # }
//! ```

use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::hash::Hash;
use std::io::Write;
use std::marker::PhantomData;
use std::ops::Range;
use std::path::{Path, PathBuf};

use libafl::{
    Error, HasMetadata, HasNamedMetadata,
    corpus::{Corpus, CorpusId, HasCurrentCorpusId},
    events::EventFirer,
    executors::{Executor, HasObservers},
    feedbacks::{MapFeedbackMetadata, MapIndexesMetadata},
    fuzzer::{Evaluator, ExecuteInputResult},
    inputs::{BytesInput, HasMutatorBytes},
    observers::ObserversTuple,
    stages::{Restartable, RetryCountRestartHelper, Stage, TaintMetadata},
    state::{HasCorpus, HasCurrentTestcase, HasRand},
};
use libafl_bolts::{
    Named, generic_hash_std, nonzero,
    rands::Rand,
    tuples::{Handle, Handled},
};
use serde::{Deserialize, Serialize};

pub use symsan::{Config, JoinReport, Session, Stats, TaintClass, Target, TargetEdge};

/// Default name, used to key the stage's restart metadata in the state.
pub const SYMSAN_STAGE_NAME: &str = "symsan";

/// Default name of the coverage observer whose history map the stage reads,
/// matching the one the bundled fuzzer gives its edges observer.
pub const DEFAULT_COVERAGE_MAP_NAME: &str = "shared_mem";

/// The AFL-style placeholder for "the input file goes here".
const INPUT_FILE_PLACEHOLDER: &str = "@@";

/// Translate a [`symsan::Error`] into LibAFL's error type.
///
/// A free function rather than a `From` impl: the orphan rule forbids
/// implementing a foreign trait (`From`) for a foreign type (`libafl::Error`)
/// from a third crate, and neither of the two is ours.
fn to_libafl(e: symsan::Error) -> Error {
    match e {
        symsan::Error::Invalid(m) => Error::illegal_argument(m),
        symsan::Error::Busy(m) => Error::illegal_state(m),
        symsan::Error::NotReady => Error::illegal_state("symsan session is not initialized"),
        other => Error::unknown(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// builder
// ---------------------------------------------------------------------------

/// Builder for [`SymSanStage`].
///
/// Split out from the stage itself because building one *creates a session*,
/// which can fail and which claims the process's single session slot. Making
/// that a distinct `build()` step keeps the fallible part visible.
#[derive(Debug, Default)]
pub struct SymSanStageBuilder {
    target: Option<PathBuf>,
    args: Vec<String>,
    input_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    branch_map: Option<PathBuf>,
    coverage_map_name: Option<String>,
    validate_coverage: bool,
    name: Option<String>,
    i2s: bool,
    jigsaw: bool,
    z3: bool,
    nested: bool,
    trace_bounds: bool,
    solve_ub: bool,
    debug: bool,
    timeout_ms: Option<u32>,
    max_solutions_per_input: usize,
    forkserver: bool,
    cmplog_filter: bool,
    flip_log: Option<PathBuf>,
}

impl SymSanStageBuilder {
    fn new() -> Self {
        Self {
            // Sensible defaults for fuzzing: i2s and jigsaw, but not Z3. i2s
            // alone is fast but only cracks direct input-to-state comparisons;
            // jigsaw is what makes the RGD stack worth running.
            //
            // Z3 is off because a fuzzing loop is a throughput game and Z3 is
            // the one rung that can spend seconds on a single task. It is the
            // most *capable* solver, so leaving it out does lose solves -- turn
            // it on for a target whose checks jigsaw's gradient descent cannot
            // climb, and expect the exec rate to drop for them.
            i2s: true,
            jigsaw: true,
            z3: false,
            // Also the fuzzing default: a trace of a short-running target
            // spends a good fraction of its wall clock on process setup, and
            // the fallback when a target cannot be served this way is silent.
            forkserver: true,
            ..Default::default()
        }
    }

    /// The SymSan-instrumented build of the target. Required.
    #[must_use]
    pub fn target(mut self, path: impl Into<PathBuf>) -> Self {
        self.target = Some(path.into());
        self
    }

    /// Arguments after `argv[0]`, AFL-style: a bare `@@` is replaced with the
    /// input file. If no `@@` appears, the target is fed on stdin.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Where to stage each traced input. Defaults to a per-pid path under the
    /// temp directory, so several fuzzer processes do not overwrite each
    /// other's input file.
    #[must_use]
    pub fn input_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.input_file = Some(path.into());
        self
    }

    /// Where SymSan writes solved inputs, if `save_solved` is on in the
    /// environment. A debugging aid.
    #[must_use]
    pub fn output_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_dir = Some(path.into());
        self
    }

    /// Share a branch namespace -- and therefore coverage -- with the fuzzer.
    ///
    /// `path` is what TaintPass writes when `-taint-branch-map=<file>` is set
    /// while instrumenting the target. It maps each side of each branch onto
    /// the AFL++ edge it reaches, which is what lets the stage look a branch up
    /// in the fuzzer's history map and skip solving for one the fuzzer already
    /// reached.
    ///
    /// Without it the session only knows what it has traced itself, so it keeps
    /// paying to re-solve branches the fuzzer covered long ago.
    #[must_use]
    pub fn branch_map(mut self, path: impl Into<PathBuf>) -> Self {
        self.branch_map = Some(path.into());
        self
    }

    /// Name of the coverage observer whose history map to read, when a
    /// [`branch_map`](Self::branch_map) is in use.
    ///
    /// This is the name of the *observer* the `MaxMapFeedback` was built from,
    /// since the feedback stores its metadata under its own name and inherits
    /// that from the observer. Defaults to [`DEFAULT_COVERAGE_MAP_NAME`].
    #[must_use]
    pub fn coverage_map_name(mut self, name: impl Into<String>) -> Self {
        self.coverage_map_name = Some(name.into());
        self
    }

    /// Check the branch map against ground truth on every traced entry.
    ///
    /// A debugging mode, off by default. Where
    /// [`branch_map`](Self::branch_map) *uses* the join, this *audits* it: for
    /// each entry, the edges the fuzzer's own build recorded (the testcase's
    /// `MapIndexesMetadata`) are held against the edges the map claims the
    /// trace's branch directions correspond to. Mismatches are logged.
    ///
    /// Worth turning on once when setting up a new target, because a map that
    /// joins to the *wrong* edges fails silently -- the stage simply stops
    /// solving, and [`Stats::mapped_branches`] still looks healthy. Not worth
    /// leaving on: it costs a hash insert per branch and a comparison per
    /// entry.
    ///
    /// Requires a [`branch_map`](Self::branch_map), and the fuzzer's map
    /// feedback to have been built with `track_indices()` -- the bundled
    /// fuzzer's is.
    #[must_use]
    pub fn validate_coverage(mut self, yes: bool) -> Self {
        self.validate_coverage = yes;
        self
    }

    /// Distinguish this stage's restart metadata from another's. Rarely needed.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Include the input-to-state solver, the cheapest rung. On by default,
    /// and worth leaving on: it costs almost nothing and it is what cracks the
    /// "input byte compared against a constant" shape most branches have.
    #[must_use]
    pub fn i2s(mut self, yes: bool) -> Self {
        self.i2s = yes;
        self
    }

    /// Include the JIT/gradient-descent solver. On by default.
    #[must_use]
    pub fn jigsaw(mut self, yes: bool) -> Self {
        self.jigsaw = yes;
        self
    }

    /// Include Z3 as the last resort. **Off** by default: it is the only rung
    /// that can spend seconds on one task, which a fuzzing loop feels.
    #[must_use]
    pub fn z3(mut self, yes: bool) -> Self {
        self.z3 = yes;
        self
    }

    /// Fold path constraints into each task. More precise, more expensive; off
    /// by default because a fuzzing loop usually gets there faster by
    /// re-tracing a solved input than by solving deeply the first time.
    #[must_use]
    pub fn nested_solving(mut self, yes: bool) -> Self {
        self.nested = yes;
        self
    }

    /// Track allocation bounds, so out-of-bounds accesses can be detected.
    #[must_use]
    pub fn trace_bounds(mut self, yes: bool) -> Self {
        self.trace_bounds = yes;
        self
    }

    /// Solve for undefined behaviour as well as coverage.
    #[must_use]
    pub fn solve_ub(mut self, yes: bool) -> Self {
        self.solve_ub = yes;
        self
    }

    /// Verbose output from the SymSan runtime.
    #[must_use]
    pub fn debug(mut self, yes: bool) -> Self {
        self.debug = yes;
        self
    }

    /// Per-trace timeout in milliseconds. Strongly recommended: without it a
    /// target that loops forever on some input wedges the whole fuzzer.
    #[must_use]
    pub fn timeout_ms(mut self, ms: u32) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    /// Stop after this many solutions for a single corpus entry; `0` means no
    /// limit. A budget knob for targets where one input yields thousands of
    /// tasks and the mutational stage would otherwise never get a turn.
    #[must_use]
    pub fn max_solutions_per_input(mut self, n: usize) -> Self {
        self.max_solutions_per_input = n;
        self
    }

    /// Trade a per-trace `execv` for a `fork`. On by default.
    ///
    /// The target is spawned once and forks a child per input, which skips the
    /// dynamic link and the shadow and union table setup every trace. It needs
    /// file input (`@@`) and a target whose backend has a fork server; neither
    /// is an error, since the session falls back to exec'ing per run.
    ///
    /// Turn it off if the target keeps state across `main()` that a fork would
    /// wrongly share -- a `/dev/urandom` fd it seeds itself from, say.
    #[must_use]
    pub fn forkserver(mut self, enable: bool) -> Self {
        self.forkserver = enable;
        self
    }

    /// Publish, after each trace, which of the entry's bytes are still worth
    /// mutating -- so a cmplog pipeline running alongside can leave the rest
    /// alone. Off by default, because it only pays for itself when there *is*
    /// such a pipeline.
    ///
    /// With it on, the stage attaches a [`SymSanTaintMetadata`] to the state
    /// for every entry it traces. [`SymSanColorizationStage`] turns that into
    /// the colorized input AFL++ RedQueen consumes, and
    /// [`symsan_cmplog_worthwhile`] / [`symsan_needs_stock_colorization`] gate
    /// the rest of the pipeline on it. See the [module docs](crate) for why
    /// freezing a byte is enough to make RedQueen skip it.
    ///
    /// Costs one flag on the session and a bitset walk per trace; nothing runs
    /// twice.
    #[must_use]
    pub fn cmplog_filter(mut self, yes: bool) -> Self {
        self.cmplog_filter = yes;
        self
    }

    /// Check every solution against the branch it was solved for, and append
    /// the verdict to @p path as `<cid> <direction> <dest edge> <outcome>`.
    ///
    /// Without this the stage reports `solved` -- solutions the fuzzer found
    /// interesting -- and that is not the same question. A solved input is run
    /// on the coverage build, where new coverage *anywhere* makes it
    /// interesting, including coverage the mutated bytes reached nowhere near
    /// the branch they were solved for. So a target whose ASTs are wrong can
    /// report a healthy solve rate indefinitely: the arithmetic is unsound, the
    /// solver is SAT on it anyway, and the resulting input still stumbles into
    /// something new. The classic source is an uninstrumented library --
    /// zlib's inflate writes decompressed bytes with no labels, so the shadow
    /// still describes whatever occupied that memory before.
    ///
    /// Needs a [`branch_map`](Self::branch_map) to know which edge to look for;
    /// without one every verdict is [`Flip::Unknown`]. The task-to-branch link
    /// it reads comes from `export_taint`, which this switches on by itself --
    /// no [`cmplog_filter`](Self::cmplog_filter) required.
    ///
    /// Costs no execution: the ids are shared between the two builds, so the
    /// coverage the fuzzer already recorded for the solution is the answer.
    #[must_use]
    pub fn flip_log(mut self, path: impl Into<PathBuf>) -> Self {
        self.flip_log = Some(path.into());
        self
    }

    /// Create the session and the stage.
    ///
    /// Fails if `target` was not set, if a session already exists in this
    /// process, or if SymSan cannot start the target.
    pub fn build(self) -> Result<SymSanStage, Error> {
        let target = self
            .target
            .ok_or_else(|| Error::illegal_argument("SymSanStage needs a target()"))?;
        let target = path_str(&target)?.to_owned();

        let input_file = self.input_file.unwrap_or_else(|| {
            std::env::temp_dir().join(format!(".symsan_input_{}", std::process::id()))
        });
        let input_file_str = path_str(&input_file)?.to_owned();

        // AFL convention: `@@` in the arguments means "the input file", and its
        // absence means the target reads stdin. argv[0] is the target itself,
        // as every execve-based launcher expects.
        let mut argv = Vec::with_capacity(self.args.len() + 1);
        argv.push(target.clone());
        let mut uses_file = false;
        for arg in &self.args {
            if arg == INPUT_FILE_PLACEHOLDER {
                uses_file = true;
                argv.push(input_file_str.clone());
            } else {
                argv.push(arg.clone());
            }
        }

        let mut config = Config::new(&target, &input_file_str)
            .args(argv)
            .use_stdin(!uses_file)
            .i2s(self.i2s)
            .jigsaw(self.jigsaw)
            .z3(self.z3)
            .nested_solving(self.nested)
            .trace_bounds(self.trace_bounds)
            .solve_ub(self.solve_ub)
            .debug(self.debug)
            .forkserver(self.forkserver)
            // What export_taint buys is the per-task record of which branch a
            // solution was solved for. The cmplog filter reads it to decide
            // what to hand cmplog; the flip log reads it to name the branch it
            // is judging. Either one alone is reason enough to pay for it.
            .export_taint(self.cmplog_filter || self.flip_log.is_some());
        if let Some(ms) = self.timeout_ms {
            config = config.timeout_ms(ms);
        }
        if let Some(dir) = &self.output_dir {
            config = config.output_dir(path_str(dir)?);
        }
        if let Some(map) = &self.branch_map {
            config = config.branch_map(path_str(map)?);
        }
        if self.validate_coverage {
            if self.branch_map.is_none() {
                return Err(Error::illegal_argument(
                    "validate_coverage() without branch_map(): there is no join to check",
                ));
            }
            config = config.validate_coverage(true);
        }

        // Reading the history map is only meaningful with a branch map to join
        // it against, so the observer name is remembered only in that case --
        // and asking for one without the other is a mistake worth naming.
        let coverage_map_name = match (&self.branch_map, self.coverage_map_name) {
            (Some(_), name) => Some(name.unwrap_or_else(|| DEFAULT_COVERAGE_MAP_NAME.to_owned())),
            (None, Some(_)) => {
                return Err(Error::illegal_argument(
                    "coverage_map_name() without branch_map(): there is no way to tell \
                     which entry of the coverage map belongs to which branch",
                ));
            }
            (None, None) => None,
        };

        // Opened before the session, so a bad path fails the build rather than
        // leaving a live session behind.
        let flip_log = match &self.flip_log {
            Some(path) => Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| {
                        Error::illegal_argument(format!(
                            "cannot open the flip log {}: {e}",
                            path.display()
                        ))
                    })?,
            ),
            None => None,
        };

        let mut session = Session::new().map_err(to_libafl)?;
        session.init(&config).map_err(to_libafl)?;

        Ok(SymSanStage {
            session,
            name: Cow::Owned(self.name.unwrap_or_else(|| SYMSAN_STAGE_NAME.to_owned())),
            traced: HashSet::new(),
            max_solutions_per_input: self.max_solutions_per_input,
            coverage_map_name,
            coverage_warned: false,
            validate_coverage: self.validate_coverage,
            validate_warned: false,
            join: JoinReport::default(),
            join_entries: 0,
            solutions: 0,
            solved: 0,
            cmplog_filter: self.cmplog_filter,
            flip_log,
            flips: [0; 4],
        })
    }
}

/// Paths are `OsString`s, but the C ABI wants UTF-8. Reject rather than mangle.
fn path_str(p: &Path) -> Result<&str, Error> {
    p.to_str()
        .ok_or_else(|| Error::illegal_argument(format!("path is not valid UTF-8: {}", p.display())))
}

// ---------------------------------------------------------------------------
// the stage
// ---------------------------------------------------------------------------

/// A [`Stage`] that concolically executes each new corpus entry.
///
/// See the [module docs](crate) for what it does and how to set it up.
///
/// Note there are no type parameters on the struct. The input type is fixed to
/// [`BytesInput`] -- SymSan solves over a flat byte buffer, so there is nothing
/// to generalise -- and `E`/`EM`/`S`/`Z` appear only in the [`Stage`] impl,
/// which means no `PhantomData` and no turbofish at the call site.
#[derive(Debug)]
pub struct SymSanStage {
    session: Session,
    name: Cow<'static, str>,
    /// Corpus entries already traced.
    ///
    /// Tracing is expensive and deterministic: running it twice on the same
    /// bytes yields the same constraints, so there is nothing to gain. This
    /// replaces the `fuzzed_inputs` set the AFL++ mutator kept.
    ///
    /// Deliberately a plain in-process set rather than state metadata: the
    /// [`Session`] it guards is itself per-process and does not survive a
    /// restart, so persisting the set would only make a restarted fuzzer skip
    /// work its new session never actually did.
    traced: HashSet<CorpusId>,
    max_solutions_per_input: usize,
    /// Observer name to read the fuzzer's history map from before each trace,
    /// or `None` when no branch map was configured and the session therefore
    /// has no way to interpret it.
    coverage_map_name: Option<String>,
    /// Whether the "could not read the history map" warning has already been
    /// issued. It would otherwise repeat once per corpus entry.
    coverage_warned: bool,
    /// Audit the branch map against each entry's tracked edge indices. See
    /// [`SymSanStageBuilder::validate_coverage`].
    validate_coverage: bool,
    /// As `coverage_warned`, for the audit's own setup complaints.
    validate_warned: bool,
    /// The audit's counters, summed over every entry checked. Per-entry reports
    /// are logged as they happen; this is what a caller can read at the end.
    join: JoinReport,
    /// Entries the audit actually managed to check.
    join_entries: u64,
    solutions: u64,
    solved: u64,
    /// Publish a [`SymSanTaintMetadata`] per traced entry. See
    /// [`SymSanStageBuilder::cmplog_filter`].
    cmplog_filter: bool,
    /// Where to append one line per solution saying whether the branch it was
    /// solved for actually flipped, or `None` to not check at all. See
    /// [`SymSanStageBuilder::flip_log`].
    flip_log: Option<File>,
    /// Flip outcomes so far, indexed by [`Flip`] as `usize`.
    flips: [u64; 4],
}

/// What became of the branch a solution was solved for.
///
/// The two "cannot tell" cases are kept apart from the answer rather than
/// folded into it: a rate computed over them would drift with how much of the
/// map the run has already covered, which has nothing to do with solver
/// quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flip {
    /// The run took the branch the way it was solved to go. The solve worked.
    Flipped = 0,
    /// The run did not take it, and would have been noticed if it had. The
    /// solver returned SAT on an AST that does not describe the program.
    Missed = 1,
    /// Something else had already covered that edge, so this run taking it
    /// would have gone unremarked. No conclusion either way.
    AlreadyCovered = 2,
    /// No edge to look for: the direction is pruned or unmapped, the branch map
    /// is absent, or the input was filtered out before it ever ran.
    Unknown = 3,
}

impl SymSanStage {
    /// Start configuring a stage. See [`SymSanStageBuilder`].
    #[must_use]
    pub fn builder() -> SymSanStageBuilder {
        SymSanStageBuilder::new()
    }

    /// SymSan's own counters: branches seen, tasks queued, tasks solved.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.session.stats()
    }

    /// How many solved inputs this stage has handed to the fuzzer.
    #[must_use]
    pub fn solutions(&self) -> u64 {
        self.solutions
    }

    /// How many of those the fuzzer found interesting -- new coverage or a
    /// crash. The honest number the AFL++ mutator could only estimate.
    #[must_use]
    pub fn solved(&self) -> u64 {
        self.solved
    }

    /// Corpus entries traced so far.
    #[must_use]
    pub fn traced(&self) -> usize {
        self.traced.len()
    }

    /// The branch-map audit's totals, summed over every entry it checked.
    ///
    /// All zero unless [`SymSanStageBuilder::validate_coverage`] was set. A
    /// non-zero [`JoinReport::violations`] means the map names the wrong edge
    /// for at least one branch -- see [`join_entries`](Self::join_entries) for
    /// how much evidence that is drawn from.
    #[must_use]
    pub fn join_report(&self) -> JoinReport {
        self.join
    }

    /// Corpus entries the audit managed to check. Zero with a non-zero
    /// [`join_report`](Self::join_report) is impossible; zero with the audit on
    /// means it never found the tracked indices to check against.
    #[must_use]
    pub fn join_entries(&self) -> u64 {
        self.join_entries
    }

    /// Write SymSan's full statistics -- counters, the task-size histogram and
    /// each solver's own numbers -- to a file descriptor. `2` is stderr.
    pub fn print_stats(&self, fd: i32) {
        self.session.print_stats(fd);
    }

    /// How many solutions fell into each [`Flip`] class.
    ///
    /// All zero unless [`SymSanStageBuilder::flip_log`] is set. `Flipped`
    /// against `Flipped + Missed` is the rate worth quoting -- the other two
    /// classes are "could not tell", and folding them in would make the number
    /// move with how much of the map is already covered.
    #[must_use]
    pub fn flips(&self) -> [u64; 4] {
        self.flips
    }

    /// Is edge @p edge already set in the fuzzer's history map?
    ///
    /// `None` when there is no history map to read, which is a different answer
    /// from `Some(false)` and must not collapse into it.
    fn edge_covered<S>(&self, state: &S, edge: u32) -> Option<bool>
    where
        S: HasNamedMetadata,
    {
        let name = self.coverage_map_name.as_ref()?;
        let meta = state.named_metadata::<MapFeedbackMetadata<u8>>(name).ok()?;
        meta.history_map.get(edge as usize).map(|&v| v != 0)
    }

    /// Did the branch @p target was solved for actually go the other way?
    ///
    /// @p was_covered is [`edge_covered`](Self::edge_covered) read *before* the
    /// run, @p result the fuzzer's verdict on it, and @p added the corpus entry
    /// the run produced, if any.
    ///
    /// Two independent pieces of evidence, because neither covers every case.
    /// When the solution was added to the corpus its tracked indices are the
    /// exact edge set of that execution, and membership settles it outright.
    /// When it was not added there are no indices -- but not being added is
    /// itself informative: had the run taken a previously-uncovered edge, that
    /// is new coverage, and it would have been added. So an uncovered target
    /// edge plus a *rejected* input means the branch did not move.
    ///
    /// Rejected is the load-bearing word, and why @p result is here at all: an
    /// input that crashes is filed as an objective, which also leaves @p added
    /// empty. Reading that as "did not move" would score every crashing
    /// solution as a miss -- exactly the solutions most likely to have moved
    /// something.
    fn judge_flip<S>(
        &self,
        state: &S,
        target: Target,
        was_covered: Option<bool>,
        result: ExecuteInputResult,
        added: Option<CorpusId>,
    ) -> Flip
    where
        S: HasCorpus<BytesInput> + HasNamedMetadata,
    {
        // Nothing to look for: pruned means AFL++ numbered no edge for this
        // side, unmapped means the branch map never heard of the branch. In
        // both cases the branch may well have flipped and left no trace, so
        // this is "cannot tell", not "no".
        let TargetEdge::Edge(edge) = target.dest_edge else {
            return Flip::Unknown;
        };

        if let Some(id) = added {
            if let Ok(tc) = state.corpus().get(id) {
                let took = tc
                    .borrow()
                    .metadata::<MapIndexesMetadata>()
                    .ok()
                    .map(|m| m.list.iter().any(|&i| i as u32 == edge));
                if let Some(took) = took {
                    return if took { Flip::Flipped } else { Flip::Missed };
                }
            }
        }

        match was_covered {
            // Already covered before the run, and no indices to check against:
            // taking it again would have looked like nothing happened.
            Some(true) => Flip::AlreadyCovered,
            // Not covered before, and the fuzzer found nothing in it at all --
            // so the run did not take it.
            Some(false) if result == ExecuteInputResult::None => Flip::Missed,
            // Interesting, but with no corpus entry to inspect: an objective.
            // It may well have flipped on its way to crashing.
            Some(false) => Flip::Unknown,
            // No history map at all.
            None => Flip::Unknown,
        }
    }

    /// Append one verdict to the flip log. Failures are silent by design: a
    /// full disk must not take the fuzzer down over a measurement.
    fn record_flip(&mut self, target: Target, flip: Flip) {
        let Some(log) = self.flip_log.as_mut() else {
            return;
        };
        let dest = match target.dest_edge {
            TargetEdge::Edge(e) => e.to_string(),
            TargetEdge::Pruned => "pruned".to_owned(),
            TargetEdge::Unmapped => "unmapped".to_owned(),
        };
        let outcome = match flip {
            Flip::Flipped => "flipped",
            Flip::Missed => "missed",
            Flip::AlreadyCovered => "already-covered",
            Flip::Unknown => "unknown",
        };
        let _ = writeln!(
            log,
            "{}\t{}\t{dest}\t{outcome}",
            target.cid,
            u8::from(target.direction)
        );
    }

    /// Attach this entry's byte classification to its testcase, for the cmplog
    /// pipeline to read when the entry is scheduled again. A no-op unless
    /// [`cmplog_filter`](SymSanStageBuilder::cmplog_filter) is on.
    ///
    /// Every way of failing publishes nothing at all, because "this testcase
    /// carries no taint" is precisely how the readers are told to do the full
    /// job.
    fn publish_taint<S>(&mut self, state: &mut S, corpus_id: CorpusId, input_len: usize)
    where
        S: HasCurrentTestcase<BytesInput>,
    {
        if !self.cmplog_filter {
            return;
        }
        let classes = match self.session.input_taint() {
            Ok(c) => c,
            Err(e) => {
                log::warn!("symsan: cannot read the taint of entry {corpus_id}: {e}");
                return;
            }
        };
        // The session clamps what it traces to max_input_size, so a long entry
        // can come back classified only in part. Rather than teach every reader
        // about a partial answer, say nothing and let them do the full job.
        if classes.len() != input_len {
            log::debug!(
                "symsan: entry {corpus_id} is {input_len} bytes but only {} were traced; \
                 not filtering cmplog for it",
                classes.len()
            );
            return;
        }

        let meta = SymSanTaintMetadata::new(&classes);
        log::debug!(
            "symsan: entry {corpus_id} taint: {} settled, {} open, {} untainted",
            meta.settled_count(),
            meta.open_count(),
            input_len - meta.tainted()
        );
        match state.current_testcase_mut() {
            Ok(mut testcase) => testcase.add_metadata(meta),
            Err(e) => log::warn!("symsan: cannot record the taint of entry {corpus_id}: {e}"),
        }
    }
}

impl Named for SymSanStage {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for SymSanStage
where
    // The state must have a corpus of byte inputs and know which entry is
    // current. `HasCurrentTestcase` -- which gives us `current_input_cloned()`
    // -- is blanket-implemented for exactly that combination.
    // `HasNamedMetadata` is where the coverage feedback keeps its history map,
    // which is what branch_map() needs to read; `Restartable` requires it of
    // `S` anyway, so it costs a stage nothing. `HasMetadata` is where
    // cmplog_filter() publishes its answer.
    S: HasCorpus<BytesInput>
        + HasCurrentCorpusId
        + HasCurrentTestcase<BytesInput>
        + HasMetadata
        + HasNamedMetadata,
    // ...and the fuzzer must be able to run and judge an input for us. This is
    // the bound that makes honest reporting possible.
    Z: Evaluator<E, EM, BytesInput, S>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let Some(corpus_id) = state.current_corpus_id()? else {
            // No entry is scheduled; nothing to trace. Not an error -- some
            // fuzzer configurations run stages outside a corpus iteration.
            return Ok(());
        };

        // `insert` returns false if it was already there, which folds the
        // "have we seen this?" check and the bookkeeping into one lookup.
        if !self.traced.insert(corpus_id) {
            return Ok(());
        }

        // Clone the bytes out of the testcase. The clone is necessary, not
        // incidental: `current_testcase()` hands back a `Ref` that borrows the
        // corpus, and we are about to call `fuzzer.evaluate_filtered(state,
        // ...)`, which needs `&mut state`. Holding the Ref across that would
        // not compile -- and if it did, it would be a RefCell panic at runtime.
        let input: BytesInput = state.current_input_cloned()?;
        let bytes: Vec<u8> = input.into();

        // Ground truth for the branch-map audit: the edge ids the *fuzzer's*
        // build recorded for these very bytes. Free, because a `MaxMapFeedback`
        // built with `track_indices()` attaches them to every corpus entry, so
        // nothing has to be executed a second time.
        //
        // Read here rather than after the trace because the loop below needs
        // `&mut state`, and the `Ref` into the corpus cannot survive that.
        let covered: Option<Vec<u32>> = if self.validate_coverage {
            let indices = state.current_testcase().ok().and_then(|tc| {
                tc.metadata::<MapIndexesMetadata>()
                    .ok()
                    .map(|m| m.list.iter().map(|&i| i as u32).collect::<Vec<u32>>())
            });
            if indices.is_none() && !self.validate_warned {
                log::warn!(
                    "symsan: validate_coverage is on but corpus entries carry no \
                     MapIndexesMetadata; build the map feedback with track_indices()"
                );
                self.validate_warned = true;
            }
            indices
        } else {
            None
        };

        // Tell the session what the fuzzer has already covered, so it does not
        // spend the whole trace solving for branches that were won hours ago.
        // Done per entry rather than once: the history map only grows, and a
        // stale snapshot would just mean redundant work, not wrong answers.
        if let Some(map_name) = &self.coverage_map_name {
            match state.named_metadata::<MapFeedbackMetadata<u8>>(map_name) {
                Ok(meta) => {
                    if let Err(e) = self.session.set_coverage(&meta.history_map) {
                        if !self.coverage_warned {
                            log::warn!("symsan: cannot share coverage: {e}");
                            self.coverage_warned = true;
                        }
                    }
                }
                Err(e) => {
                    // Wrong observer name, or a fuzzer whose map is not u8.
                    // Not fatal -- without a snapshot the session simply falls
                    // back to its own view, which is what it did before.
                    if !self.coverage_warned {
                        log::warn!(
                            "symsan: no u8 coverage map named {map_name:?} in the state ({e}); \
                             running without shared coverage"
                        );
                        self.coverage_warned = true;
                    }
                }
            }
        }

        let tasks = match self.session.trace(&bytes) {
            Ok(n) => n,
            Err(e) => {
                // A target that crashes, hangs or blows a limit under tracing
                // must not take the fuzzer down with it: skip this entry and
                // carry on. It is already marked traced, so we will not retry.
                log::warn!("symsan: tracing corpus entry {corpus_id} failed: {e}");
                return Ok(());
            }
        };
        // Audit the join now, while the session still holds the directions this
        // trace took. Deliberately before the `tasks == 0` bail-out: an entry
        // that yields nothing to solve has still exercised branches, and a
        // wrong map is exactly why it might have yielded nothing.
        if let Some(covered) = &covered {
            match self.session.check_coverage(covered) {
                Ok(r) => {
                    self.join_entries += 1;
                    self.join.executed += r.executed;
                    self.join.checked += r.checked;
                    self.join.violations += r.violations;
                    self.join.pruned += r.pruned;
                    self.join.unmapped += r.unmapped;
                    if r.is_consistent() {
                        log::debug!(
                            "symsan: entry {corpus_id} join ok: {}/{} directions checked \
                             against {} fuzzer edges, {} unmapped, {} pruned",
                            r.checked,
                            r.executed,
                            covered.len(),
                            r.unmapped,
                            r.pruned
                        );
                    } else {
                        // Loud, because this is not a missed opportunity: the
                        // map is pointing at edges the fuzzer never took, so
                        // every branch it resolves is being judged against
                        // somebody else's coverage.
                        log::error!(
                            "symsan: entry {corpus_id} contradicts the branch map: \
                             {} of {} checked directions map to an edge the fuzzer's \
                             build did not record. The two builds disagree about \
                             branch identity, or they took different paths on the \
                             same input.",
                            r.violations,
                            r.checked
                        );
                    }
                }
                Err(e) => {
                    if !self.validate_warned {
                        log::warn!("symsan: cannot audit the branch map: {e}");
                        self.validate_warned = true;
                    }
                }
            }
        }

        // Not an early return, unlike every other bail-out above: an entry with
        // nothing to solve has still exercised branches, and "every target on
        // this path is already reached" is the single most useful answer the
        // taint export can give -- it is what lets the cmplog group be skipped
        // outright. So fall through to publish it.
        // Logged unconditionally, including the zero: a stage that traces every
        // entry and solves nothing looks exactly like a stage that never ran,
        // and the two have completely different causes.
        log::debug!("symsan: corpus entry {corpus_id} produced {tasks} tasks");
        if tasks != 0 {

            let mut produced = 0usize;
            while let Some(solution) = self.session.next_solution() {
                self.solutions += 1;
                produced += 1;

                // Before the run, while the solution is still outstanding:
                // report_result() below retires the task, and after that the
                // session no longer knows what this input was for.
                let target = if self.flip_log.is_some() {
                    self.session.current_target()
                } else {
                    None
                };
                // Whether the edge we are about to look for was *already*
                // covered. Has to be read before the run, because the run is
                // what would add it -- and if it was already there, finding it
                // afterwards proves nothing.
                let was_covered = target.and_then(|t| match t.dest_edge {
                    TargetEdge::Edge(e) => self.edge_covered(state, e),
                    _ => None,
                });

                // Hand the solved input to the fuzzer exactly as a mutational
                // stage would: it runs it on the *coverage-instrumented* build,
                // applies the feedbacks, and adds it to the corpus if it is
                // interesting. `evaluate_filtered` honours the fuzzer's input
                // filter, so an input we have already seen is not re-run.
                let (result, added) =
                    fuzzer.evaluate_filtered(state, executor, manager, &BytesInput::new(solution))?;

                let interesting = result != ExecuteInputResult::None;
                if interesting {
                    self.solved += 1;
                }

                if let Some(target) = target {
                    let flip = self.judge_flip(state, target, was_covered, result, added);
                    self.flips[flip as usize] += 1;
                    self.record_flip(target, flip);
                }
                // The honest answer. `false` makes the session escalate this
                // task to the next solver in the ladder; `true` retires it.
                self.session.report_result(interesting);

                if self.max_solutions_per_input != 0 && produced >= self.max_solutions_per_input {
                    log::debug!(
                        "symsan: hit the {} solution budget for corpus entry {corpus_id}, \
                         dropping {} pending tasks",
                        self.max_solutions_per_input,
                        self.session.pending_tasks()
                    );
                    break;
                }
            }
        }

        // Last, because a target only counts as reached once report_result()
        // has said its solution was interesting.
        self.publish_taint(state, corpus_id, bytes.len());

        Ok(())
    }
}

impl<S> Restartable<S> for SymSanStage
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        // No retries. If tracing an entry killed the fuzzer once it will do so
        // again, and the entry is not worth a restart loop -- the same
        // reasoning `SyncFromDiskStage` uses.
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

// ---------------------------------------------------------------------------
// telling cmplog which bytes are still worth attacking
// ---------------------------------------------------------------------------

/// What SymSan's trace said about the bytes of one corpus entry.
///
/// Published by [`SymSanStage`] when
/// [`cmplog_filter`](SymSanStageBuilder::cmplog_filter) is on, and consumed by
/// [`SymSanColorizationStage`] and the two gates below.
///
/// It lives on the **testcase**, not on the state, because the two sides of
/// this are a scheduling apart: SymSan traces an entry the first time it is
/// scheduled, while the cmplog group waits for the second (`scheduled_count()
/// == 1`, the same condition upstream's cmplog fuzzers use). A single slot in
/// the state would have been overwritten by every entry traced in between.
///
/// Stored as the *runs* of bytes still worth moving rather than a flag per
/// byte, which keeps it to a few words per entry however long the input is --
/// it has to survive on the testcase until that second scheduling, and a
/// per-byte vector would have doubled what the corpus costs to hold.
#[derive(Debug, Serialize, Deserialize)]
// impl_serdeany! gives the type a `pub unsafe fn register`, which is all this
// lint is reacting to.
#[allow(clippy::unsafe_derive_deserialize)]
pub struct SymSanTaintMetadata {
    /// Ascending, non-adjacent runs of the bytes an input-to-state pass should
    /// still move. Everything outside them is settled: every branch target
    /// reading it has been reached, so there is nothing left to flip there.
    movable: Vec<Range<usize>>,
    /// Length of the input this describes, so a reader can tell it is looking
    /// at the entry it thinks it is.
    input_len: usize,
    /// How many bytes any branch on the traced path read at all. The rest are
    /// bytes SymSan saw nothing depend on -- which is *not* the same as bytes
    /// nothing depends on, so they are never frozen.
    tainted: usize,
    /// Set by [`SymSanColorizationStage`] when its one-shot colorized input did
    /// not reproduce the original coverage, meaning the stock bisecting
    /// [`ColorizationStage`](libafl::stages::ColorizationStage) has to run
    /// after all.
    fallback: bool,
}

libafl_bolts::impl_serdeany!(SymSanTaintMetadata);

impl SymSanTaintMetadata {
    fn new(classes: &[TaintClass]) -> Self {
        let mut movable: Vec<Range<usize>> = Vec::new();
        let mut tainted = 0;
        for (i, class) in classes.iter().enumerate() {
            if *class != TaintClass::Untainted {
                tainted += 1;
            }
            if *class == TaintClass::Settled {
                continue;
            }
            match movable.last_mut() {
                Some(last) if last.end == i => last.end = i + 1,
                _ => movable.push(i..i + 1),
            }
        }
        Self {
            movable,
            input_len: classes.len(),
            tainted,
            fallback: false,
        }
    }

    /// The runs of bytes an input-to-state pass should still move.
    #[must_use]
    pub fn movable(&self) -> &[Range<usize>] {
        &self.movable
    }

    /// Length of the input this describes.
    #[must_use]
    pub fn input_len(&self) -> usize {
        self.input_len
    }

    /// Bytes some branch on the traced path read.
    #[must_use]
    pub fn tainted(&self) -> usize {
        self.tainted
    }

    /// Bytes that are settled, and so may be held still.
    #[must_use]
    pub fn settled_count(&self) -> usize {
        self.input_len - self.movable.iter().map(Range::len).sum::<usize>()
    }

    /// Tainted bytes that are *not* settled -- some target reading them is
    /// still unreached.
    #[must_use]
    pub fn open_count(&self) -> usize {
        self.tainted - self.settled_count()
    }

    /// Whether the stock colorization stage still has to run for this entry.
    #[must_use]
    pub fn fallback(&self) -> bool {
        self.fallback
    }

    /// Is there anything here for an input-to-state pass to do?
    ///
    /// False only when *every* byte is settled. Note this is weaker than "no
    /// open byte": untainted bytes count as work too, because SymSan's taint
    /// under-approximates -- a comparison reached through something it does not
    /// model (a libc call it has no wrapper for, hand-written assembly) leaves
    /// its operands looking untainted, and cmplog observes those just fine.
    /// Freezing them would hand cmplog exactly the blind spots SymSan has.
    #[must_use]
    pub fn worth_mutating(&self) -> bool {
        !self.movable.is_empty()
    }
}

/// Should the cmplog pipeline run at all for the entry being fuzzed?
///
/// True unless SymSan traced this very entry and found every one of its bytes
/// settled -- see [`SymSanTaintMetadata::worth_mutating`]. No answer, because
/// the entry was never traced or the trace failed, means yes, run it: this
/// filter only ever removes work it can prove is redundant.
pub fn symsan_cmplog_worthwhile<S>(state: &S) -> Result<bool, Error>
where
    S: HasCurrentTestcase<BytesInput> + HasCurrentCorpusId,
{
    let Some(corpus_id) = state.current_corpus_id()? else {
        return Ok(true);
    };
    let Ok(meta) = state
        .current_testcase()?
        .metadata::<SymSanTaintMetadata>()
        .map(SymSanTaintMetadata::worth_mutating)
    else {
        return Ok(true);
    };
    if !meta {
        log::debug!("symsan: skipping cmplog for entry {corpus_id}: every byte is settled");
    }
    Ok(meta)
}

/// Does the stock [`ColorizationStage`](libafl::stages::ColorizationStage)
/// still have to run for the entry being fuzzed?
///
/// True when [`SymSanColorizationStage`] could not do the job -- no taint for
/// this entry, or a colorized input whose coverage did not match. Meant to gate
/// a stock colorization stage placed immediately after it.
pub fn symsan_needs_stock_colorization<S>(state: &S) -> Result<bool, Error>
where
    S: HasCurrentTestcase<BytesInput> + HasCurrentCorpusId,
{
    if state.current_corpus_id()?.is_none() {
        return Ok(true);
    }
    Ok(state
        .current_testcase()?
        .metadata::<SymSanTaintMetadata>()
        .map_or(true, SymSanTaintMetadata::fallback))
}

/// Default name for [`SymSanColorizationStage`].
pub const SYMSAN_COLORIZATION_STAGE_NAME: &str = "symsan_colorization";

/// Colorize an input the way AFL++ does, but using SymSan's taint instead of
/// bisection to decide which bytes may move.
///
/// A drop-in replacement for LibAFL's
/// [`ColorizationStage`](libafl::stages::ColorizationStage) that costs **two**
/// executions per entry instead of `1 + 2 * input_len`. Both stages answer the
/// same question -- which bytes can be replaced without changing the path? --
/// but where the stock one discovers it by halving ranges and re-running,
/// SymSan already computed it exactly while tracing.
///
/// It does more than save executions, and that is the point of the whole
/// exercise: the bytes it holds still are the ones whose branches SymSan
/// *already solved*, and AFL++ RedQueen acts on an integer comparison only when
/// its operand actually moved between the original run and the colorized one.
/// So a frozen byte silently removes every integer comparison it feeds from
/// RedQueen's work list, with no change to RedQueen itself. What is left is the
/// comparisons SymSan could not crack -- which is exactly what cmplog is for.
///
/// Two things it cannot filter, both properties of RedQueen rather than of the
/// taint: the `Bytes`/RTN arm (`memcmp`, `strcmp`) splices its pattern in
/// regardless of whether the operand moved, and LibAFL's RedQueen has no `U8`
/// arm at all.
///
/// Requires [`SymSanStage`] with
/// [`cmplog_filter`](SymSanStageBuilder::cmplog_filter) on, earlier in the same
/// stage list. Without a fresh [`SymSanTaintMetadata`] it does nothing at all,
/// which is why it should be paired with a stock colorization stage gated on
/// [`symsan_needs_stock_colorization`].
#[derive(Debug, Clone)]
pub struct SymSanColorizationStage<C, O> {
    map_observer_handle: Handle<C>,
    name: Cow<'static, str>,
    /// `O` appears only in the [`Stage`] bounds -- it is the observer's own
    /// type, behind the `AsRef` the hash is taken through.
    phantom: PhantomData<O>,
}

impl<C, O> SymSanColorizationStage<C, O>
where
    C: Named,
{
    /// Create the stage, reading coverage from `map_observer` -- the same
    /// observer the stock colorization stage would be given.
    #[must_use]
    pub fn new(map_observer: &C) -> Self {
        let obs_name = map_observer.name().clone().into_owned();
        Self {
            map_observer_handle: map_observer.handle(),
            name: Cow::Owned(SYMSAN_COLORIZATION_STAGE_NAME.to_owned() + ":" + obs_name.as_str()),
            phantom: PhantomData,
        }
    }
}

impl<C, O> Named for SymSanColorizationStage<C, O> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<C, E, EM, O, S, Z> Stage<E, EM, S, Z> for SymSanColorizationStage<C, O>
where
    C: AsRef<O> + Named,
    O: Hash,
    E: HasObservers + Executor<EM, BytesInput, S, Z>,
    E::Observers: ObserversTuple<BytesInput, S>,
    EM: EventFirer<BytesInput, S>,
    S: HasCorpus<BytesInput>
        + HasCurrentCorpusId
        + HasCurrentTestcase<BytesInput>
        + HasMetadata
        + HasRand,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let Some(corpus_id) = state.current_corpus_id()? else {
            return Ok(());
        };

        // Copied out rather than borrowed: running the target below needs
        // `&mut state`, which a borrow of the testcase cannot survive. The runs
        // double as the `ranges` handed to TaintMetadata at the end -- they are
        // the same thing seen from both sides, the bytes free to move.
        let Some((ranges, taint_len, settled_count)) = state
            .current_testcase()?
            .metadata::<SymSanTaintMetadata>()
            .ok()
            .map(|m| (m.movable.clone(), m.input_len(), m.settled_count()))
        else {
            // Nothing to go on. Deliberately *not* recorded as a fallback:
            // symsan_needs_stock_colorization() already reads missing metadata
            // as "run the stock stage", and writing a marker here would only
            // make a later reader mistake it for a real answer.
            log::debug!("symsan: no taint for entry {corpus_id}; not colorizing it");
            return Ok(());
        };

        let input: BytesInput = state.current_input_cloned()?;
        if input.mutator_bytes().len() != taint_len {
            // The entry changed length since it was traced. Cheap to guard, and
            // impossible to recover from.
            log::debug!(
                "symsan: entry {corpus_id} is {} bytes but its taint covers {taint_len}; \
                 falling back to stock colorization",
                input.mutator_bytes().len(),
            );
            set_fallback(state, true);
            return Ok(());
        }

        let orig_hash = self.map_hash(fuzzer, executor, state, manager, &input)?;

        let mut bytes = input.mutator_bytes().to_vec();
        for range in &ranges {
            for byte in &mut bytes[range.clone()] {
                *byte = type_replace(*byte, state.rand_mut());
            }
        }
        let colorized = BytesInput::new(bytes);
        let colorized_hash = self.map_hash(fuzzer, executor, state, manager, &colorized)?;

        if orig_hash != colorized_hash {
            // Randomizing every unsettled byte at once took the target down a
            // different path. The taint is not wrong -- it describes the
            // *symbolic* build, and the two builds can disagree about a
            // comparison SymSan never modelled -- but it is not usable here, so
            // hand the entry to the stage that finds out the slow way.
            log::debug!(
                "symsan: colorizing entry {corpus_id} changed its coverage; \
                 falling back to stock colorization"
            );
            set_fallback(state, true);
            return Ok(());
        }

        log::debug!(
            "symsan: colorized entry {corpus_id} in 2 execs, holding {settled_count} of \
             {taint_len} bytes still across {} range(s)",
            ranges.len()
        );

        let colorized_bytes = colorized.mutator_bytes().to_vec();
        if let Some(meta) = state.metadata_map_mut().get_mut::<TaintMetadata>() {
            meta.update(colorized_bytes, ranges);
        } else {
            state.add_metadata(TaintMetadata::new(colorized_bytes, ranges));
        }
        set_fallback(state, false);
        Ok(())
    }
}

impl<C, O, S> Restartable<S> for SymSanColorizationStage<C, O>
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        // Deterministic, like the stage it replaces: if it failed once it will
        // fail again.
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<C, O> SymSanColorizationStage<C, O> {
    /// Run the target and hash the coverage map, before the hitcount observer's
    /// `post_exec` classifies it -- the same raw hash the stock colorization
    /// stage compares, so the two agree on what "the same path" means.
    fn map_hash<E, EM, S, Z>(
        &self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        input: &BytesInput,
    ) -> Result<usize, Error>
    where
        C: AsRef<O> + Named,
        O: Hash,
        E: HasObservers + Executor<EM, BytesInput, S, Z>,
        E::Observers: ObserversTuple<BytesInput, S>,
    {
        executor.observers_mut().pre_exec_all(state, input)?;
        let exit_kind = executor.run_target(fuzzer, state, manager, input)?;
        let hash = {
            let observers = executor.observers();
            generic_hash_std(observers[&self.map_observer_handle].as_ref()) as usize
        };
        executor
            .observers_mut()
            .post_exec_all(state, input, &exit_kind)?;
        Ok(hash)
    }
}

/// Record on the current testcase whether the stock colorization stage is
/// needed. Silently does nothing if the testcase carries no taint, which is
/// already read as "run the stock stage".
fn set_fallback<S>(state: &mut S, yes: bool)
where
    S: HasCurrentTestcase<BytesInput>,
{
    if let Ok(mut testcase) = state.current_testcase_mut() {
        if let Ok(meta) = testcase.metadata_mut::<SymSanTaintMetadata>() {
            meta.fallback = yes;
        }
    }
}

/// Replace a byte with a different one of the same kind: a digit stays a digit,
/// a letter a letter, whitespace whitespace.
///
/// AFL++'s `type_replace`, one byte at a time. Copied rather than called
/// because LibAFL's is private to its colorization stage, and reimplemented
/// rather than simplified because the *kind*-preserving part is what keeps a
/// text input parseable -- colorize a JSON file into random bytes and the
/// parser rejects it before reaching any of the comparisons cmplog wants to
/// see. Every arm returns a value different from its input, which is what makes
/// RedQueen notice the byte moved.
fn type_replace(byte: u8, rand: &mut impl Rand) -> u8 {
    match byte {
        // 'A' + 1 + rand('F' - 'A')
        0x41..=0x46 => 0x41 + 1 + rand.below(nonzero!(5)) as u8,
        // 'a' + 1 + rand('f' - 'a')
        0x61..=0x66 => 0x61 + 1 + rand.below(nonzero!(5)) as u8,
        // '0' -> '1'
        0x30 => 0x31,
        // '1' -> '0'
        0x31 => 0x30,
        // '2' + 1 + rand('9' - '2')
        0x32..=0x39 => 0x32 + 1 + rand.below(nonzero!(7)) as u8,
        // 'G' + 1 + rand('Z' - 'G')
        0x47..=0x5a => 0x47 + 1 + rand.below(nonzero!(19)) as u8,
        // 'g' + 1 + rand('z' - 'g')
        0x67..=0x7a => 0x67 + 1 + rand.below(nonzero!(19)) as u8,
        // '!' + 1 + rand('*' - '!')
        0x21..=0x2a => 0x21 + 1 + rand.below(nonzero!(9)) as u8,
        // ',' + 1 + rand('.' - ',')
        0x2c..=0x2e => 0x2c + 1 + rand.below(nonzero!(2)) as u8,
        // ':' + 1 + rand('@' - ':')
        0x3a..=0x40 => 0x3a + 1 + rand.below(nonzero!(6)) as u8,
        // '[' + 1 + rand('`' - '[')
        0x5b..=0x60 => 0x5b + 1 + rand.below(nonzero!(5)) as u8,
        // '{' + 1 + rand('~' - '{')
        0x7b..=0x7e => 0x7b + 1 + rand.below(nonzero!(3)) as u8,
        // '+' -> '/'
        0x2b => 0x2f,
        // '/' -> '+'
        0x2f => 0x2b,
        // ' ' -> '\t'
        0x20 => 0x9,
        // '\t' -> ' '
        0x9 => 0x20,
        // '\r' -> '\n'
        0xd => 0xa,
        // '\n' -> '\r'
        0xa => 0xd,
        0x0 => 0x1,
        0x1 | 0xff => 0x0,
        other if other < 32 => other ^ 0x1f,
        other => other ^ 0x7f,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These build no session, so they are safe to run in parallel.

    #[test]
    fn builder_requires_a_target() {
        let err = SymSanStage::builder().build().unwrap_err();
        assert!(err.to_string().contains("target"), "unexpected error: {err}");
    }

    #[test]
    fn ladder_defaults_are_the_fast_two() {
        let b = SymSanStage::builder();
        assert!(b.i2s, "i2s should default on");
        assert!(b.jigsaw, "jigsaw should default on");
        assert!(
            !b.z3,
            "z3 should default off: it is the one rung slow enough to cost a \
             fuzzing loop more than it returns"
        );
        assert!(!b.nested, "nested solving should default off");
        assert!(
            b.forkserver,
            "the fork server should default on: it is a throughput win and \
             falls back on its own when a target cannot be served that way"
        );
    }
}
