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
use std::path::{Path, PathBuf};

use libafl::{
    Error, HasMetadata, HasNamedMetadata,
    corpus::{CorpusId, HasCurrentCorpusId},
    feedbacks::{MapFeedbackMetadata, MapIndexesMetadata},
    fuzzer::{Evaluator, ExecuteInputResult},
    inputs::BytesInput,
    stages::{Restartable, RetryCountRestartHelper, Stage},
    state::{HasCorpus, HasCurrentTestcase},
};
use libafl_bolts::Named;

pub use symsan::{Config, JoinReport, Session, Stats};

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
    jigsaw: bool,
    z3: bool,
    nested: bool,
    trace_bounds: bool,
    solve_ub: bool,
    debug: bool,
    timeout_ms: Option<u32>,
    max_solutions_per_input: usize,
    forkserver: bool,
}

impl SymSanStageBuilder {
    fn new() -> Self {
        Self {
            // Sensible defaults for fuzzing: the full ladder. i2s alone is fast
            // but only cracks direct input-to-state comparisons; jigsaw is what
            // makes the RGD stack worth running.
            jigsaw: true,
            z3: true,
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
    /// `path` is what a patched AFL++ writes when `AFL_LLVM_DOCUMENT_IDS` is
    /// set while building the *coverage* copy of the target (see
    /// `patches/aflpp-document-ids.patch` in the SymSan tree). It maps each
    /// source-level branch direction onto the AFL++ edge ids that represent it,
    /// which is what lets the stage look a branch up in the fuzzer's history
    /// map and skip solving for one the fuzzer already reached.
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

    /// Include the JIT/gradient-descent solver. On by default.
    #[must_use]
    pub fn jigsaw(mut self, yes: bool) -> Self {
        self.jigsaw = yes;
        self
    }

    /// Include Z3 as the last resort. On by default.
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
            .jigsaw(self.jigsaw)
            .z3(self.z3)
            .nested_solving(self.nested)
            .trace_bounds(self.trace_bounds)
            .solve_ub(self.solve_ub)
            .debug(self.debug)
            .forkserver(self.forkserver);
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
    // `S` anyway, so it costs a stage nothing.
    S: HasCorpus<BytesInput>
        + HasCurrentCorpusId
        + HasCurrentTestcase<BytesInput>
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
                    self.join.ambiguous += r.ambiguous;
                    self.join.ambiguous_violations += r.ambiguous_violations;
                    self.join.unmapped += r.unmapped;
                    if r.is_consistent() {
                        log::debug!(
                            "symsan: entry {corpus_id} join ok: {}/{} directions checked \
                             against {} fuzzer edges, {} unmapped, {} ambiguous",
                            r.checked,
                            r.executed,
                            covered.len(),
                            r.unmapped,
                            r.ambiguous
                        );
                    } else {
                        // Loud, because this is not a missed opportunity: the
                        // map is pointing at edges the fuzzer never took, so
                        // every branch it resolves is being judged against
                        // somebody else's coverage.
                        log::error!(
                            "symsan: entry {corpus_id} contradicts the branch map: \
                             {} of {} checked directions map to an edge the fuzzer's \
                             build did not record ({} of {} ambiguous ones too). \
                             The two builds disagree about branch identity, or they \
                             took different paths on the same input.",
                            r.violations,
                            r.checked,
                            r.ambiguous_violations,
                            r.ambiguous
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

        if tasks == 0 {
            return Ok(());
        }
        log::debug!("symsan: corpus entry {corpus_id} produced {tasks} tasks");

        let mut produced = 0usize;
        while let Some(solution) = self.session.next_solution() {
            self.solutions += 1;
            produced += 1;

            // Hand the solved input to the fuzzer exactly as a mutational stage
            // would: it runs it on the *coverage-instrumented* build, applies
            // the feedbacks, and adds it to the corpus if it is interesting.
            // `evaluate_filtered` honours the fuzzer's input filter, so an
            // input we have already seen is not re-run.
            let (result, _) =
                fuzzer.evaluate_filtered(state, executor, manager, &BytesInput::new(solution))?;

            let interesting = result != ExecuteInputResult::None;
            if interesting {
                self.solved += 1;
            }
            // The honest answer. `false` makes the session escalate this task
            // to the next solver in the ladder; `true` retires it.
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
    fn ladder_defaults_are_on() {
        let b = SymSanStage::builder();
        assert!(b.jigsaw, "jigsaw should default on");
        assert!(b.z3, "z3 should default on");
        assert!(!b.nested, "nested solving should default off");
        assert!(
            b.forkserver,
            "the fork server should default on: it is a throughput win and \
             falls back on its own when a target cannot be served that way"
        );
    }
}
