//! Which stage found each corpus entry.
//!
//! The fuzzer runs three stages that can add to the corpus -- SymSan, cmplog's
//! RedQueen, and havoc -- and until now nothing recorded which one did.  A
//! testcase carries no tag saying where it came from: every stage reaches the
//! corpus through the same `fuzzer.evaluate_*`, which has no idea who called
//! it.  The corpus is on disk (`<out>/queue`), so an entry can at least be
//! inspected afterwards, but its name is a hash of its contents and says
//! nothing about its origin either.
//!
//! [`CreditedStage`] answers the question from the outside instead of threading
//! provenance through LibAFL: it wraps a stage and measures how much the corpus
//! and the solutions grew across one `perform`.  That is deliberately coarse and
//! it is worth being clear about what it does and does not mean:
//!
//! - **It credits the whole wrapped stage, nested stages included.**  The
//!   cmplog arm is an `IfStage` over colorization, tracing and RedQueen; only
//!   RedQueen adds anything, so the credit lands where it belongs, but if a
//!   colorization stage ever started adding entries it would be counted as
//!   cmplog's.
//! - **It measures a net delta.**  Nothing here evicts from the corpus today
//!   (`IndexesLenTimeMinimizerScheduler` picks a favored set, it does not
//!   remove), so growth is the same as finds.  A stage that added two entries
//!   and removed one would be credited with one, hence the saturating
//!   subtraction rather than an assert.
//!
//! The counts go out as one `UserStats` field per stage, so they land in the
//! monitor line next to `corpus:` and `objectives:` and can be read off a
//! running campaign rather than only from a post-mortem.  Summed over the
//! stages plus the imported seeds they come to exactly `corpus:` and
//! `objectives:`, which is the check worth doing on them.
//!
//! One reading trap: a stage credits itself only once its `perform` returns,
//! but the `[Testcase]` and `[Objective]` events fire from inside
//! `fuzzer.evaluate_*`, part-way through it.  So the line announcing a find
//! still carries the count from before that find, and the next line carries it.
//! Nothing is lost, but the two disagree by one for a line at a time.
//!
//! # The provenance log
//!
//! The counts above are enough for "how much did each stage earn", and the
//! order of the `[Testcase]` events in the monitor log even recovers *which*
//! entry each stage earned.  What neither gives is the entry's **identity**:
//! the corpus file is named after a hash of its contents, its metadata records
//! `executions: 0`, and its mtime has one-second resolution -- so an entry on
//! disk cannot be matched back to a line in the log, and the edge sets in
//! `.<name>_1.metadata` stay unattributed.  That is the whole reason "which
//! stage first covered edge E" was unanswerable for a finished campaign.
//!
//! So write the join down while it is still known: one `<stage>\t<corpus |
//! solution>\t<filename>` line per find, appended to `<out>/stage_origin.log`.
//! Together with the novelties the map feedback records per entry, that makes
//! the attribution a direct read rather than a reconstruction.
//!
//! Unbuffered on purpose.  A Magma campaign ends by killing the fuzzer, so
//! anything still sitting in a `BufWriter` at the timeout would be exactly the
//! tail of the run -- the part worth having.
//!
//! Off when the corpus is in memory (`--in-memory-corpus`): entries have no
//! filename then, and there would be nothing to join to.

use core::marker::PhantomData;
use std::{
    borrow::Cow,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};

use libafl::{
    Error,
    corpus::{Corpus, CorpusId},
    events::{Event, EventFirer, EventWithStats},
    monitors::stats::{AggregatorOps, UserStats, UserStatsValue},
    stages::{Restartable, Stage},
    state::{HasCorpus, HasExecutions, HasSolutions},
};

/// Wraps a stage and reports the corpus and solution finds it is responsible
/// for. See the module docs for what "responsible for" means here.
#[derive(Debug)]
pub struct CreditedStage<I, St> {
    inner: St,
    /// The `UserStats` key, e.g. `finds_symsan`.
    key: Cow<'static, str>,
    corpus_finds: u64,
    solution_finds: u64,
    /// Whether the field has been published at least once. An enabled stage
    /// that has found nothing yet should still say so -- otherwise "no
    /// `finds_symsan` in the line" is ambiguous between "found nothing" and
    /// "not running", which is exactly the confusion this module exists to end.
    published: bool,
    /// The bare stage name, as it appears in the provenance log.
    name: &'static str,
    /// Append handle on `<out>/stage_origin.log`, or `None` when there is
    /// nothing to join to. See the module docs.
    log: Option<File>,
    phantom: PhantomData<I>,
}

impl<I, St> CreditedStage<I, St> {
    /// `name` is the stage as a human would name it: `symsan`, `cmplog`,
    /// `havoc`. `log` is the provenance log to append finds to; pass `None` to
    /// record only the counts.
    pub fn new(name: &'static str, inner: St, log: Option<&Path>) -> Self {
        // A provenance log that cannot be opened is worth a word but not a
        // failed campaign: the counts, which are what the monitor line needs,
        // do not depend on it.
        let log = log.and_then(|path| {
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => Some(f),
                Err(e) => {
                    log::warn!("cannot open the provenance log {}: {e}", path.display());
                    None
                }
            }
        });
        Self {
            inner,
            key: Cow::Owned(format!("finds_{name}")),
            corpus_finds: 0,
            solution_finds: 0,
            published: false,
            name,
            log,
            phantom: PhantomData,
        }
    }
}

/// The ids added after `after`, in insertion order. `None` means "from the
/// start", which is what an empty corpus reports before the first find.
fn ids_after<I, C: Corpus<I>>(corpus: &C, after: Option<CorpusId>) -> Vec<CorpusId> {
    let mut out = Vec::new();
    let mut cur = match after {
        Some(id) => corpus.next(id),
        None => corpus.first(),
    };
    while let Some(id) = cur {
        out.push(id);
        cur = corpus.next(id);
    }
    out
}

impl<E, EM, I, S, St, Z> Stage<E, EM, S, Z> for CreditedStage<I, St>
where
    St: Stage<E, EM, S, Z>,
    S: HasCorpus<I> + HasSolutions<I> + HasExecutions,
    EM: EventFirer<I, S>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let before_corpus = state.corpus().count();
        let before_solutions = state.solutions().count();
        // Ids, not just counts, so the new entries can be named afterwards.
        // Read even without a log: two cheap `Option<CorpusId>` reads.
        let last_corpus = state.corpus().last();
        let last_solution = state.solutions().last();

        // The inner stage's error is returned as-is, but only after the counts
        // are folded in: a stage that found something and *then* failed still
        // found it, and losing that would make the totals disagree with the
        // `corpus:` field for the rest of the campaign.
        let result = self.inner.perform(fuzzer, executor, state, manager);

        let found_corpus = state.corpus().count().saturating_sub(before_corpus) as u64;
        let found_solutions = state.solutions().count().saturating_sub(before_solutions) as u64;
        self.corpus_finds += found_corpus;
        self.solution_finds += found_solutions;

        if self.log.is_some() && (found_corpus > 0 || found_solutions > 0) {
            let mut line = String::new();
            for (kind, id) in ids_after(state.corpus(), last_corpus)
                .into_iter()
                .map(|id| ("corpus", id))
                .chain(
                    ids_after(state.solutions(), last_solution)
                        .into_iter()
                        .map(|id| ("solution", id)),
                )
            {
                // An entry with no filename is an in-memory one, which the
                // module docs already exclude -- but a mixed configuration
                // (on-disk corpus, in-memory solutions) is legal, so skip
                // rather than assume.
                let cell = if kind == "corpus" {
                    state.corpus().get(id)
                } else {
                    state.solutions().get(id)
                };
                let Ok(cell) = cell else { continue };
                let tc = cell.borrow();
                if let Some(name) = tc.filename() {
                    line.push_str(self.name);
                    line.push('\t');
                    line.push_str(kind);
                    line.push('\t');
                    line.push_str(name);
                    line.push('\n');
                }
            }
            // One write for the whole batch: the file is opened O_APPEND, so a
            // single write is a single atomic extend even if a second process
            // ever shares it.
            if let Some(f) = self.log.as_mut() {
                if let Err(e) = f.write_all(line.as_bytes()) {
                    log::warn!("cannot append to the provenance log: {e}");
                    self.log = None;
                }
            }
        }

        if found_corpus > 0 || found_solutions > 0 || !self.published {
            self.published = true;
            let value = format!(
                "{} corpus, {} crashes",
                self.corpus_finds, self.solution_finds
            );
            let executions = *state.executions();
            manager.fire(
                state,
                EventWithStats::with_current_time(
                    Event::UpdateUserStats {
                        name: self.key.clone(),
                        value: UserStats::new(
                            UserStatsValue::String(Cow::Owned(value)),
                            AggregatorOps::None,
                        ),
                        phantom: PhantomData,
                    },
                    executions,
                ),
            )?;
        }

        result
    }
}

impl<I, S, St> Restartable<S> for CreditedStage<I, St>
where
    St: Restartable<S>,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        self.inner.should_restart(state)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        self.inner.clear_progress(state)
    }
}
