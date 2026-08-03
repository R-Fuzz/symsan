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

use core::marker::PhantomData;
use std::borrow::Cow;

use libafl::{
    Error,
    corpus::Corpus,
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
    phantom: PhantomData<I>,
}

impl<I, St> CreditedStage<I, St> {
    /// `name` is the stage as a human would name it: `symsan`, `cmplog`,
    /// `havoc`.
    pub fn new(name: &'static str, inner: St) -> Self {
        Self {
            inner,
            key: Cow::Owned(format!("finds_{name}")),
            corpus_finds: 0,
            solution_finds: 0,
            published: false,
            phantom: PhantomData,
        }
    }
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

        // The inner stage's error is returned as-is, but only after the counts
        // are folded in: a stage that found something and *then* failed still
        // found it, and losing that would make the totals disagree with the
        // `corpus:` field for the rest of the campaign.
        let result = self.inner.perform(fuzzer, executor, state, manager);

        let found_corpus = state.corpus().count().saturating_sub(before_corpus) as u64;
        let found_solutions = state.solutions().count().saturating_sub(before_solutions) as u64;
        self.corpus_finds += found_corpus;
        self.solution_finds += found_solutions;

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
