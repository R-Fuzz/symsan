#pragma once

#include "task.h"

#include <deque>
#include <map>
#include <memory>
#include <stdint.h>

namespace rgd {

class TaskManager {
public:
  virtual ~TaskManager() {}
  /// Queue @p task, which exists to reach @p ctx -- the *negated* branch
  /// context, the direction the trace did not take.  @return false if the task
  /// was not queued, which today means a bounded manager refused it.
  virtual bool add_task(std::shared_ptr<BranchContext> ctx, std::shared_ptr<SearchTask> task) = 0;
  virtual std::shared_ptr<SearchTask> get_next_task() = 0;
  virtual size_t get_num_tasks() = 0;

  /// Tasks this manager refused or threw away to stay inside its bound.
  ///
  /// On the base and not virtual: a bound is the one thing every manager may
  /// have and counts the same way, and an unbounded one leaves it at zero.  It
  /// is the number that says whether the bound is costing anything -- a queue
  /// that never evicts is a queue whose capacity is not the constraint.
  uint64_t evicted() const { return evicted_; }

  /// How the tasks offered to this manager scored, indexed by TargetNovelty,
  /// or null from a manager that does not score.
  ///
  /// The diagnostic the ranking cannot be read without: if every task scores
  /// the same, a priority queue *is* a FIFO, and an A/B that measures no
  /// difference has measured nothing rather than measured a tie.  Counted over
  /// tasks offered, not tasks kept -- it describes the population the order is
  /// chosen from.
  virtual const uint64_t *novelty_histogram() const { return nullptr; }

protected:
  uint64_t evicted_ = 0;
};

class FIFOTaskManager : public TaskManager {
public:
  /// @p capacity is the most tasks the queue will hold; 0 means unbounded,
  /// which is what it always was.
  explicit FIFOTaskManager(size_t capacity = 0) : capacity_(capacity) {}

  bool add_task(std::shared_ptr<BranchContext> ctx, std::shared_ptr<SearchTask> task) override {
    (void)ctx;
    // Drop the newcomer, not the head.  The head is the next task out, so a
    // bound that discarded it would make the queue lose precisely the work it
    // was about to do, and the drain order would no longer be FIFO at all.
    // PriorityTaskManager drops the newcomer under the same rule when it ties
    // with the worst it holds, which is what makes a constant score there
    // behave exactly like this and the A/B a comparison of one variable.
    if (capacity_ && tasks.size() >= capacity_) {
      evicted_ += 1;
      return false;
    }
    tasks.push_back(std::move(task));
    return true;
  }

  std::shared_ptr<SearchTask> get_next_task() override {
    if (tasks.empty()) return nullptr;
    auto task = std::move(tasks.front());
    tasks.pop_front();
    return task;
  }

  size_t get_num_tasks() override {
    return tasks.size();
  }

private:
  std::deque<task_t> tasks;
  size_t capacity_;
};

/// One global queue, drained best-first, bounded by throwing away the worst.
///
/// FIFO is the right order only while the queue is drained to exhaustion inside
/// the trace that filled it: then every task is solved and the order is just
/// latency.  Under a budget -- a fuzzer that gives the stage a slice and moves
/// on -- the order decides *which* tasks are solved at all, and a queue that
/// spans traces makes that a global choice rather than a per-trace one.
///
/// The score is the destination's novelty (enum TargetNovelty) at the moment
/// the task is queued, read from the same coverage manager everything else
/// asks.  Deliberately not re-read on the way out: next_pending_task() already
/// re-asks the current question of every task it pops, so a stale score can
/// only misorder, never mis-solve, and rescoring a whole queue per pop is a
/// cost with no matching benefit at this step.
///
/// Ties break oldest-first, so a queue whose scores are all equal drains in
/// exactly FIFO order and evicts exactly what a bounded FIFO would.  That is
/// what makes the A/B against FIFOTaskManager a one-variable comparison.
class PriorityTaskManager : public TaskManager {
public:
  /// @p cov is borrowed and must outlive this manager -- ConcolicSession owns
  /// both, and constructs the coverage manager first.  Null is tolerated and
  /// scores everything the same, which degrades to a bounded FIFO.
  /// @p capacity is the most tasks the queue will hold; 0 means unbounded.
  PriorityTaskManager(CovManager *cov, size_t capacity)
      : cov_(cov), capacity_(capacity) {}

  bool add_task(std::shared_ptr<BranchContext> ctx, std::shared_ptr<SearchTask> task) override {
    // No context is not the same as a worthless target: it means nobody said.
    // Score it as new, for the same reason is_target_uncovered() answers true
    // about a branch it has no record of -- the optimistic answer is the one
    // that cannot silently drop solvable work.
    int score = (cov_ && ctx) ? cov_->target_novelty(ctx) : kTargetNewEdge;
    if (score >= 0 && score < kTargetNoveltyCount) graded_[score] += 1;
    Key key{score, seq_++};

    if (capacity_ && tasks_.size() >= capacity_) {
      // The worst the queue holds.  `key` carries the newest seq, so on a tie
      // in score it is itself the worst and `!(key < worst)` refuses it.
      auto worst = std::prev(tasks_.end());
      evicted_ += 1;
      if (!(key < worst->first)) return false;
      tasks_.erase(worst);
    }

    tasks_.emplace(key, std::move(task));
    return true;
  }

  std::shared_ptr<SearchTask> get_next_task() override {
    if (tasks_.empty()) return nullptr;
    auto best = tasks_.begin();
    auto task = std::move(best->second);
    tasks_.erase(best);
    return task;
  }

  size_t get_num_tasks() override {
    return tasks_.size();
  }

  const uint64_t *novelty_histogram() const override { return graded_; }

private:
  /// Best first, then oldest first, so begin() is the task to solve and the
  /// last element is the one to throw away.  A single ordering serving both
  /// ends is the point: the queue can never evict something it would have
  /// popped before the thing it kept.
  struct Key {
    int score;
    uint64_t seq;
    bool operator<(const Key &o) const {
      if (score != o.score) return score > o.score;
      return seq < o.seq;
    }
  };

  CovManager *cov_;
  size_t capacity_;
  /// Monotonic, never reset: it is the tiebreak across the whole session, and
  /// restarting it per trace would make an old task look newer than a fresh one.
  uint64_t seq_ = 0;
  std::map<Key, task_t> tasks_;
  /// Every task ever offered, by the score it got.  See novelty_histogram().
  uint64_t graded_[kTargetNoveltyCount] = {0};
};

};  // namespace rgd
