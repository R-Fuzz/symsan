/*
  driver/queuetest.cpp -- unit tests for the search-task queue and for the
  novelty grade it orders by.

  Two things are pinned here, and neither can be pinned from a real trace.

  The *ordering* cannot, because a task is only ever built for a destination
  is_branch_interesting() already said yes about: every task a trace produces
  scores the same, so a queue that ignored the score entirely would pass any
  end-to-end test.  The scores have to be scripted for the order to mean
  anything, which is what ScriptedCovManager is for.

  The *grade* cannot, because the three levels come from the fuzzer's hit-count
  classes and reproducing all three from a target would mean arranging a
  particular history map, a particular loop depth and a particular branch map --
  three moving parts to observe one function.  Here the map is four lines and
  the history is a byte array, so each grade is one assignment.

  No launcher, no instrumented target, no solver: the whole file runs in
  milliseconds.

  (c) 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#include "cov.h"
#include "task_mgr.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

using namespace rgd;

namespace {

uint64_t g_checks = 0;
uint64_t g_failures = 0;

void check(bool ok, const std::string &what) {
  g_checks += 1;
  if (ok) return;
  g_failures += 1;
  printf("QUEUE-FAIL %s\n", what.c_str());
}

std::string join(const std::vector<int> &v) {
  std::string s;
  for (size_t i = 0; i < v.size(); ++i) {
    if (i) s += ",";
    s += std::to_string(v[i]);
  }
  return s;
}

void check_order(const std::vector<int> &got, const std::vector<int> &want,
                 const std::string &what) {
  g_checks += 1;
  if (got == want) return;
  g_failures += 1;
  printf("QUEUE-FAIL %s: got [%s], want [%s]\n", what.c_str(),
         join(got).c_str(), join(want).c_str());
}

/// A CovManager that answers from a table instead of from a trace.
///
/// Only target_novelty() is real; nothing here traces, so add_branch() is never
/// called and is_branch_interesting() would only ever be asked by code that
/// does.  The score is keyed on the context's cid, which the fixture below sets
/// to the task's index.
class ScriptedCovManager : public CovManager {
public:
  const std::shared_ptr<BranchContext>
  add_branch(void *, uint32_t, bool, uint32_t, bool, bool) override {
    return nullptr;
  }
  bool is_branch_interesting(const std::shared_ptr<BranchContext>) override {
    return true;
  }
  int target_novelty(const std::shared_ptr<BranchContext> ctx) override {
    auto itr = scores.find(ctx->id);
    return itr == scores.end() ? kTargetCovered : itr->second;
  }

  std::unordered_map<uint32_t, int> scores;
};

/// One queue, one task per score, drained to exhaustion.
///
/// Tasks are identified by index rather than by anything on the task, because
/// what is being tested is which object comes back and in what order -- an
/// identity question, so pointer identity is the honest way to ask it.
struct Fixture {
  ScriptedCovManager cov;
  std::vector<task_t> tasks;
  std::vector<std::shared_ptr<TaskTarget>> ctxs;
  std::unique_ptr<TaskManager> mgr;
  /// get_num_tasks() after every add, so a bound can be checked as it is
  /// enforced rather than only at the end.
  std::vector<size_t> sizes;

  Fixture(bool priority, size_t capacity) {
    if (priority) {
      mgr.reset(new PriorityTaskManager(&cov, capacity));
    } else {
      mgr.reset(new FIFOTaskManager(capacity));
    }
  }

  /// Queue one task whose destination scores @p score.  @return what add_task()
  /// said.
  bool add(int score) {
    uint32_t id = (uint32_t)tasks.size();
    auto ctx = std::make_shared<TaskTarget>();
    ctx->addr = nullptr;
    ctx->direction = true;
    ctx->id = id;
    ctx->context = 0;
    ctx->flipped = false;
    cov.scores[id] = score;
    ctxs.push_back(ctx);
    tasks.push_back(std::make_shared<SearchTask>());
    bool ok = mgr->add_task(ctx, tasks.back());
    sizes.push_back(mgr->get_num_tasks());
    return ok;
  }

  /// Queue a task nobody gave a context for -- what a producer outside this
  /// tree may do.
  bool add_no_context() {
    ctxs.push_back(nullptr);
    tasks.push_back(std::make_shared<SearchTask>());
    bool ok = mgr->add_task(nullptr, tasks.back());
    sizes.push_back(mgr->get_num_tasks());
    return ok;
  }

  /// Drain, as indices into the order things were added.  -1 for a task this
  /// fixture never queued, which cannot happen and would be a real defect.
  std::vector<int> drain() {
    std::vector<int> order;
    while (auto t = mgr->get_next_task()) {
      int which = -1;
      for (size_t i = 0; i < tasks.size(); ++i) {
        if (tasks[i] == t) {
          which = (int)i;
          break;
        }
      }
      order.push_back(which);
    }
    return order;
  }
};

std::vector<int> run(bool priority, size_t capacity,
                     const std::vector<int> &scores, uint64_t *evicted) {
  Fixture f(priority, capacity);
  for (int s : scores) f.add(s);
  auto order = f.drain();
  if (evicted) *evicted = f.mgr->evicted();
  return order;
}

// --- the queue ------------------------------------------------------------

void test_fifo_ignores_the_score() {
  uint64_t evicted = 0;
  auto order = run(/*priority=*/false, /*capacity=*/0, {2, 0, 1}, &evicted);
  check_order(order, {0, 1, 2}, "unbounded FIFO drains in arrival order");
  check(evicted == 0, "an unbounded queue evicts nothing");
}

void test_priority_drains_best_first() {
  uint64_t evicted = 0;
  auto order = run(/*priority=*/true, /*capacity=*/0, {1, 2, 0, 2, 1}, &evicted);
  // scores 2 first (indices 1, 3 -- oldest of the two first), then the 1s
  // (0, 4), then the 0 (2).
  check_order(order, {1, 3, 0, 4, 2},
              "priority drains best-first, oldest-first within a score");
  check(evicted == 0, "an unbounded priority queue evicts nothing");
}

void test_the_histogram_counts_what_was_offered() {
  // The number the A/B is read against: it says whether the queue had anything
  // to rank at all.  Over tasks *offered*, so a bound cannot make a run look
  // like it saw only the work it kept.
  Fixture f(/*priority=*/true, /*capacity=*/2);
  for (int s : {2, 0, 1, 0, 2}) f.add(s);
  const uint64_t *h = f.mgr->novelty_histogram();
  check(h != nullptr, "the priority queue reports a histogram");
  if (h) {
    check(h[kTargetNewEdge] == 2 && h[kTargetNewClass] == 1 &&
              h[kTargetCovered] == 2,
          "the histogram counts every task offered, not the three kept");
  }

  Fixture g(/*priority=*/false, /*capacity=*/0);
  g.add(2);
  check(g.mgr->novelty_histogram() == nullptr,
        "a FIFO reports no histogram rather than a histogram of zeroes");
}

void test_priority_with_equal_scores_is_fifo() {
  // The property the A/B rests on: with nothing to tell tasks apart the two
  // managers must be the same queue, or a difference in a campaign could be the
  // tiebreak rather than the ranking.
  uint64_t evicted = 0;
  auto order = run(/*priority=*/true, /*capacity=*/0, {1, 1, 1, 1}, &evicted);
  check_order(order, {0, 1, 2, 3}, "priority with equal scores is FIFO");

  uint64_t pevicted = 0, fevicted = 0;
  auto p = run(/*priority=*/true, /*capacity=*/2, {1, 1, 1, 1}, &pevicted);
  auto q = run(/*priority=*/false, /*capacity=*/2, {1, 1, 1, 1}, &fevicted);
  check_order(p, q, "bounded priority with equal scores is bounded FIFO");
  check(pevicted == fevicted && pevicted == 2,
        "both bounded managers refuse the same two tasks");
}

void test_bound_evicts_the_worst() {
  uint64_t evicted = 0;
  // The third task outranks the second, so it takes its place.
  auto order = run(/*priority=*/true, /*capacity=*/2, {2, 0, 1}, &evicted);
  check_order(order, {0, 2}, "a better task displaces the worst one held");
  check(evicted == 1, "displacing counts as one eviction");

  // ...and does not displace anything when it is the worst.
  evicted = 0;
  order = run(/*priority=*/true, /*capacity=*/2, {2, 2, 0}, &evicted);
  check_order(order, {0, 1}, "a worse task is refused, not swapped in");
  check(evicted == 1, "a refusal counts as one eviction");

  // A tie is a refusal, not a swap: the newcomer is the newest, so within a
  // score band it *is* the worst, and swapping would turn the band LIFO.
  evicted = 0;
  order = run(/*priority=*/true, /*capacity=*/2, {1, 1, 1}, &evicted);
  check_order(order, {0, 1}, "a newcomer tying the worst is refused");
  check(evicted == 1, "the tie counts as one eviction");
}

void test_fifo_bound_drops_the_newcomer() {
  uint64_t evicted = 0;
  auto order = run(/*priority=*/false, /*capacity=*/2, {2, 0, 1}, &evicted);
  check_order(order, {0, 1},
              "a bounded FIFO drops the newcomer, not the head");
  check(evicted == 1, "one task refused");
}

void test_bound_is_never_exceeded() {
  const size_t kCap = 8;
  Fixture f(/*priority=*/true, kCap);
  // Deterministic but not monotonic, so the queue is asked to displace and to
  // refuse repeatedly rather than filling once and staying full.
  for (int i = 0; i < 100; ++i) f.add((i * 7) % 3);

  bool within = true;
  for (size_t s : f.sizes) within = within && s <= kCap;
  check(within, "the queue never exceeds its capacity");

  auto order = f.drain();
  check(order.size() == kCap, "a full queue holds exactly its capacity");

  // Whatever survived must come out best-first.  Checked as a property rather
  // than an expected list, because the point is the invariant and not this
  // particular arithmetic sequence.
  bool sorted = true;
  for (size_t i = 1; i < order.size(); ++i) {
    int prev = f.cov.scores[(uint32_t)order[i - 1]];
    int cur = f.cov.scores[(uint32_t)order[i]];
    if (cur > prev) sorted = false;
    if (cur == prev && order[i] < order[i - 1]) sorted = false;
  }
  check(sorted, "the drain order is non-increasing in score, oldest-first");

  check(f.mgr->evicted() == 100 - kCap,
        "every task not held was counted as evicted");
}

void test_no_context_is_not_worthless() {
  // Nobody said is not the same as nothing there.  A task with no context must
  // outrank a covered one, the same way is_target_uncovered() answers true
  // about a branch it has no record of.
  Fixture f(/*priority=*/true, /*capacity=*/1);
  f.add(kTargetCovered);
  bool ok = f.add_no_context();
  check(ok, "a task with no context displaces a covered one");
  auto order = f.drain();
  check_order(order, {1}, "the contextless task is the one kept");
}

// --- the grade ------------------------------------------------------------

void test_edge_cov_manager_grades() {
  EdgeCovManager cov;
  auto ctx = std::make_shared<BranchContext>();
  ctx->addr = (void *)0x1000;
  ctx->id = 7;

  // Never seen: the default target_novelty() reads is_target_uncovered().
  ctx->direction = true;
  check(cov.target_novelty(ctx) == kTargetNewEdge,
        "EdgeCovManager: an unseen direction is a new edge");

  cov.add_branch((void *)0x1000, 7, /*direction=*/true, 0, false, false);
  check(cov.target_novelty(ctx) == kTargetCovered,
        "EdgeCovManager: a direction taken is covered");
  ctx->direction = false;
  check(cov.target_novelty(ctx) == kTargetNewEdge,
        "EdgeCovManager: the other direction is still new");
  // The two must not be able to disagree; every caller of one may call the
  // other about the same context.
  check(cov.is_target_uncovered(ctx) ==
            (cov.target_novelty(ctx) != kTargetCovered),
        "EdgeCovManager: the grade agrees with the bool");
}

/// The three grades, one history map at a time.
///
/// cid 4096 is a conditional branch whose true side reaches edge 100.  The
/// history map is ours to set, and trace_hits_ is driven by calling add_branch
/// the way a trace would -- which is the only way to reach kTargetNewClass,
/// since it is precisely "this loop has been round once already".
void test_shared_map_grades(const std::string &map_path) {
  FILE *fp = fopen(map_path.c_str(), "w");
  if (!fp) {
    printf("QUEUE-FAIL cannot write the branch map to %s: %s\n",
           map_path.c_str(), strerror(errno));
    g_failures += 1;
    return;
  }
  fprintf(fp, "# symsan branch map v1 base=4096 edges=65536\n");
  fprintf(fp, "C 4096 100 101\n");
  fclose(fp);

  BranchMap map;
  int n = map.load(map_path);
  check(n == 2, "the test branch map parsed to two directions");

  std::vector<uint8_t> history(65536, 0);

  auto ctx = std::make_shared<BranchContext>();
  ctx->addr = (void *)0x2000;
  ctx->id = 4096;
  ctx->direction = true;

  {
    SharedMapCovManager cov(&map);
    cov.set_coverage(history.data(), history.size());
    check(cov.target_novelty(ctx) == kTargetNewEdge,
          "SharedMap: an edge the fuzzer never walked is a new edge");
  }

  {
    // One hit on edge 100, and this trace has not taken the true side, so one
    // more traversal would land in class(1) = 1 -- which the history already
    // has.
    history[100] = 1;
    SharedMapCovManager cov(&map);
    cov.set_coverage(history.data(), history.size());
    check(cov.target_novelty(ctx) == kTargetCovered,
          "SharedMap: a class the history already holds is covered");
    check(!cov.is_target_uncovered(ctx),
          "SharedMap: the grade agrees with the bool when covered");
  }

  {
    // Same history, but this trace has already taken the true side once, so the
    // solution would be its second traversal -- class(2) = 2, which the history
    // does not have.  New to MaxMapFeedback, on an edge it has walked: the
    // middle grade, and the one a covered-bit test cannot see.
    SharedMapCovManager cov(&map);
    cov.set_coverage(history.data(), history.size());
    cov.new_trace();
    cov.add_branch((void *)0x2000, 4096, /*direction=*/true, 0, false, false);
    check(cov.target_novelty(ctx) == kTargetNewClass,
          "SharedMap: one more traversal into a new class is a new class");
    check(cov.is_target_uncovered(ctx),
          "SharedMap: the grade agrees with the bool when new");
  }

  {
    // A direction the map has nothing to say about degrades to what this
    // session has seen, which is a bit and so has only two grades.
    auto other = std::make_shared<BranchContext>();
    other->addr = (void *)0x3000;
    other->id = 9999;
    other->direction = true;
    SharedMapCovManager cov(&map);
    cov.set_coverage(history.data(), history.size());
    check(cov.target_novelty(other) == kTargetNewEdge,
          "SharedMap: an unmapped branch nobody reached is a new edge");
    cov.add_branch((void *)0x3000, 9999, /*direction=*/true, 0, false, false);
    check(cov.target_novelty(other) == kTargetCovered,
          "SharedMap: an unmapped direction this session took is covered");
  }
}

void usage(const char *argv0) {
  fprintf(stderr,
          "usage: %s --map <path>\n"
          "  --map <path>  scratch file for the synthetic branch map; it is\n"
          "                written, not read, and may be overwritten\n",
          argv0);
}

} // namespace

int main(int argc, char **argv) {
  std::string map_path;
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--map") && i + 1 < argc) {
      map_path = argv[++i];
    } else {
      usage(argv[0]);
      return 2;
    }
  }
  // Required rather than defaulted, so the grade half can never be silently
  // skipped -- a run that tested only the queue would still print PASS.
  if (map_path.empty()) {
    usage(argv[0]);
    return 2;
  }

  test_fifo_ignores_the_score();
  test_priority_drains_best_first();
  test_the_histogram_counts_what_was_offered();
  test_priority_with_equal_scores_is_fifo();
  test_bound_evicts_the_worst();
  test_fifo_bound_drops_the_newcomer();
  test_bound_is_never_exceeded();
  test_no_context_is_not_worthless();
  test_edge_cov_manager_grades();
  test_shared_map_grades(map_path);

  printf("QUEUE-SUMMARY checks=%" PRIu64 " failures=%" PRIu64 "\n", g_checks,
         g_failures);
  if (g_failures) {
    printf("QUEUE-RESULT FAIL\n");
    return 1;
  }
  printf("QUEUE-RESULT PASS\n");
  return 0;
}
