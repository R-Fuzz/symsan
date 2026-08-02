#pragma once

#include "branch_map.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <utility>

namespace rgd {

struct BranchContext {
  void *addr;
  bool direction;
};

struct HybridBranchContext : public BranchContext {
  uint32_t id;
};

struct ContextAwareBranchContext : public BranchContext {
  uint32_t context;
};

struct LoopAwareBranchContext : public BranchContext {
  uint32_t loop_counter;
};

struct HistoryAwareBranchContext : public BranchContext {
  uint32_t history;
};

struct FullBranchContext : public HybridBranchContext,
                          public ContextAwareBranchContext,
                          public LoopAwareBranchContext,
                          public HistoryAwareBranchContext {
};

class CovManager {
public:
  virtual ~CovManager() {}
  virtual const std::shared_ptr<BranchContext> // don't want the saved context to be modified
    add_branch(void *addr, uint32_t id, bool direction, uint32_t context, bool is_loop_header, bool is_loop_exit) = 0;
  virtual bool
    is_branch_interesting(const std::shared_ptr<BranchContext> context) = 0;

  /// The same question is_branch_interesting() answers -- is this target still
  /// unreached? -- but without the bookkeeping.
  ///
  /// For asking again after the trace has finished, when the answer can have
  /// changed (a later branch took the other direction) but the counters must
  /// not, because they describe the branches the trace saw.  Defaulted, so an
  /// implementation that keeps no counters needs no override.
  virtual bool
    is_target_uncovered(const std::shared_ptr<BranchContext> context) {
      return is_branch_interesting(context);
    }

  /// A new input is about to be traced.  For per-trace state; anything the
  /// manager keeps for the life of the session must survive this.  Defaulted,
  /// so a manager with no per-trace state needs no override.
  virtual void new_trace() {}
};

class EdgeCovManager : public CovManager {
private:
  using BranchTargets = std::pair<bool, bool>;
  std::unordered_map<void*, BranchTargets> branches;
  std::shared_ptr<BranchContext> _ctx;

public:
  EdgeCovManager() { _ctx = std::make_shared<BranchContext>(); }

  const std::shared_ptr<BranchContext>
  add_branch(void *addr, uint32_t id, bool direction, uint32_t context, bool is_loop_header, bool is_loop_exit) override {
    auto &itr = branches[addr];
    itr.first |= direction? true : false;
    itr.second |= direction? false : true;
    _ctx->addr = addr;
    _ctx->direction = direction;
    return _ctx;
  }

  bool is_branch_interesting(const std::shared_ptr<BranchContext> context) override {
    auto itr = branches.find(context->addr);
    // assert(itr != branches.end());
    if (context->direction) {
      return itr->second.first == false;
    } else {
      return itr->second.second == false;
    }
  }

  /// Unlike is_branch_interesting(), this one can be asked about an address the
  /// manager never saw: input_taint() also asks about symbolic array indices,
  /// and on_gep() does not call add_branch().  Something we have no record of
  /// reaching is unreached.
  bool is_target_uncovered(const std::shared_ptr<BranchContext> context) override {
    auto itr = branches.find(context->addr);
    if (itr == branches.end()) return true;
    return context->direction ? itr->second.first == false
                              : itr->second.second == false;
  }
};

/// What a validation run found: does the branch map point at the edges the
/// fuzzer's build actually covers?
///
/// mapped()/unmapped() only say how *much* of the map lands, and a map that
/// resolved every branch to the wrong edge would report a perfect ratio while
/// quietly suppressing every solve.  This is the counterpart that can tell the
/// difference, because it compares against a ground truth: the edges the
/// fuzzer's own build recorded for the very same input.
struct JoinReport {
  /// distinct branch directions the trace actually took
  size_t executed = 0;
  /// of those, the ones mapping to exactly one edge id
  size_t checked = 0;
  /// of the checked ones, those whose edge the fuzzer's build did *not* record
  size_t violations = 0;
  /// directions mapping to several edge ids because the branch was inlined
  size_t ambiguous = 0;
  /// of those, the ones where *none* of the edges was recorded
  size_t ambiguous_violations = 0;
  /// directions the map had nothing to say about
  size_t unmapped = 0;
};

/// EdgeCovManager, but a branch the *fuzzer* has already covered is not
/// interesting either.
///
/// EdgeCovManager only ever knows what this process has seen, so a branch the
/// fuzzer flipped an hour ago still looks new to every freshly started session.
/// Given a BranchMap -- SymSan branch id to AFL++ edge ids, see
/// include/branch_map.h -- and a snapshot of the fuzzer's history map, we can
/// ask the question the fuzzer would answer.
///
/// Where the map has nothing to say (a branch the two builds name differently,
/// or one AFL++ pruned) this degrades exactly to EdgeCovManager.
class SharedMapCovManager : public CovManager {
private:
  using BranchTargets = std::pair<bool, bool>;
  std::unordered_map<void*, BranchTargets> branches;
  /// addr -> the id the instrumentation baked in.  A side table rather than a
  /// HybridBranchContext because ConcolicSession::on_cond builds the negated
  /// context by assigning through a BranchContext, which would slice the id
  /// straight back off.
  std::unordered_map<void*, uint32_t> cids;
  std::shared_ptr<BranchContext> _ctx;

  const BranchMap *map_;
  /// The fuzzer's history map as of the last set_coverage(); empty means "no
  /// idea", which reads as "nothing covered".
  std::vector<uint8_t> host_;
  uint64_t mapped_ = 0;
  uint64_t unmapped_ = 0;

  /// Branch directions this trace actually took, as (cid << 1) | direction.
  /// Only kept when validating -- a hot loop would otherwise push an entry per
  /// iteration.  A set rather than a list because the question is which
  /// directions were reached, not how often.
  std::unordered_set<uint64_t> taken_;
  bool validating_ = false;

  /// How many times this trace has traversed each branch address, both
  /// directions together.  Per trace, not per session: it is how far around a
  /// loop we are, which is what tells the k-th iteration of a branch apart from
  /// the first.
  std::unordered_map<void*, uint32_t> trace_hits_;

  /// AFL's hit-count buckets -- 1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+ --
  /// each collapsed onto its lower bound.  LibAFL's HitcountsMapObserver
  /// classifies the fuzzer's edge counts this way before MaxMapFeedback
  /// compares them against the history map, so these are the values host_
  /// holds and the only granularity at which asking "would the fuzzer call
  /// this new?" means anything.
  static uint8_t count_class(uint32_t hits) {
    if (hits == 0) return 0;
    if (hits == 1) return 1;
    if (hits == 2) return 2;
    if (hits == 3) return 4;
    if (hits <= 7) return 8;
    if (hits <= 15) return 16;
    if (hits <= 31) return 32;
    if (hits <= 127) return 64;
    return 128;
  }

public:
  explicit SharedMapCovManager(const BranchMap *map)
      : map_(map) { _ctx = std::make_shared<BranchContext>(); }

  /// Start (or stop) recording the directions each trace takes, for validate().
  void set_validating(bool on) { validating_ = on; if (!on) taken_.clear(); }
  /// Forget the previous trace's directions.  Call at the top of each trace.
  void clear_taken() { taken_.clear(); }

  void new_trace() override { trace_hits_.clear(); }

  /// Check the map against ground truth: @p covered is the set of edge ids the
  /// *fuzzer's* build recorded for the same input this session just traced.
  ///
  /// The invariant is one-directional.  Every direction we took must map to an
  /// edge the fuzzer also recorded, so a violation is real: either the map
  /// points at the wrong edge, or the two builds diverged on this input.  The
  /// converse says nothing -- the fuzzer records every edge it walks, and the
  /// ones whose condition did not depend on the input never reach us.
  ///
  /// A source location is not always one branch, and that costs precision: it
  /// is N edge ids both when the branch was inlined and when a macro or a
  /// && / || chain puts several distinct branches on one column.  A run takes
  /// one of them, so those can only be checked as "at least one covered" and
  /// are counted apart from the exact ones.  For the second kind even that can
  /// fail honestly -- the direction taken may belong to a sibling comparison
  /// whose block AFL++ pruned, leaving no edge to record -- so an
  /// ambiguous_violation is a weaker signal than a violation.
  void validate(const uint32_t *covered, size_t n, JoinReport *out) const {
    std::unordered_set<uint32_t> hit(covered, covered + n);
    // A count alone says a contradiction happened but not where, which is the
    // difference between a finding and a mystery.  Print the first few, capped
    // because a systematically wrong map would otherwise print thousands.
    size_t named = 0;
    for (uint64_t key : taken_) {
      out->executed += 1;
      uint32_t cid = (uint32_t)(key >> 1);
      bool dir = (key & 1) != 0;
      const std::vector<uint32_t> *edges = map_ ? map_->lookup(cid, dir) : nullptr;
      bool bad = false;
      if (!edges || edges->empty()) {
        out->unmapped += 1;
      } else if (edges->size() == 1) {
        out->checked += 1;
        bad = hit.find((*edges)[0]) == hit.end();
        if (bad) out->violations += 1;
      } else {
        out->ambiguous += 1;
        bool any = false;
        for (uint32_t e : *edges) {
          if (hit.find(e) != hit.end()) { any = true; break; }
        }
        bad = !any;
        if (bad) out->ambiguous_violations += 1;
      }
      if (bad && named < 8) {
        named += 1;
        const std::string *src = map_->source(cid, dir);
        fprintf(stderr, "[symsan] branch map contradiction: cid %u dir %d -> ",
                cid, (int)dir);
        for (uint32_t e : *edges) fprintf(stderr, "%u ", e);
        fprintf(stderr, "(none covered), at %s\n",
                src ? src->c_str() : "an unrecorded location");
      }
    }
  }

  /// Replace the coverage snapshot.  Cheap enough to do once per traced input;
  /// the map is tens of kilobytes and tracing a target costs milliseconds.
  void set_coverage(const uint8_t *map, size_t len) {
    if (map == nullptr || len == 0) host_.clear();
    else host_.assign(map, map + len);
  }

  /// How many branch directions we could and could not look up.  The ratio is
  /// the diagnostic for whether the two builds actually agree on names.
  uint64_t mapped() const { return mapped_; }
  uint64_t unmapped() const { return unmapped_; }

  const std::shared_ptr<BranchContext>
  add_branch(void *addr, uint32_t id, bool direction, uint32_t context, bool is_loop_header, bool is_loop_exit) override {
    auto &itr = branches[addr];
    itr.first |= direction? true : false;
    itr.second |= direction? false : true;
    cids[addr] = id;
    trace_hits_[addr] += 1;
    // Here rather than in is_branch_interesting(), which is handed the
    // *negated* context: this is the only place the direction actually taken
    // is in hand, and that is the one the fuzzer's map can be checked against.
    if (validating_) taken_.insert(((uint64_t)id << 1) | (direction ? 1 : 0));
    _ctx->addr = addr;
    _ctx->direction = direction;
    return _ctx;
  }

  bool is_branch_interesting(const std::shared_ptr<BranchContext> context) override {
    return uncovered(context, /*count=*/true);
  }

  bool is_target_uncovered(const std::shared_ptr<BranchContext> context) override {
    return uncovered(context, /*count=*/false);
  }

private:
  /// @p count is what separates the two entry points above: the counters are a
  /// census of the branches the trace saw, so a re-ask must not add to them.
  bool uncovered(const std::shared_ptr<BranchContext> context, bool count) {
    // Consult the fuzzer first, and unconditionally, so the counters describe
    // every branch we saw rather than only the ones that got past the local
    // check below.
    bool host_says_new = true;
    auto cid = cids.find(context->addr);
    const std::vector<uint32_t> *edges =
        (map_ && cid != cids.end())
            ? map_->lookup(cid->second, context->direction)
            : nullptr;
    if (edges) {
      if (count) mapped_ += 1;
      // "Has the fuzzer covered this edge?" is not a yes/no question to
      // MaxMapFeedback -- it compares hit-count *classes*, so the second
      // traversal of an edge is a different observation from the first.  That
      // distinction is the whole reason a loop body is solvable more than
      // once, and asking host_[e] == 0 threw it away: one hit on the flipped
      // edge, ever, and every later iteration of the loop looked covered.
      //
      // trace_hits_ is how far around the loop this branch already is, so
      // class(hits) is the class the flipped edge would land in.  It is an
      // estimate -- what the fuzzer records depends on the whole rewritten
      // trace, which we would have to run to know -- and it errs towards
      // solving, which is the right way to err for a stage that is gated to
      // once per corpus entry anyway.
      auto hit = trace_hits_.find(context->addr);
      uint8_t want = count_class(hit == trace_hits_.end() ? 1 : hit->second);
      // Inlining gives one source branch several edge ids, and so does a macro
      // or a && / || chain, which puts several *distinct* branches on one
      // column (see include/branch_map.h).  One uncovered member is still worth
      // solving for, so this is "any", not "all" -- which is also the safe way
      // round for the second case, where the members are unrelated branches:
      // it can only make us solve something already covered, never skip
      // something that is not.
      host_says_new = false;
      for (uint32_t e : *edges) {
        if (e >= host_.size() || host_[e] < want) { host_says_new = true; break; }
      }
      // The map answered, so it decides.  `branches` is keyed on address and
      // lives as long as the session, which makes it wrong in exactly the case
      // we came here to fix: it can only ever say "solved once already", and a
      // branch inside a loop is worth solving at every depth.  Letting it veto
      // is what kept test-crc32 stuck -- the fuzzer would happily have taken
      // the input, and we never built the task.
      return host_says_new;
    }

    if (count) unmapped_ += 1;
    // No edge for this branch: a name the two builds disagree on, or one AFL++
    // pruned.  Nothing better to consult than our own history, which is
    // EdgeCovManager's answer -- the documented degrade path.
    auto itr = branches.find(context->addr);
    // assert(itr != branches.end());
    // ...except when is_target_uncovered() asks: it also asks about symbolic
    // array indices, and on_gep() does not call add_branch().  Something we
    // have no record of reaching is unreached.
    if (itr == branches.end()) return true;
    return context->direction ? itr->second.first == false
                              : itr->second.second == false;
  }
};

}; // namespace rgd