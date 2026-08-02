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
  /// The id the instrumentation baked into the branch.  In an AFL++-numbered
  /// build this is an edge id and the branch map can be asked about it; in a
  /// per-TU build it is a source hash, and in a check the runtime raised itself
  /// it is one of `enum undefined_check_ids`, shared by every such site.
  ///
  /// Carried here rather than in a derived struct so that it survives
  /// ConcolicSession::on_cond building the negated context by assigning through
  /// a BranchContext, which would slice a derived member straight back off.
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

struct FullBranchContext : public ContextAwareBranchContext,
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
    _ctx->id = id;
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
  /// of those, the ones naming an edge id
  size_t checked = 0;
  /// of the checked ones, those whose edge the fuzzer's build did *not* record
  size_t violations = 0;
  /// directions the map answered for with "AFL++ numbered no block here"
  size_t pruned = 0;
  /// directions the map had nothing to say about
  size_t unmapped = 0;
};

/// EdgeCovManager, but a branch the *fuzzer* has already covered is not
/// interesting either.
///
/// EdgeCovManager only ever knows what this process has seen, so a branch the
/// fuzzer flipped an hour ago still looks new to every freshly started session.
/// Given a BranchMap -- what each side of a branch reaches, in the fuzzer's own
/// edge numbering, see include/branch_map.h -- we can put the question to the
/// fuzzer's own history (set_coverage) instead, about the edge that direction
/// leads to.
///
/// Where the map has nothing to say -- a branch out of code AFL++ never
/// instrumented, the false side of a switch case, or a direction AFL++ pruned
/// and so gave no edge id -- this degrades exactly to EdgeCovManager.
class SharedMapCovManager : public CovManager {
private:
  /// Which directions of each branch address this session has taken.  Only the
  /// unmapped path below consults it, and it stays keyed on the address rather
  /// than the cid because the ids that land there are not unique: a check the
  /// runtime raised itself carries one of `enum undefined_check_ids`, the same
  /// sixteen values for every site in the program, and keying on those would
  /// collapse every UB check in the target into one bucket.
  using BranchTargets = std::pair<bool, bool>;
  std::unordered_map<void*, BranchTargets> branches;
  std::shared_ptr<BranchContext> _ctx;

  const BranchMap *map_;
  /// The fuzzer's history map as of the last set_coverage(); empty means "no
  /// idea", which reads as "nothing covered".  Already hit-count classed --
  /// that is what LibAFL's HitcountsMapObserver hands MaxMapFeedback.
  std::vector<uint8_t> host_;
  /// How many times this trace has taken each branch, keyed on the cid.  Keying
  /// on the cid is safe here where it is not for `branches` above, because only
  /// the mapped path reads it and a cid the map answers for is an AFL++ edge
  /// id, unique to its branch.
  ///
  /// This is what the target's own AFL++ counters cannot supply, for all that
  /// they are real counts over every edge rather than only the tainted ones.
  /// The question is how far along *this traversal* is, and a counter map has
  /// no ordering: we drain the event pipe of a process that is still running,
  /// and by the time the first iteration's event is read the target has usually
  /// finished the loop, so the map reads the same -- final -- number at every
  /// iteration.  Measured: it collapses the graduated classes below to one
  /// value and makes every iteration look equally new.
  std::unordered_map<uint32_t, uint32_t> trace_hits_;
  uint64_t mapped_ = 0;
  uint64_t unmapped_ = 0;

  /// Branch directions this trace actually took, as (cid << 1) | direction.
  /// Only kept when validating -- a hot loop would otherwise push an entry per
  /// iteration.  A set rather than a list because the question is which
  /// directions were reached, not how often.
  std::unordered_set<uint64_t> taken_;
  bool validating_ = false;

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

  /// The class the fuzzer's history has for @p edge.  Already classed on the
  /// way in; past the end is not covered, because a snapshot shorter than the
  /// binary's id range says nothing about the ids it does not reach and
  /// "unknown" has to read as "worth solving".
  uint8_t host_at(uint32_t edge) const {
    return edge < host_.size() ? host_[edge] : 0;
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
  /// A direction the map answers for with kPruned has no edge to check against
  /// anything -- AFL++ numbered no block behind it -- so it is counted apart
  /// rather than treated as either a pass or a failure.
  void validate(const uint32_t *covered, size_t n, JoinReport *out) const {
    std::unordered_set<uint32_t> hit(covered, covered + n);
    // A count alone says a contradiction happened but not where, which is the
    // difference between a finding and a mystery.  Print the first few, capped
    // because a systematically wrong map would otherwise print thousands.
    //
    // Both numbers name the branch as precisely as anything can: the cid is
    // itself one of the edge ids around it, so AFL++'s own
    // AFL_LLVM_DOCUMENT_IDS listing for the same build turns either of them
    // back into a source location.
    size_t named = 0;
    for (uint64_t key : taken_) {
      out->executed += 1;
      uint32_t cid = (uint32_t)(key >> 1);
      bool dir = (key & 1) != 0;
      const uint32_t *edge = map_ ? map_->lookup(cid, dir) : nullptr;
      if (!edge) {
        out->unmapped += 1;
        continue;
      }
      if (*edge == BranchMap::kPruned) {
        out->pruned += 1;
        continue;
      }
      out->checked += 1;
      if (hit.find(*edge) != hit.end()) continue;
      out->violations += 1;
      if (named < 8) {
        named += 1;
        fprintf(stderr,
                "[symsan] branch map contradiction: cid %u dir %d -> edge %u, "
                "which the fuzzer's build did not record\n",
                cid, (int)dir, *edge);
      }
    }
  }

  /// Replace the coverage snapshot.  Cheap enough to do once per traced input;
  /// the map is tens of kilobytes and tracing a target costs milliseconds.
  void set_coverage(const uint8_t *map, size_t len) {
    if (map == nullptr || len == 0) host_.clear();
    else host_.assign(map, map + len);
  }

  /// How many branch directions we could and could not get an edge for.  The
  /// ratio is the diagnostic for whether the map covers the code being traced.
  /// A pruned direction counts as unmapped here -- the entry exists, but not an
  /// edge to consult the fuzzer's history about.  validate() keeps the two
  /// apart, because there the distinction is what it can and cannot check.
  uint64_t mapped() const { return mapped_; }
  uint64_t unmapped() const { return unmapped_; }

  const std::shared_ptr<BranchContext>
  add_branch(void *addr, uint32_t id, bool direction, uint32_t context, bool is_loop_header, bool is_loop_exit) override {
    auto &itr = branches[addr];
    itr.first |= direction? true : false;
    itr.second |= direction? false : true;
    trace_hits_[id] += 1;
    // Here rather than in is_branch_interesting(), which is handed the
    // *negated* context: this is the only place the direction actually taken
    // is in hand, and that is the one the fuzzer's map can be checked against.
    if (validating_) taken_.insert(((uint64_t)id << 1) | (direction ? 1 : 0));
    _ctx->addr = addr;
    _ctx->direction = direction;
    _ctx->id = id;
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
    const uint32_t *edge =
        map_ ? map_->lookup(context->id, context->direction) : nullptr;
    // AFL++ numbered no block behind this direction, so there is no edge to ask
    // the fuzzer's history about.  For validate() that is a real answer --
    // nothing to contradict -- but here it must *not* be read as "flipping this
    // buys nothing".  AFL++ also prunes a block that dominates all of its
    // successors, and reaching those successors is new coverage by anyone's
    // reckoning: the true side of an `if` guarding nested work is pruned
    // exactly that way, so calling it uninteresting would refuse to solve the
    // one branch that gates the rest of the program.  The honest statement is
    // that this direction resolves to a *disjunction* of edges and the map
    // holds one target per direction, so it cannot answer -- which is the same
    // position as a branch it never heard of, and takes the same degrade path.
    //
    // TODO: recording the pruned block's numbered successors would let the
    // fuzzer's history decide here too, and would be strictly better than our
    // own session-local record.  It needs a map entry that is a set, so it
    // waits for a format that has one.
    if (edge && *edge == BranchMap::kPruned) edge = nullptr;
    if (edge) {
      if (count) mapped_ += 1;
      // "Has the fuzzer covered this edge?" is not a yes/no question to
      // MaxMapFeedback -- it compares hit-count *classes*, so the second
      // traversal of an edge is a different observation from the first.  That
      // distinction is the whole reason a loop body is solvable more than
      // once, and asking host_[e] == 0 threw it away: one hit on the flipped
      // edge, ever, and every later iteration of the loop looked covered.
      //
      // trace_hits_ is how far around the loop this branch already is, so
      // class(that) is the class the flipped edge would land in.  It is an
      // estimate -- what the fuzzer records depends on the whole rewritten
      // trace, which we would have to run to know -- and it errs towards
      // solving, which is the right way to err for a stage that is gated to
      // once per corpus entry anyway.
      auto hit = trace_hits_.find(context->id);
      uint8_t want = count_class(hit == trace_hits_.end() ? 1 : hit->second);
      // Only the fuzzer's history answers the other half.  Nothing of ours is
      // folded in: it refreshes host_ before every traced entry
      // (bindings/rust/libafl-symsan/src/lib.rs), so a session-lifetime record
      // would only duplicate it -- except when it did not, and then it would be
      // our bookkeeping vetoing the fuzzer's, which is the failure this class
      // exists to undo.
      uint8_t have = host_at(*edge);
      // The map answered, so it decides.  `branches` is keyed on address and
      // lives as long as the session, which makes it wrong in exactly the case
      // we came here to fix: it can only ever say "solved once already", and a
      // branch inside a loop is worth solving at every depth.  Letting it veto
      // is what kept test-crc32 stuck -- the fuzzer would happily have taken
      // the input, and we never built the task.
      return have < want;
    }

    if (count) unmapped_ += 1;
    // Nothing in the map for this branch: code AFL++ never instrumented, one of
    // SymSan's own checks, or the false side of a switch case, which is not one
    // edge.  Nothing better to consult than our own history, which is
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