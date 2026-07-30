#pragma once

#include "branch_map.h"

#include <stdint.h>
#include <stddef.h>
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

public:
  explicit SharedMapCovManager(const BranchMap *map)
      : map_(map) { _ctx = std::make_shared<BranchContext>(); }

  /// Start (or stop) recording the directions each trace takes, for validate().
  void set_validating(bool on) { validating_ = on; if (!on) taken_.clear(); }
  /// Forget the previous trace's directions.  Call at the top of each trace.
  void clear_taken() { taken_.clear(); }

  /// Check the map against ground truth: @p covered is the set of edge ids the
  /// *fuzzer's* build recorded for the same input this session just traced.
  ///
  /// The invariant is one-directional.  Every direction we took must map to an
  /// edge the fuzzer also recorded, so a violation is real: either the map
  /// points at the wrong edge, or the two builds diverged on this input.  The
  /// converse says nothing -- the fuzzer records concrete branches, switch
  /// cases and plain blocks, none of which reach us.
  ///
  /// Inlining costs precision: one source branch becomes N edge ids and a run
  /// takes one of them, so those can only be checked as "at least one covered"
  /// and are counted apart from the exact ones.
  void validate(const uint32_t *covered, size_t n, JoinReport *out) const {
    std::unordered_set<uint32_t> hit(covered, covered + n);
    for (uint64_t key : taken_) {
      out->executed += 1;
      const std::vector<uint32_t> *edges =
          map_ ? map_->lookup((uint32_t)(key >> 1), (key & 1) != 0) : nullptr;
      if (!edges || edges->empty()) {
        out->unmapped += 1;
      } else if (edges->size() == 1) {
        out->checked += 1;
        if (hit.find((*edges)[0]) == hit.end()) out->violations += 1;
      } else {
        out->ambiguous += 1;
        bool any = false;
        for (uint32_t e : *edges) {
          if (hit.find(e) != hit.end()) { any = true; break; }
        }
        if (!any) out->ambiguous_violations += 1;
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
    // Here rather than in is_branch_interesting(), which is handed the
    // *negated* context: this is the only place the direction actually taken
    // is in hand, and that is the one the fuzzer's map can be checked against.
    if (validating_) taken_.insert(((uint64_t)id << 1) | (direction ? 1 : 0));
    _ctx->addr = addr;
    _ctx->direction = direction;
    return _ctx;
  }

  bool is_branch_interesting(const std::shared_ptr<BranchContext> context) override {
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
      mapped_ += 1;
      // Inlining gives one source branch several edge ids.  One uncovered copy
      // is still worth solving for, so this is "any", not "all".
      host_says_new = false;
      for (uint32_t e : *edges) {
        if (e >= host_.size() || host_[e] == 0) { host_says_new = true; break; }
      }
    } else {
      unmapped_ += 1;
    }

    auto itr = branches.find(context->addr);
    // assert(itr != branches.end());
    bool locally_new = context->direction ? itr->second.first == false
                                          : itr->second.second == false;
    return locally_new && host_says_new;
  }
};

}; // namespace rgd