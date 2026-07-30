#pragma once

#include "branch_map.h"

#include <stdint.h>
#include <vector>
#include <unordered_map>
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

public:
  explicit SharedMapCovManager(const BranchMap *map)
      : map_(map) { _ctx = std::make_shared<BranchContext>(); }

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