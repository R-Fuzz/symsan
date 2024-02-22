#pragma once

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
    assert(itr != branches.end());
    if (context->direction) {
      return itr->second.first == false;
    } else {
      return itr->second.second == false;
    }
  }
};

}; // namespace rgd