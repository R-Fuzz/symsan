#pragma once

#include <stdint.h>
#include <vector>
#include <unordered_map>
#include <memory>
#include <utility>

namespace rgd {

struct BranchContext {
  void *addr;
  uint32_t id;
  bool direction;
  uint32_t context;
  uint32_t loop_counter;
  uint32_t history;
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
public:
  const std::shared_ptr<BranchContext>
  add_branch(void *addr, uint32_t id, bool direction, uint32_t context, bool is_loop_header, bool is_loop_exit) override {
    auto itr = branches.find(addr);
    if (itr == branches.end()) {
      auto ctx = std::make_shared<BranchContext>();
      ctx->addr = addr;
      ctx->direction = direction;
      std::shared_ptr<BranchContext> tt = direction? ctx : nullptr;
      std::shared_ptr<BranchContext> ft = direction? nullptr : ctx;
      branches.insert({addr, {tt, ft}});
      return ctx;
    } else {
      if (direction) {
        auto ctx = itr->second.first;
        if (!ctx) {
          ctx = std::make_shared<BranchContext>();
          ctx->addr = addr;
          ctx->direction = direction;
          itr->second.first = ctx;
        }
        return ctx;
      } else {
        auto ctx = itr->second.second;
        if (!ctx) {
          ctx = std::make_shared<BranchContext>();
          ctx->addr = addr;
          ctx->direction = direction;
          itr->second.second = ctx;
        }
        return ctx;
      }
    }
  }

  bool is_branch_interesting(const std::shared_ptr<BranchContext> context) override {
    auto itr = branches.find(context->addr);
    assert(itr != branches.end());
    if (context->direction) {
      return itr->second.first == nullptr;
    } else {
      return itr->second.second == nullptr;
    }
  }

private:
  typedef std::pair<std::shared_ptr<BranchContext>, std::shared_ptr<BranchContext>> BranchTargets;
  std::unordered_map<void*, BranchTargets> branches;
};

}; // namespace rgd