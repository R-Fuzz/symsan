#pragma once

#include <stdint.h>
#include <vector>
#include <map>
#include <memory>
#include <unordered_map>
#include <bitset>
#include <queue>

#include "ast.h"
#include "cov.h"

namespace rgd {

// JIT'ed function for each relational constraint
typedef void(*test_fn_type)(uint64_t*);

// the first two slots of the arguments for reseved for the left and right operands
static const int RET_OFFSET = 2;

struct Constraint {
  Constraint() = delete;
  Constraint(int ast_size): fn(nullptr), const_num(0) {
    ast = std::make_shared<AstNode>(ast_size);
  }
  const AstNode *get_root() const { return const_cast<const AstNode*>(ast.get()); }

  // JIT'ed function for a comparison expression
  test_fn_type fn;
  // the AST
  std::shared_ptr<AstNode> ast;

  // During constraint collection, (symbolic) input bytes are recorded
  // as offsets from the beginning of the input.  However, the JIT'ed
  // function consumes inputs as an input array.  So, when building the
  // function, we need to map the offset to the idx in input array,
  // which is stored in local_map.
  std::map<size_t, uint32_t> local_map;
  // if const {false, const value}, if symbolic {true, index in the inputs}
  // during local search, we use a single global array (to avoid memory
  // allocation and free) to prepare the inputs, so we need to know where
  // to load the input values into the input array.
  std::vector<std::pair<bool, uint64_t>> input_args;
  // map the offset to iv (initial value)
  std::unordered_map<uint32_t, uint8_t> inputs;
  // shape information about the input (e.g., 1, 2, 4, 8 bytes)
  std::unordered_map<uint32_t, uint32_t> shapes;
  // number of constant in the input array
  uint32_t const_num;
  // recorded comparison operands
  uint64_t op1, op2;
};

struct ConsMeta {
  // per-constraint arg mapping, so we can share the constraints
  std::vector<std::pair<bool, uint64_t>> input_args;
  // per-constraint relational operator, so we can share the AST
  uint32_t comparison;
  // input2state inference related
  bool i2s_feasible;
  uint64_t op1, op2;
};

struct SearchTask {
  SearchTask(): scratch_args(nullptr), max_const_num(0),
      stopped(false), attempts(0), solved(false), skip_next(false),
      base_task(nullptr) {}
  ~SearchTask() { if (scratch_args) free(scratch_args); }

  uint32_t num_exprs;
  // constraints, could be shared, strictly read-only
  std::vector<std::shared_ptr<const Constraint>> constraints;
  // temporary storage for the comparison operation
  std::vector<uint32_t> comparisons;
  // per-constraint mutable metadata
  std::vector<std::unique_ptr<ConsMeta>> consmeta;

  // inputs as pairs of <offset (from the beginning of the input, and value>
  std::vector<std::pair<uint32_t, uint8_t>> inputs;
  // shape information at each offset
  std::unordered_map<uint32_t, uint32_t> shapes;
  // max number of constants in the input array
  uint32_t max_const_num;
  // record constraints that use a certain input byte
  std::unordered_map<uint32_t, std::vector<size_t>> cmap;
  // the input array used for all JIT'ed functions
  // all input bytes are extended to 64 bits
  uint64_t* scratch_args;

  // intermediate states for the search
  std::vector<uint64_t> min_distances; // current best
  std::vector<uint64_t> distances; // general scratch
  std::vector<uint64_t> plus_distances; // used in partial derivation
  std::vector<uint64_t> minus_distances; // used in partial derivation

  // statistics
  uint64_t start; //start time
  bool stopped;
  int attempts;

  // solutions
  bool solved;
  std::unordered_map<size_t, uint8_t> solution;

  // base task
  std::shared_ptr<SearchTask> base_task;
  bool skip_next; // FIXME: an ugly hack to skip the next task

  void finalize() {
    // aggregate the contraints, map each input byte to a constraint to
    // an index in the "global" input array (i.e., the scratch_args)
    std::unordered_map<uint32_t, uint32_t> sym_map;
    uint32_t gidx = 0;
    for (size_t i = 0; i < constraints.size(); i++) {
      std::unique_ptr<ConsMeta> cm = std::make_unique<ConsMeta>();
      cm->input_args = constraints[i]->input_args;
      cm->comparison = comparisons[i];
      uint32_t last_offset = -1;
      cm->i2s_feasible = true;
      for (const auto& [offset, lidx] : constraints[i]->local_map) {
        auto gitr = sym_map.find(offset);
        if (gitr == sym_map.end()) {
          gidx = inputs.size();
          sym_map[offset] = gidx;
          inputs.push_back(std::make_pair(offset, constraints[i]->inputs.at(offset)));
          shapes[offset] = constraints[i]->shapes.at(offset);
        } else {
          gidx = gitr->second;
        }
        // record input to constraint mapping
        // skip memcmp constraints
        if (cm->comparison != rgd::Memcmp && cm->comparison != rgd::MemcmpN) {
          auto slot = cmap.find(gidx);
          if (slot != cmap.end()) {
            slot->second.push_back(i);
          } else {
            cmap.emplace(std::make_pair(gidx, std::vector<size_t>{i}));
          }
        }
        // save the mapping between the local index (i.e., where the JIT'ed
        // function is going to read the input from) and the global index
        // (i.e., where the current value corresponding to the input byte
        // is stored in MutInput)
        cm->input_args[lidx].second = gidx;

        // check if the input bytes are consecutive
        // using std::map ensures that the offsets (keys) are sorted
        if (last_offset != -1 && last_offset + 1 != offset) {
          cm->i2s_feasible = false;
        }
        last_offset = offset;
      }
      // FIXME: only support up to 64-bit for now
      if (comparisons[i] != rgd::Memcmp && comparisons[i] != rgd::MemcmpN
          && constraints[i]->local_map.size() > 8) {
        cm->i2s_feasible = false;
      }

      // update the number of required constants in the input array
      if (max_const_num < constraints[i]->const_num)
        max_const_num = constraints[i]->const_num;

      // insert the constraint metadata
      consmeta.push_back(std::move(cm));
    }

    // allocate the input array, reserver 2 for comparison operands a,b
    scratch_args = (uint64_t*)aligned_alloc(sizeof(*scratch_args),
        (2 + inputs.size() + max_const_num + 1) * sizeof(*scratch_args));
    min_distances.resize(constraints.size(), 0);
    distances.resize(constraints.size(), 0);
    plus_distances.resize(constraints.size(), 0);
    minus_distances.resize(constraints.size(), 0);
  }

  void load_hint() { // load hint from base task
    if (!base_task || !base_task->solved) return;
    for (auto itr = inputs.begin(); itr != inputs.end(); itr++) {
      auto got = base_task->solution.find(itr->first);
      if (got != base_task->solution.end())
        itr->second = got->second;
    }
  }

};

class TaskManager {
public:
  virtual ~TaskManager() {}
  virtual bool add_task(std::shared_ptr<BranchContext> ctx, std::shared_ptr<SearchTask> task) = 0;
  virtual std::shared_ptr<SearchTask> get_next_task() = 0;
  virtual size_t get_num_tasks() = 0;
};

class FIFOTaskManager : public TaskManager {
public:
  bool add_task(std::shared_ptr<BranchContext> ctx, std::shared_ptr<SearchTask> task) override {
    (void)ctx;
    tasks.push_back(task);
    return true;
  }

  std::shared_ptr<SearchTask> get_next_task() override {
    if (tasks.empty()) return nullptr;
    auto task = tasks.front();
    tasks.pop_front();
    return task;
  }

  size_t get_num_tasks() override {
    return tasks.size();
  }

private:
  std::deque<std::shared_ptr<SearchTask>> tasks;
};

}; // namespace rgd
