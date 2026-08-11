#pragma once

#include <stdint.h>

#include <algorithm>
#include <bitset>
#include <cassert>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "ast.h"
#include "cov.h"

namespace rgd {

// JIT'ed function for each relational constraint
typedef void(*test_fn_type)(uint64_t*);

// the first two slots of the arguments for reseved for the left and right operands
static const int RET_OFFSET = 2;

struct Constraint {
  Constraint() = delete;
  // @p arg_size is an upper bound on the input_args slots the AST will need,
  // so the parse path does not reallocate.  Unlike @p ast_size -- which
  // AstNode::add_children() treats as a hard limit -- it is only a hint: too
  // small merely lets the vector grow as it used to.
  Constraint(int ast_size, size_t arg_size = 0): fn(nullptr), const_num(0) {
    ast = std::make_shared<AstNode>(ast_size);
    if (arg_size) input_args.reserve(arg_size);
  }
  Constraint(const Constraint&) = default; // XXX: okay to use default?
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
  // special infomation for atoi: offset -> (result_length, base, str_length)
  std::unordered_map<uint32_t, std::tuple<uint32_t, uint32_t, uint32_t>> atoi_info;
  // record the involved operations
  std::bitset<rgd::LastOp> ops;
  // number of constant in the input array
  uint32_t const_num;
  // recorded comparison operands
  uint64_t op1, op2;

  // --- serialization ----------------------------------------------------
  // The Constraint, not the AstNode, is the self-contained unit.  Every
  // payload the AST refers to -- constant values, memcmp/string content --
  // deliberately lives in input_args rather than in a node, so that one
  // JIT'ed function serves many values; see THE HASHING INVARIANT in
  // include/ast.h.  An AST on its own is therefore only half a constraint.
  //
  // fn is not saved: it is a pointer into jigsaw's JIT'ed code, and a loaded
  // constraint re-enters the fCache lookup like any other.

  static constexpr uint32_t kMagic = 0x43444752u; // "RGDC", little-endian
  // Bump on ANY layout change below -- and also when rgd::LastOp moves, because
  // the ops bitset is written as bit-per-kind.  Appending kinds keeps every
  // existing bit position valid, so an OLD file still loads correctly, but a
  // NEW file with a high bit set read by an old binary would have that bit
  // silently dropped by its shorter loop.  The ops_words check below does not
  // catch it: 85 and 98 kinds both pack into two words.
  //   v1  LastOp = 85 (through BitReverse)
  //   v2  LastOp = 98 (the string kinds, StrLen..StrPtrToInt)
  static constexpr uint32_t kVersion = 2u;

  // Laid out so every field is naturally aligned and sizeof() has no implicit
  // padding -- the static_asserts below hold the format to that.
  struct FileHeader {
    uint32_t magic, version;
    uint32_t num_nodes; // the arena, NOT counting the standalone root
    uint32_t num_args, num_sym, num_atoi, ops_words, const_num;
    uint64_t op1, op2;
  };
  struct ArgRec { uint64_t value; uint8_t is_symbolic; uint8_t reserved[7]; };
  struct SymRec { uint32_t offset, lidx, shape; uint8_t iv; uint8_t reserved[3]; };
  struct AtoiRec { uint32_t offset, result_len, base, str_len; };

  bool save(std::vector<uint8_t> &out) const {
    if (!ast) return false;
    // local_map, inputs and shapes are filled together, one entry per input
    // offset (rgd-parser.cpp map_arg and the atoi case), so one SymRec covers
    // all three.  A gap means the constraint is malformed; refuse rather than
    // write a file that cannot be loaded back.
    for (const auto& [offset, lidx] : local_map) {
      uint32_t off = (uint32_t)offset;
      if (offset != off) return false; // SymRec::offset is 32 bits
      if (!inputs.count(off) || !shapes.count(off)) return false;
    }

    std::vector<AstNode::NodeRec> nodes;
    ast->serialize(nodes);
    if (nodes.empty()) return false;

    const uint32_t ops_words = (rgd::LastOp + 63) / 64;
    FileHeader hdr{};
    hdr.magic = kMagic;
    hdr.version = kVersion;
    hdr.num_nodes = (uint32_t)(nodes.size() - 1); // minus the standalone root
    hdr.num_args = (uint32_t)input_args.size();
    hdr.num_sym = (uint32_t)local_map.size();
    hdr.num_atoi = (uint32_t)atoi_info.size();
    hdr.ops_words = ops_words;
    hdr.const_num = const_num;
    hdr.op1 = op1;
    hdr.op2 = op2;
    append(out, &hdr, sizeof(hdr));
    append(out, nodes.data(), nodes.size() * sizeof(AstNode::NodeRec));

    for (const auto& [is_symbolic, value] : input_args) {
      ArgRec r{};
      r.value = value;
      r.is_symbolic = is_symbolic;
      append(out, &r, sizeof(r));
    }
    // std::map, so this iterates in offset order and the file is
    // deterministic -- a round-trip test can compare bytes
    for (const auto& [offset, lidx] : local_map) {
      SymRec r{};
      r.offset = (uint32_t)offset;
      r.lidx = lidx;
      r.shape = shapes.at((uint32_t)offset);
      r.iv = inputs.at((uint32_t)offset);
      append(out, &r, sizeof(r));
    }
    // atoi_info is unordered; sort so the file stays deterministic
    std::vector<uint32_t> atoi_offsets;
    atoi_offsets.reserve(atoi_info.size());
    for (const auto& [offset, info] : atoi_info) atoi_offsets.push_back(offset);
    std::sort(atoi_offsets.begin(), atoi_offsets.end());
    for (uint32_t offset : atoi_offsets) {
      const auto& info = atoi_info.at(offset);
      AtoiRec r{};
      r.offset = offset;
      r.result_len = std::get<0>(info);
      r.base = std::get<1>(info);
      r.str_len = std::get<2>(info);
      append(out, &r, sizeof(r));
    }
    // ops is wider than 64 bits, so to_ullong() would throw; pack by hand
    std::vector<uint64_t> words(ops_words, 0);
    for (size_t i = 0; i < rgd::LastOp; i++) {
      if (ops[i]) words[i / 64] |= 1ULL << (i % 64);
    }
    append(out, words.data(), words.size() * sizeof(uint64_t));
    return true;
  }

  // Restore into this constraint, replacing whatever it held.  Every length
  // is checked against @p len before it is used: a truncated or corrupt file
  // that loads anyway is a wrong solution later, which is far worse than a
  // rejected file here.
  bool load(const uint8_t *buf, size_t len) {
    size_t pos = 0;
    FileHeader hdr{};
    if (!consume(buf, len, pos, &hdr, sizeof(hdr))) return false;
    if (hdr.magic != kMagic) return false;
    if (hdr.version != kVersion) return false;
    if (hdr.ops_words != (rgd::LastOp + 63) / 64) return false;
    if (hdr.num_nodes == UINT32_MAX) return false; // +1 below would wrap

    std::vector<AstNode::NodeRec> nodes(hdr.num_nodes + 1);
    if (!consume(buf, len, pos, nodes.data(),
                 nodes.size() * sizeof(AstNode::NodeRec))) return false;

    std::vector<std::pair<bool, uint64_t>> new_args;
    new_args.reserve(hdr.num_args);
    for (uint32_t i = 0; i < hdr.num_args; i++) {
      ArgRec r{};
      if (!consume(buf, len, pos, &r, sizeof(r))) return false;
      new_args.push_back(std::make_pair((bool)r.is_symbolic, r.value));
    }

    std::map<size_t, uint32_t> new_local_map;
    std::unordered_map<uint32_t, uint8_t> new_inputs;
    std::unordered_map<uint32_t, uint32_t> new_shapes;
    for (uint32_t i = 0; i < hdr.num_sym; i++) {
      SymRec r{};
      if (!consume(buf, len, pos, &r, sizeof(r))) return false;
      // lidx indexes input_args; finalize() writes through it
      if (r.lidx >= hdr.num_args) return false;
      new_local_map[r.offset] = r.lidx;
      new_inputs[r.offset] = r.iv;
      new_shapes[r.offset] = r.shape;
    }

    std::unordered_map<uint32_t, std::tuple<uint32_t, uint32_t, uint32_t>> new_atoi;
    for (uint32_t i = 0; i < hdr.num_atoi; i++) {
      AtoiRec r{};
      if (!consume(buf, len, pos, &r, sizeof(r))) return false;
      new_atoi[r.offset] = std::make_tuple(r.result_len, r.base, r.str_len);
    }

    std::vector<uint64_t> words(hdr.ops_words, 0);
    if (!consume(buf, len, pos, words.data(),
                 words.size() * sizeof(uint64_t))) return false;
    std::bitset<rgd::LastOp> new_ops;
    for (size_t i = 0; i < rgd::LastOp; i++) {
      if (words[i / 64] & (1ULL << (i % 64))) new_ops.set(i);
    }

    // the AST is rebuilt last, and range checks its own child indices
    auto new_ast = std::make_shared<AstNode>(hdr.num_nodes);
    if (!new_ast->deserialize(nodes.data(), nodes.size())) return false;

    fn = nullptr;
    ast = new_ast;
    local_map = std::move(new_local_map);
    input_args = std::move(new_args);
    inputs = std::move(new_inputs);
    shapes = std::move(new_shapes);
    atoi_info = std::move(new_atoi);
    ops = new_ops;
    const_num = hdr.const_num;
    op1 = hdr.op1;
    op2 = hdr.op2;
    return true;
  }

private:
  static inline void append(std::vector<uint8_t> &out, const void *p, size_t n) {
    const uint8_t *b = (const uint8_t*)p;
    out.insert(out.end(), b, b + n);
  }
  // memcpy rather than a cast: the record sizes are not all multiples of 8,
  // so a section can start unaligned
  static inline bool consume(const uint8_t *buf, size_t len, size_t &pos,
                             void *dst, size_t n) {
    if (n > len - pos) return false; // pos <= len always, so this cannot wrap
    memcpy(dst, buf + pos, n);
    pos += n;
    return true;
  }
};

static_assert(sizeof(Constraint::FileHeader) == 48, "on-disk layout changed");
static_assert(sizeof(AstNode::NodeRec) == 28, "on-disk layout changed");
static_assert(sizeof(Constraint::ArgRec) == 16, "on-disk layout changed");
static_assert(sizeof(Constraint::SymRec) == 16, "on-disk layout changed");
static_assert(sizeof(Constraint::AtoiRec) == 16, "on-disk layout changed");

struct ConsMeta {
  // per-constraint arg mapping, so we can share the constraints
  std::vector<std::pair<bool, uint64_t>> input_args;
  // per-constraint relational operator, so we can share the AST
  uint32_t comparison;
  // input2state inference related
  std::vector<std::pair<size_t, uint32_t>> i2s_candidates;
  uint64_t op1, op2;
};

class SearchTask {
public:
  SearchTask(): scratch_args(nullptr), max_const_num_(0),
      stopped(false), attempts(0), solved(false), skip_next(false),
      base_task(nullptr) {}
  SearchTask(const SearchTask&) = delete;
  ~SearchTask() { if (scratch_args) free(scratch_args); }
  inline bool has_finalized() const { return scratch_args != nullptr; }

  using constraint_t = std::shared_ptr<const Constraint>;
  using consmeta_t = std::unique_ptr<ConsMeta>;
  using input_t = std::pair<uint32_t, uint8_t>;

  inline bool empty() const {
    return constraints_.empty();
  }

  inline size_t size() const {
    return constraints_.size();
  }

  inline void add_constraint(constraint_t constraint, uint32_t comparison) {
    if (has_finalized()) {
      throw std::runtime_error("Cannot add constraints after finalization");
    }
    constraints_.push_back(constraint);
    comparisons_.push_back(comparison);
  }

  inline const constraint_t& constraints(size_t i) const {
    return constraints_.at(i);
  }

  inline const uint32_t comparisons(size_t i) const {
    return comparisons_.at(i);
  }

  inline consmeta_t& consmetas(size_t i) {
    // consmeta can be changed, but the vector cannot
    return consmetas_.at(i);
  }

  inline size_t inputs_size() const {
    return inputs_.size();
  }

  inline auto const& inputs() const {
    return inputs_;
  }

  inline const uint32_t shapes(uint32_t offset) const {
    auto itr = shapes_.find(offset);
    if (itr == shapes_.end()) {
      throw std::runtime_error("Cannot find shape information");
    }
    return itr->second;
  }

  inline auto const& atoi_info() const {
    return atoi_info_;
  }

  inline auto const& cmap(uint32_t index) const {
    if (index >= inputs_.size()) {
      throw std::out_of_range("index out of range");
    }
    auto itr = cmap_.find(index);
    if (itr == cmap_.end()) {
      throw std::runtime_error("Cannot find constraint mapping");
    }
    return itr->second;
  }

private:
  // varaible that should not change after finalization

  // constraints, could be shared, strictly read-only
  std::vector<constraint_t> constraints_;
  // temporary storage for the comparison operation
  std::vector<uint32_t> comparisons_;
  // per-constraint mutable metadata
  std::vector<consmeta_t> consmetas_;

  // inputs as pairs of <offset (from the beginning of the input, and value>
  std::vector<std::pair<uint32_t, uint8_t>> inputs_;
  // shape information at each offset
  std::unordered_map<uint32_t, uint32_t> shapes_;
  // aggreated atoi info
  std::unordered_map<uint32_t, std::tuple<uint32_t, uint32_t, uint32_t>> atoi_info_;
  // max number of constants in the input array
  uint32_t max_const_num_;
  // record constraints that use a certain input byte
  std::unordered_map<uint32_t, std::vector<size_t>> cmap_;

public:
  // scratching area for solving the task

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

  /// The branch this task was built to flip, or null if nobody said.
  ///
  /// Shared with the sibling tasks built for the same branch.  The session used
  /// to hold this link in a SearchTask* -> index map alongside a vector it
  /// cleared on every trace, which meant a task could not be solved outside the
  /// trace that produced it: it lost its target, and next_pending_task() reads a
  /// missing target as "solve it", so the loss was silent.  Whoever builds the
  /// task sets it; a caller that solves tasks straight through (afltest) leaves
  /// it null and nothing asks.
  std::shared_ptr<TaskTarget> target;

  /// The bytes this task's Reads are offsets into, or null if nobody said.
  ///
  /// A task is "these constraints over *these* bytes", and the two halves used
  /// to be separated: the solvers were handed whatever the session had traced
  /// most recently.  While the queue was drained to exhaustion inside the trace
  /// that filled it those were the same bytes; with a budget they are not, and
  /// a task solved against another seed does not give a worse answer, it
  /// answers a different question.
  ///
  /// Shared with every other task from the same trace, so the cost is one copy
  /// of the seed per traced entry, not per task.  A caller that solves tasks
  /// straight through (afltest, fgtest) leaves it null and passes the buffer.
  std::shared_ptr<const std::vector<uint8_t>> input;

  /// Which rung of the solver ladder gets this task next: an index into the
  /// session's solver list, advanced by every attempt that did not end in an
  /// accepted answer.  Past the end of the ladder means every solver has had
  /// its turn and the task is finished.
  ///
  /// On the task rather than on the session because the ladder is a property of
  /// the question, not of the loop asking it.  The session used to keep one
  /// cur_solver_index_ and walk it inline, which is only correct while a task
  /// stays in hand for its whole ladder; once a task can go back into the queue
  /// between two of its own attempts, the session has no memory of how far this
  /// one had got, and the position has to travel with it.
  ///
  /// Distinct from `attempts`, which is jigsaw's own gradient-descent counter
  /// and moves inside a single solve() call.
  uint8_t solver_index = 0;

  void finalize() {
    // aggregate the contraints, map each input byte to a constraint to
    // an index in the "global" input array (i.e., the scratch_args)
    std::unordered_map<uint32_t, uint32_t> sym_map;
    uint32_t gidx = 0;
    size_t num_const = constraints_.size();
    for (size_t i = 0; i < num_const; i++) {
      auto const& constraint = constraints_[i];
      std::unique_ptr<ConsMeta> cm = std::make_unique<ConsMeta>();
      cm->input_args = constraint->input_args;
      cm->comparison = comparisons_[i];
      uint32_t last_offset = -1;
      uint32_t size = 0;
      for (const auto& [offset, lidx] : constraint->local_map) {
        auto gitr = sym_map.find(offset);
        if (gitr == sym_map.end()) {
          gidx = inputs_.size();
          sym_map[offset] = gidx;
          inputs_.push_back(std::make_pair(offset, constraint->inputs.at(offset)));
          shapes_[offset] = constraint->shapes.at(offset);
        } else {
          gidx = gitr->second;
        }
        // record input to constraint mapping
        // skip memcmp constraints
        if (cm->comparison != rgd::Memcmp && cm->comparison != rgd::MemcmpN) {
          auto slot = cmap_.find(gidx);
          if (slot != cmap_.end()) {
            slot->second.push_back(i);
          } else {
            cmap_.emplace(std::make_pair(gidx, std::vector<size_t>{i}));
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
          // a new set of consecutive input bytes, save the info
          // and resset
          cm->i2s_candidates.push_back({last_offset + 1 - size, size});
          size = 0;
        }
        last_offset = offset;
        size++;
      }
      // save the last set of consecutive input bytes
      cm->i2s_candidates.push_back({last_offset + 1 - size, size});

      // process atoi
      for (const auto& [offset, info] : constraint->atoi_info) {
        // check dependencies
        uint32_t length = std::get<2>(info);
        for (auto j = 0; j < length; ++j) {
          auto ditr = cmap_.find(offset + j);
          if (ditr != cmap_.end()) {
            fprintf(stderr, "atoi bytes (%d) used in other constraints\n", offset + j);
          }
        }
        auto itr = atoi_info_.find(offset);
        if (itr != atoi_info_.end()) {
          fprintf(stderr, "atoi bytes (%d) already exists\n", offset);
          assert(info == itr->second);
        }
        atoi_info_[offset] = info;
      }

      // update the number of required constants in the input array
      if (max_const_num_ < constraint->const_num)
        max_const_num_ = constraint->const_num;

      // insert the constraint metadata
      consmetas_.push_back(std::move(cm));
    }

    // fill the gap in cmap_
    for (size_t i = 0; i < inputs_.size(); i++) {
      auto slot = cmap_.find(i);
      if (slot == cmap_.end()) {
        cmap_.emplace(std::make_pair(i, std::vector<size_t>{}));
      }
    }

    // allocate the input array, reserver 2 for comparison operands a,b
    scratch_args = (uint64_t*)aligned_alloc(sizeof(*scratch_args),
        (2 + inputs_.size() + max_const_num_ + 1) * sizeof(*scratch_args));
    min_distances.resize(num_const, 0);
    distances.resize(num_const, 0);
    plus_distances.resize(num_const, 0);
    minus_distances.resize(num_const, 0);
  }

  void load_hint() { // load hint from base task
    if (!base_task || !base_task->solved) return;
    for (auto itr = inputs_.begin(), e = inputs_.end(); itr != e; itr++) {
      auto got = base_task->solution.find(itr->first);
      if (got != base_task->solution.end())
        itr->second = got->second;
    }
  }

};

using task_t = std::shared_ptr<rgd::SearchTask>;

}; // namespace rgd
