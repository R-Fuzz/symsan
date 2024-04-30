/*
  a custom mutator for AFL++
  (c) 2023 - 2024 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#include "dfsan/dfsan.h"

#include "ast.h"
#include "task.h"
#include "solver.h"
#include "cov.h"
#include "union_find.h"

extern "C" {
#include "afl-fuzz.h"
}

#include "boost/dynamic_bitset.hpp"

#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <queue>
#include <memory>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

using namespace __dfsan;

#ifndef DEBUG
#define DEBUG 0
#endif

#if !DEBUG
#undef DEBUGF
#define DEBUGF(_str...) do { } while (0)
#endif

#define NEED_OFFLINE 0

#define PRINT_STATS 0

#define MAX_AST_SIZE 200

#define MIN_TIMEOUT 50U

#define MAX_LOCAL_BRANCH_COUNTER 128

static bool NestedSolving = false;
static int TraceBounds = 0;

#undef alloc_printf
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = (char*)ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

using expr_t = std::shared_ptr<rgd::AstNode>;
using constraint_t = std::shared_ptr<rgd::Constraint> ;
using task_t = std::shared_ptr<rgd::SearchTask>;
using solver_t = std::shared_ptr<rgd::Solver>;
using branch_ctx_t = std::shared_ptr<rgd::BranchContext>;

enum mutation_state_t {
  MUTATION_INVALID,
  MUTATION_IN_VALIDATION,
  MUTATION_VALIDATED,
};

enum ast_node_t {
  NONE_CMP_NODE = 0,
  CMP_NODE = 1,
  INVALID_NODE = 2,
  CONCRETIZE_NODE = 4,
};

struct my_mutator_t {
  my_mutator_t() = delete;
  my_mutator_t(const afl_state_t *afl, rgd::TaskManager* tmgr, rgd::CovManager* cmgr) :
    afl(afl), out_dir(NULL), out_file(NULL), symsan_bin(NULL),
    argv(NULL), out_fd(-1), shm_fd(-1), cur_queue_entry(NULL),
    cur_mutation_state(MUTATION_INVALID), output_buf(NULL),
    cur_task(nullptr), cur_solver_index(-1),
    task_mgr(tmgr), cov_mgr(cmgr) {}

  ~my_mutator_t() {
    if (out_fd >= 0) close(out_fd);
    if (shm_fd >= 0) close(shm_fd);
    // unlink(data->out_file);
    shm_unlink(shm_name);
    ck_free(shm_name);
    ck_free(out_dir);
    ck_free(out_file);
    ck_free(output_buf);
    ck_free(argv);
    delete task_mgr;
    delete cov_mgr;
  }

  const afl_state_t *afl;
  char *out_dir;
  char *out_file;
  char *symsan_bin;
  char **argv;
  int out_fd;
  char *shm_name;
  int shm_fd;
  u8* cur_queue_entry;
  int cur_mutation_state;
  u8* output_buf;
  int log_fd;

  std::unordered_set<u32> fuzzed_inputs;
  rgd::TaskManager* task_mgr;
  rgd::CovManager* cov_mgr;
  std::vector<solver_t> solvers;

  // XXX: well, we have to keep track of solving states
  task_t cur_task;
  size_t cur_solver_index;
};

// FIXME: find another way to make the union table hash work
static dfsan_label_info *__dfsan_label_info;
static const size_t MAX_LABEL = uniontable_size / sizeof(dfsan_label_info);

dfsan_label_info* __dfsan::get_label_info(dfsan_label label) {
  if (unlikely(label >= MAX_LABEL)) {
    throw std::out_of_range("label too large " + std::to_string(label));
  }
  return &__dfsan_label_info[label];
}

static const std::unordered_map<unsigned, std::pair<unsigned, const char*> > OP_MAP {
  {__dfsan::Extract, {rgd::Extract, "extract"}},
  {__dfsan::Trunc,   {rgd::Extract, "extract"}},
  {__dfsan::Concat,  {rgd::Concat, "concat"}},
  {__dfsan::ZExt,    {rgd::ZExt, "zext"}},
  {__dfsan::SExt,    {rgd::SExt, "sext"}},
  {__dfsan::Add,     {rgd::Add, "add"}},
  {__dfsan::Sub,     {rgd::Sub, "sub"}},
  {__dfsan::Mul,     {rgd::Mul, "mul"}},
  {__dfsan::UDiv,    {rgd::UDiv, "udiv"}},
  {__dfsan::SDiv,    {rgd::SDiv, "sdiv"}},
  {__dfsan::URem,    {rgd::URem, "urem"}},
  {__dfsan::SRem,    {rgd::SRem, "srem"}},
  {__dfsan::Shl,     {rgd::Shl, "shl"}},
  {__dfsan::LShr,    {rgd::LShr, "lshr"}},
  {__dfsan::AShr,    {rgd::AShr, "ashr"}},
  {__dfsan::And,     {rgd::And, "and"}},
  {__dfsan::Or,      {rgd::Or, "or"}},
  {__dfsan::Xor,     {rgd::Xor, "xor"}},
  // relational comparisons
#define RELATIONAL_ICMP(cmp) (__dfsan::ICmp | (cmp << 8)) 
  {RELATIONAL_ICMP(__dfsan::bveq),  {rgd::Equal, "equal"}},
  {RELATIONAL_ICMP(__dfsan::bvneq), {rgd::Distinct, "distinct"}},
  {RELATIONAL_ICMP(__dfsan::bvugt), {rgd::Ugt, "ugt"}},
  {RELATIONAL_ICMP(__dfsan::bvuge), {rgd::Uge, "uge"}},
  {RELATIONAL_ICMP(__dfsan::bvult), {rgd::Ult, "ult"}},
  {RELATIONAL_ICMP(__dfsan::bvule), {rgd::Ule, "ule"}},
  {RELATIONAL_ICMP(__dfsan::bvsgt), {rgd::Sgt, "sgt"}},
  {RELATIONAL_ICMP(__dfsan::bvsge), {rgd::Sge, "sge"}},
  {RELATIONAL_ICMP(__dfsan::bvslt), {rgd::Slt, "slt"}},
  {RELATIONAL_ICMP(__dfsan::bvsle), {rgd::Sle, "sle"}},
#undef RELATIONAL_ICMP
};

static inline bool is_rel_cmp(uint16_t op, __dfsan::predicate pred) {
  return (op & 0xff) == __dfsan::ICmp && (op >> 8) == pred;
}

static inline bool eval_icmp(uint16_t op, uint64_t op1, uint64_t op2) {
  if ((op & 0xff) == __dfsan::ICmp) {
    switch (op >> 8) {
      case __dfsan::bveq: return op1 == op2;
      case __dfsan::bvneq: return op1 != op2;
      case __dfsan::bvugt: return op1 > op2;
      case __dfsan::bvuge: return op1 >= op2;
      case __dfsan::bvult: return op1 < op2;
      case __dfsan::bvule: return op1 <= op2;
      case __dfsan::bvsgt: return (int64_t)op1 > (int64_t)op2;
      case __dfsan::bvsge: return (int64_t)op1 >= (int64_t)op2;
      case __dfsan::bvslt: return (int64_t)op1 < (int64_t)op2;
      case __dfsan::bvsle: return (int64_t)op1 <= (int64_t)op2;
      default: return false;
    }
  }
  return false;
}

// FIXME: global caches
static std::unordered_map<dfsan_label, expr_t> root_expr_cache;
static std::unordered_map<dfsan_label, constraint_t> constraint_cache;
using input_dep_t = boost::dynamic_bitset<>;
static std::vector<input_dep_t> branch_to_inputs;
static std::unordered_map<dfsan_label, std::unique_ptr<uint8_t[]>> memcmp_cache;
static std::vector<uint32_t> ast_size_cache;
static std::vector<uint8_t> nested_cmp_cache;
static std::unordered_map<dfsan_label, uint8_t> concretize_node;
static std::unordered_map<uint32_t, uint8_t> local_counter;
// FIXME: global input dependency forests
static rgd::UnionFind data_flow_deps;
static std::vector<std::vector<expr_t> > input_to_branches;
// staticstics
static uint64_t total_branches = 0;
static uint64_t branches_to_solve = 0;
static uint64_t total_tasks = 0;
static std::map<uint64_t, uint64_t> task_size_dist;
static uint64_t solved_tasks = 0;
static uint64_t solved_branches = 0;

static void reset_global_caches(size_t buf_size) {
  root_expr_cache.clear();
  constraint_cache.clear();
  branch_to_inputs.clear();
  memcmp_cache.clear();
  ast_size_cache.clear();
  nested_cmp_cache.clear();
  concretize_node.clear();
  local_counter.clear();
  data_flow_deps.reset(buf_size);
  for (auto &s: input_to_branches) {
    s.clear();
  }
  input_to_branches.resize(buf_size);
}

static uint32_t map_arg(const u8 *buf, size_t offset, uint32_t length,
                        std::shared_ptr<rgd::Constraint> constraint) {
  uint32_t hash = 0;
  for (uint32_t i = 0; i < length; ++i, ++offset) {
    u8 val = buf[offset];
    uint32_t arg_index = 0;
    auto itr = constraint->local_map.find(offset);
    if (itr == constraint->local_map.end()) {
      arg_index = (uint32_t)constraint->input_args.size();
      constraint->inputs.insert({offset, val});
      constraint->local_map[offset] = arg_index;
      constraint->input_args.push_back(std::make_pair(true, 0)); // 0 is to be filled in the aggragation
    } else {
      arg_index = itr->second;
    }
    if (i == 0) {
      constraint->shapes[offset] = length;
      hash = rgd::xxhash(length * 8, rgd::Read, arg_index);
    } else {
      constraint->shapes[offset] = 0;
    }
  }
  return hash;
}

// this combines both AST construction and arg mapping
[[nodiscard]] [[gnu::hot]]
static bool do_uta_rel(dfsan_label label, rgd::AstNode *ret,
                       const u8 *buf, size_t buf_size,
                       std::shared_ptr<rgd::Constraint> constraint,
                       std::unordered_set<dfsan_label> &visited) {

  if (label < CONST_OFFSET || label == kInitializingLabel || label >= MAX_LABEL) {
    WARNF("invalid label: %d\n", label);
    return false;
  }

  dfsan_label_info *info = get_label_info(label);
  DEBUGF("do_uta_real: %u = (l1:%u, l2:%u, op:%u, size:%u, op1:%lu, op2:%lu)\n",
         label, info->l1, info->l2, info->op, info->size, info->op1.i, info->op2.i);

  // we can't really reuse AST nodes across constraints,
  // but we still need to avoid duplicate nodes within a constraint
  if (visited.count(label)) {
    // if a node has been visited, just record its label without expanding
    ret->set_label(label);
    ret->set_bits(info->size);
    return true;
  }

  // terminal node
  if (info->op == 0) {
    // input
    ret->set_kind(rgd::Read);
    ret->set_bits(8);
    ret->set_label(label);
    uint64_t offset = info->op1.i;
    if (unlikely(offset >= buf_size)) {
      WARNF("invalid offset: %lu >= %lu\n", offset, buf_size);
      return false;
    }
    ret->set_index(offset);
    // map arg
    uint32_t hash = map_arg(buf, offset, 1, constraint);
    ret->set_hash(hash);
#if NEED_OFFLINE
    std::string val;
    rgd::buf_to_hex_string(&buf[offset], 1, val);
    ret->set_value(std::move(val));
    ret->set_name("read");
#endif
    return true;
  } else if (info->op == __dfsan::Load) {
    ret->set_kind(rgd::Read);
    ret->set_bits(info->l2 * 8);
    ret->set_label(label);
    uint64_t offset = get_label_info(info->l1)->op1.i;
    if (unlikely(offset + info->l2 > buf_size)) {
      WARNF("invalid offset: %lu + %u > %lu\n", offset, info->l2, buf_size);
      return false;
    }
    ret->set_index(offset);
    // map arg
    uint32_t hash = map_arg(buf, offset, info->l2, constraint);
    ret->set_hash(hash);
#if NEED_OFFLINE
    std::string val;
    rgd::buf_to_hex_string(&buf[offset], info->l2, val);
    ret->set_value(std::move(val));
    ret->set_name("read");
#endif
    return true;
  } else if (info->op == __dfsan::fmemcmp) {
    rgd::AstNode *s1 = ret->add_children();
    if (unlikely(s1 == nullptr)) {
      WARNF("failed to add children\n");
      return false;
    }
    if (info->l1 >= CONST_OFFSET) {
      if (!do_uta_rel(info->l1, s1, buf, buf_size, constraint, visited)) {
        return false;
      }
      visited.insert(info->l1);
    } else {
      // s1 is a constant array
      s1->set_kind(rgd::Constant);
      s1->set_bits(info->size * 8);
      s1->set_label(0);
      // use constant args to pass the array
      auto itr = memcmp_cache.find(label);
      if (unlikely(itr == memcmp_cache.end())) {
        WARNF("memcmp target not found for label %u\n", label);
        return false;
      }
      uint32_t arg_index = (uint32_t)constraint->input_args.size();
      s1->set_index(arg_index);
      uint16_t chunks = info->size / 8;
      uint16_t remain = info->size % 8;
      uint64_t val = 0;
      for (uint16_t i = 0; i < chunks; i++) {
        val = *(uint64_t*)&(itr->second.get()[i * 8]);
        constraint->input_args.push_back(std::make_pair(false, val));
        constraint->const_num += 1;
        DEBUGF("memcmp constant chunk %d = 0x%lx\n", i, val);
      }
      if (remain) {
        val = 0;
        for (uint16_t i = 0; i < remain; i++) {
          val |= (uint64_t)itr->second.get()[chunks * 8 + i] << (i * 8);
        }
        constraint->input_args.push_back(std::make_pair(false, val));
        constraint->const_num += 1;
        DEBUGF("memcmp constant remain = %lu\n", val);
      }
      uint32_t hash = rgd::xxhash(info->size, rgd::Constant, arg_index);
      s1->set_hash(hash);
#if NEED_OFFLINE
      std::string val;
      rgd::buf_to_hex_string(itr->second, info->size, val);
      ret->set_value(std::move(val));
      ret->set_name("constant");
#endif
    }
    rgd::AstNode *s2 = ret->add_children();
    if (unlikely(s2 == nullptr)) {
      WARNF("failed to add children\n");
      return false;
    }
    if (!do_uta_rel(info->l2, s2, buf, buf_size, constraint, visited)) {
      return false;
    }
    visited.insert(info->l2);
    ret->set_kind(rgd::Memcmp);
    ret->set_bits(1);
    ret->set_label(label);
    uint32_t hash = rgd::xxhash(s1->hash(), rgd::Memcmp, s2->hash());
    ret->set_hash(hash);
#if NEED_OFFLINE
    ret->set_name("memcmp");
#endif
    return true;
  } else if (info->op == __dfsan::fatoi) {
    if (unlikely(info->l1 != 0 || info->l2 < CONST_OFFSET)) {
      WARNF("invalid atoi label %u\n", label);
      return false;
    }
    dfsan_label_info *src = get_label_info(info->l2);
    if (unlikely(src->op != Load)) {
      WARNF("invalid atoi source label %u, op = %u\n", info->l2, src->op);
      return false;
    }
    visited.insert(info->l2);
    uint64_t offset = get_label_info(src->l1)->op1.i;
    if (unlikely(offset >= buf_size)) {
      WARNF("invalid offset: %lu >= %lu\n", offset, buf_size);
      return false;
    }
    ret->set_bits(info->size);
    ret->set_label(label);
    ret->set_index(offset);
    // special handling for atoi, we are introducing the result/output of
    // atoi as fake inputs, and solve constraints over the output,
    // once solved, we convert it back to string
    // however, because the input is fake, we need to map it specially
    ret->set_kind(rgd::Read);
    auto itr = constraint->local_map.find(offset);
    if (itr != constraint->local_map.end()) {
      WARNF("atoi inputs should not be involved in other constraints\n");
      return false;
    }
    uint32_t hash = 0;
    uint32_t length = info->size / 8; // bits to bytes
    // record the offset, base, and original length
    constraint->atoi_info[offset] = std::make_tuple(length, (uint32_t)info->op1.i, (uint32_t)info->op2.i);
    for (uint32_t i = 0; i < length; ++i, ++offset) {
      u8 val = 0; // XXX: use 0 as initial value?
      // because this is fake input, we always map it to a new index
      uint32_t arg_index = (uint32_t)constraint->input_args.size();
      constraint->inputs.insert({offset, val});
      constraint->local_map[offset] = arg_index;
      constraint->input_args.push_back(std::make_pair(true, 0)); // 0 is to be filled in the aggragation
      if (i == 0) {
        constraint->shapes[offset] = length;
        // from solver's perspective, atoi and read are the same
        // they both introduce a new symbolic input as arg_index
        hash = rgd::xxhash(length * 8, rgd::Read, arg_index);
      } else {
        constraint->shapes[offset] = 0;
      }
    }
    ret->set_hash(hash);
#if NEED_OFFLINE
    ret->set_name("atoi");
#endif
    return true;
  }

  // common ops, make sure no special ops
  auto op_itr = OP_MAP.find(info->op);
  if (op_itr == OP_MAP.end()) {
    WARNF("invalid op: %u\n", info->op);
    return false;
  }
  ret->set_kind(op_itr->second.first);
  ret->set_bits(info->size);
  ret->set_label(label);
#if NEED_OFFLINE
  ret->set_name(op_itr->second.second);
#endif

  // record op
  constraint->ops[ret->kind()] = true;

  // in case we needs concretization
  uint8_t needs_concretization = 0;
  auto node_itr = concretize_node.find(label);
  if (node_itr != concretize_node.end()) {
    needs_concretization = node_itr->second;
  }

  // now we visit the children
  rgd::AstNode *left = ret->add_children();
  if (unlikely(left == nullptr)) {
    WARNF("failed to add children\n");
    return false;
  }
  if (likely(needs_concretization != 1) && (info->l1 >= CONST_OFFSET)) {
    if (!do_uta_rel(info->l1, left, buf, buf_size, constraint, visited)) {
      return false;
    }
    visited.insert(info->l1);
  } else {
    if (unlikely(needs_concretization)) {
      if (unlikely(!rgd::isRelationalKind(ret->kind()))) {
        WARNF("invalid kind for concretization %u\n", ret->kind());
        return false;
      }
    }
    // constant
    left->set_kind(rgd::Constant);
    left->set_label(0);
    uint32_t size = info->size;
    // size of concat the sum of the two operands
    // to get the size of the constant, we need to subtract the size
    // of the other operand
    if (info->op == __dfsan::Concat) {
      if (unlikely(info->l2 == 0)) {
        WARNF("invalid concat node %u\n", info->l2);
        return false;
      }
      size -= get_label_info(info->l2)->size;
    }
    left->set_bits(size);
    // map args
    uint32_t arg_index = (uint32_t)constraint->input_args.size();
    left->set_index(arg_index);
    constraint->input_args.push_back(std::make_pair(false, info->op1.i));
    constraint->const_num += 1;
    uint32_t hash = rgd::xxhash(size, rgd::Constant, arg_index);
    left->set_hash(hash);
#if NEED_OFFLINE
    left->set_value(std::to_string(info->op1.i));
    left->set_name("constant");
#endif
  }
  
  // unary ops
  if (info->op == __dfsan::ZExt || info->op == __dfsan::SExt ||
      info->op == __dfsan::Extract || info->op == __dfsan::Trunc) {
    uint32_t hash = rgd::xxhash(info->size, ret->kind(), left->hash());
    ret->set_hash(hash);
    uint64_t offset = info->op == __dfsan::Extract ? info->op2.i : 0;
    ret->set_index(offset);
    return true;
  }

  rgd::AstNode *right = ret->add_children();
  if (unlikely(right == nullptr)) {
    WARNF("failed to add children\n");
    return false;
  }
  if (likely(needs_concretization != 2) && (info->l2 >= CONST_OFFSET)) {
    if (!do_uta_rel(info->l2, right, buf, buf_size, constraint, visited)) {
      return false;
    }
    visited.insert(info->l2);
  } else {
    if (unlikely(needs_concretization)) {
      if (unlikely(!rgd::isRelationalKind(ret->kind()))) {
        WARNF("invalid kind for concretization %u\n", ret->kind());
        return false;
      }
    }
    // constant
    right->set_kind(rgd::Constant);
    right->set_label(0);
    uint32_t size = info->size;
    // size of concat the sum of the two operands
    // to get the size of the constant, we need to subtract the size
    // of the other operand
    if (info->op == __dfsan::Concat) {
      if (unlikely(info->l1 == 0)) {
        WARNF("invalid concat node %u\n", info->l1);
        return false;
      }
      size -= get_label_info(info->l1)->size;
    }
    right->set_bits(size);
    // map args
    uint32_t arg_index = (uint32_t)constraint->input_args.size();
    right->set_index(arg_index);
    constraint->input_args.push_back(std::make_pair(false, info->op2.i));
    constraint->const_num += 1;
    uint32_t hash = rgd::xxhash(size, rgd::Constant, arg_index);
    right->set_hash(hash);
#if NEED_OFFLINE
    right->set_value(std::to_string(info->op1.i));
    right->set_name("constant");
#endif
  }

  // record comparison operands
  if (rgd::isRelationalKind(ret->kind())) {
    constraint->op1 = info->op1.i;
    constraint->op2 = info->op2.i;
  }

  // binary ops, we don't really care about comparison ops in jigsaw,
  // as long as the operands are the same, we can reuse the AST/function
  uint32_t kind = rgd::isRelationalKind(ret->kind()) ? rgd::Bool : ret->kind();
  uint32_t hash = rgd::xxhash(left->hash(), (kind << 16) | ret->bits(), right->hash());
  ret->set_hash(hash);

  return true;
}

[[nodiscard]] [[gnu::hot]]
static constraint_t
parse_constraint(dfsan_label label, const u8 *buf, size_t buf_size) {
  DEBUGF("constructing constraint for label %u\n", label);
  // make sure root is a comparison node
  // XXX: root should never go oob?
  dfsan_label_info *info = get_label_info(label);
  if (unlikely(((info->op & 0xff) != __dfsan::ICmp) && (info->op != __dfsan::fmemcmp))) {
    WARNF("invalid root node %u, non-comparison root op: %u\n", label, info->op);
    return nullptr;
  }

  // retrieve the ast size
  if (unlikely(ast_size_cache.size() <= label)) {
    WARNF("invalid label %u, larger than ast_size_cache: %lu\n", label, ast_size_cache.size());
    return nullptr;
  }
  auto size = ast_size_cache.at(label);
  if (unlikely(size == 0)) {
    WARNF("invalid label %u, ast_size_cache is 0\n", label);
    return nullptr;
  }
  std::unordered_set<dfsan_label> visited;
  try {
    constraint_t constraint = std::make_shared<rgd::Constraint>(size);
    if (!do_uta_rel(label, constraint->ast.get(), buf, buf_size, constraint, visited)) {
      return nullptr;
    }
    return constraint;
  } catch (std::bad_alloc &e) {
    WARNF("failed to allocate memory for constraint\n");
    return nullptr;
  } catch (std::out_of_range &e) {
    WARNF("AST %u goes out of range at %s\n", label, e.what());
    return nullptr;
  }
}

[[nodiscard]] [[gnu::hot]]
static task_t construct_task(std::vector<const rgd::AstNode*> clause,
                             const u8 *buf, size_t buf_size) {
  task_t task = std::make_shared<rgd::SearchTask>();
  for (auto const& node: clause) {
    auto itr = constraint_cache.find(node->label());
    if (itr != constraint_cache.end()) {
      task->constraints.push_back(itr->second);
      task->comparisons.push_back(node->kind());
      continue;
    }
    // save the comparison op because we may have negated it
    // during transformation
    constraint_t constraint = parse_constraint(node->label(), buf, buf_size);
    // to maximize the resuability of the AST, the relational operator
    // is recorded elsewhere
    if (likely(constraint != nullptr)) {
      task->constraints.push_back(constraint);
      task->comparisons.push_back(node->kind());
      constraint_cache.insert({node->label(), constraint});
    }
  }
  if (!task->constraints.empty()) {
    task->finalize();
    return task;
  }
  return nullptr;
}

// sometimes llvm will zext bool
static dfsan_label strip_zext(dfsan_label label) {
  dfsan_label_info *info = get_label_info(label);
  while (info->op == __dfsan::ZExt) {
    dfsan_label child = info->l1;
    info = get_label_info(child);
    if (info->size == 1) {
      // extending a boolean value
      return child;
    } else if ((info->op & 0xff) == __dfsan::ICmp || info->op == __dfsan::fmemcmp) {
      // extending the result of icmp or memcmp
      return child;
    }
  }
  return label;
}

[[nodiscard]] [[gnu::hot]]
static int find_roots(dfsan_label label, rgd::AstNode *ret,
                      std::unordered_set<dfsan_label> &subroots) {
  if (label < CONST_OFFSET || label == kInitializingLabel) {
    WARNF("invalid label: %d\n", label);
    return INVALID_NODE;
  }

  std::vector<dfsan_label> stack;
  dfsan_label root = label;
  dfsan_label prev = 0;
  std::vector<rgd::AstNode*> node_stack;
  rgd::AstNode *root_node = ret;
  std::unordered_set<dfsan_label> visited;

  try {
  while (root != 0 || !stack.empty()) {
    if (root != 0) {
      // check if the node has been visited before
      if (visited.find(root) != visited.end()) {
        // already visited, skip the subtree
        prev = root;
        root = 0;
        continue;
      }
      // mark to be visit in the future, for in-order and post-order visitors
      stack.push_back(root);
      node_stack.push_back(root_node);
      auto *info = get_label_info(root);
      if (nested_cmp_cache[info->l1] == 0) {
        // no nested comparison in the left child, stop going down
        // again, we only collect a partial AST with comparison nodes as leafs
        // so the traversal should stop before reaching any actual leaf node
        root = 0;
      } else {
        root = strip_zext(info->l1);
        if (root) {
          // create a child node before going down
          root_node = root_node->add_children();
          if (unlikely(root_node == nullptr)) {
            WARNF("failed to add children\n");
            return INVALID_NODE;
          }
        }
      }
    } else {
      // we have reached some leaf node, going up the tree
      auto curr = stack.back();
      auto info = get_label_info(curr);
      auto zsl2 = strip_zext(info->l2);
      if (nested_cmp_cache[zsl2] > 0 && prev != zsl2) {
        // we have a right child, and we haven't visited it yet,
        // and there is a nested comparison, going down the right tree
        root = zsl2;
        root_node = node_stack.back()->add_children();
        if (unlikely(root_node == nullptr)) {
          WARNF("failed to add children\n");
          return INVALID_NODE;
        }
      } else {
        DEBUGF("label %d, l1 %d, l2 %d, op %d, size %d, op1 %ld, op2 %ld\n",
               curr, info->l1, info->l2, info->op, info->size, info->op1.i, info->op2.i);
        // both children nodes have been visited, process the node (post-order)
        auto node = node_stack.back();

        if (info->op == __dfsan::Not) {
          DEBUGF("simplify not: %d, %d\n", info->l2, info->size);
          if (unlikely(node->children_size() != 1)) {
            WARNF("child node size != 1\n");
            return INVALID_NODE;
          }
          if (unlikely(info->size != 1)) {
            WARNF("info size != 1\n");
            return INVALID_NODE;
          }
          rgd::AstNode *child = node->mutable_children(0);
          node->set_bits(1);
          if (child->kind() == rgd::Bool) {
            node->set_kind(rgd::Bool);
            node->set_boolvalue(!child->boolvalue());
            node->clear_children();
          } else {
            node->set_kind(rgd::LNot);
          }
        } else if (info->op == __dfsan::And) {
          // if And apprears, it must be LAnd, try to simplify
          DEBUGF("simplify land: %d LAnd %d, %d\n", info->l1, info->l2, info->size);
          if (unlikely(node->children_size() == 0)) {
            WARNF("child node size == 0\n");
            return INVALID_NODE;
          }
          if (unlikely(info->size != 1)) {
            WARNF("info size != 1\n");
            return INVALID_NODE;
          }
          uint32_t child = 0;
          rgd::AstNode *left = nullptr;
          rgd::AstNode *right = nullptr;
          if (nested_cmp_cache[info->l1] > 0) {
            left = node->mutable_children(0);
            child = 1; // if left child exists, rhs will be child 1
          }
          if (nested_cmp_cache[info->l2] > 0) {
            right = node->mutable_children(child);
          }
          node->set_bits(1);

          if (unlikely(info->l1 == 0)) {
            // lhs is a constant
            if (info->op1.i == 0) { // 0 LAnd x = 0
              node->set_kind(rgd::Bool);
              node->set_boolvalue(0);
              node->clear_children();
            } else if (info->op1.i == 1) { // 1 LAnd x = x
              if (unlikely(right == nullptr)) {
                WARNF("right child is null\n");
                return INVALID_NODE;
              }
              node->CopyFrom(*right);
            } else {
              WARNF("invalid constant %ld\n", info->op1.i);
              return INVALID_NODE;
            }
          } else {
            if (unlikely(left == nullptr)) {
              WARNF("left child is null\n");
              return INVALID_NODE;
            }
            if (unlikely(right == nullptr)) {
              WARNF("right child is null\n");
              return INVALID_NODE;
            }
            // check for constant
            if (left->kind() == rgd::Bool) {
              if (left->boolvalue() == 0) { // 0 LAnd x = 0
                node->set_kind(rgd::Bool);
                node->set_boolvalue(0);
                node->clear_children();
              } else if (right->kind() == rgd::Bool) {
                // both lhs and rhs are constants
                node->set_kind(rgd::Bool);
                node->set_boolvalue(right->boolvalue()); // 1 LAnd b = b
                node->clear_children();
              } else { // 1 LAnd x = x
                // lhs is 1, rhs is not
                node->CopyFrom(*right);
              }
            } else if (right->kind() == rgd::Bool) {
              // lhs is not a constant, check rhs
              if (right->boolvalue() == 0) { // x LAnd 0 = 0
                node->set_kind(rgd::Bool);
                node->set_boolvalue(0);
                node->clear_children();
              } else { // x LAnd 1 = x
                // rhs is 1, lhs is not
                node->CopyFrom(*left);
              }
            } else {
              // both sides are symbolic
              node->set_kind(rgd::LAnd);
            }
          }
        } else if (info->op == __dfsan::Or) {
          DEBUGF("simplify lor: %d LOr %d, %d\n", info->l1, info->l2, info->size);
          if (unlikely(node->children_size() == 0)) {
            WARNF("child node size == 0\n");
            return INVALID_NODE;
          }
          if (unlikely(info->size != 1)) {
            WARNF("info size != 1\n");
            return INVALID_NODE;
          }
          uint32_t child = 0;
          rgd::AstNode *left = nullptr;
          rgd::AstNode *right = nullptr;
          if (nested_cmp_cache[info->l1] > 0) {
            left = node->mutable_children(0);
            child = 1; // if left child exists, rhs will be child 1
          }
          if (nested_cmp_cache[info->l2] > 0) {
            right = node->mutable_children(child);
          }
          node->set_bits(1);

          if (unlikely(info->l1 == 0)) {
            // lhs is a constant
            if (info->op1.i == 1) { // x LOr 1 = 1
              node->set_kind(rgd::Bool);
              node->set_boolvalue(1);
              node->clear_children();
            } else if (info->op1.i == 0) { // 0 LOr x = x
              if (unlikely(right == nullptr)) {
                WARNF("right child is null\n");
                return INVALID_NODE;
              }
              node->CopyFrom(*right);
            } else {
              WARNF("invalid constant %ld\n", info->op1.i);
              return INVALID_NODE;
            }
          } else {
            if (unlikely(left == nullptr)) {
              WARNF("left child is null\n");
              return INVALID_NODE;
            }
            if (unlikely(right == nullptr)) {
              WARNF("right child is null\n");
              return INVALID_NODE;
            }
            // check for constant
            if (left->kind() == rgd::Bool) {
              if (left->boolvalue() == 1) { // 1 LOr x = 1
                node->set_kind(rgd::Bool);
                node->set_boolvalue(1);
                node->clear_children();
              } else if (right->kind() == rgd::Bool) {
                // both lhs and rhs are constants
                node->set_kind(rgd::Bool);
                node->set_boolvalue(right->boolvalue()); // 0 LOr b = b
                node->clear_children();
              } else { // 0 LOr x = x
                // lhs is 0, rhs is not
                node->CopyFrom(*right);
              }
            } else if (right->kind() == rgd::Bool) {
              if (right->boolvalue() == 1) { // x LOr 1 = 1
                node->set_kind(rgd::Bool);
                node->set_boolvalue(1);
                node->clear_children();
              } else { // x LOr 0 = x
                // rhs is 0, lhs is not
                node->CopyFrom(*left);
              }
            } else {
              // both sides are symbolic
              node->set_kind(rgd::LOr);
            }
          }
        } else if (info->op == __dfsan::Xor) {
          DEBUGF("simplify lxor: %d LXOr %d, %d\n", info->l1, info->l2, info->size);
          if (unlikely(node->children_size() == 0)) {
            WARNF("child node size == 0\n");
            return INVALID_NODE;
          }
          if (unlikely(info->size != 1)) {
            WARNF("info size != 1\n");
            return INVALID_NODE;
          }
          uint32_t child = 0;
          rgd::AstNode *left = nullptr;
          rgd::AstNode *right = nullptr;
          if (nested_cmp_cache[info->l1] > 0) {
            left = node->mutable_children(0);
            child = 1; // if left child exists, rhs will be child 1
          }
          if (nested_cmp_cache[info->l2] > 0) {
            right = node->mutable_children(child);
          }
          node->set_bits(1);

          if (likely(info->l1 == 0)) {
            // lhs is a constant
            if (unlikely(right == nullptr)) {
              WARNF("right child is null\n");
              return INVALID_NODE;
            }
            if (unlikely(right->kind() == rgd::Bool)) {
              // rhs is a constant
              node->set_kind(rgd::Bool);
              node->set_boolvalue(right->boolvalue() ^ (uint32_t)info->op1.i);
              node->clear_children();
            } else {
              // rhs is symbolic
              if (info->op1.i == 1) { // 1 LXor x = LNot x
                node->set_kind(rgd::LNot);
              } else { // 0 LXor x = x
                node->CopyFrom(*right);
              }
            }
          } else {
            if (unlikely(left == nullptr)) {
              WARNF("left child is null\n");
              return INVALID_NODE;
            }
            if (unlikely(right == nullptr)) {
              WARNF("right child is null\n");
              return INVALID_NODE;
            }
            // check for constant
            if (unlikely(left->kind() == rgd::Bool)) {
              if (unlikely(right->kind() == rgd::Bool)) {
                // both lhs and rhs are constants
                node->set_kind(rgd::Bool);
                node->set_boolvalue(right->boolvalue() ^ left->boolvalue());
                node->clear_children();
              } else if (left->boolvalue() == 0) { // 0 LXor x = x
                node->CopyFrom(*right);
              } else { // 1 LXor x = LNot x
                node->set_kind(rgd::LNot);
              }
            } else if (unlikely(right->kind() == rgd::Bool)) {
              // rhs is constant, lhs is not
              if (right->boolvalue() == 0) { // x LXor 0 = x
                node->CopyFrom(*left);
              } else { // x LXor 1 = LNot x
                node->set_kind(rgd::LNot);
              }
            } else {
              // both sides are symbolic
              node->set_kind(rgd::Xor);
            }
          }
        } else if ((info->op & 0xff) == __dfsan::ICmp) {
          // cmp node
          node->set_bits(1);
          if (likely(node->children_size() == 0)) {
            // if the node has no children, it's a leaf node
            // check size, concretize if too large
            auto size = ast_size_cache.at(curr);
            // load previous value as previous concretization could have
            // changed the ast size used for allocation
            auto itr = concretize_node.find(curr);
            uint8_t concretize = itr != concretize_node.end() ? itr->second : 0;
            if (size > MAX_AST_SIZE) {
              DEBUGF("AST size too large: %d = %u\n", curr, size);
              auto left_size = ast_size_cache.at(info->l1);
              auto right_size = ast_size_cache.at(info->l2);
              if (left_size > MAX_AST_SIZE) {
                // concretize left
                concretize |= 1;
                // update new size
                size -= (left_size - 1);
              }
              if (right_size > MAX_AST_SIZE) {
                // concretize right
                concretize |= 2;
                // update new size
                size -= (right_size - 1);
              }
              DEBUGF("new size: %d = %u\n", curr, size);
              ast_size_cache[curr] = size;
              concretize_node[curr] = concretize;
            }

            // check for concrete ops
            uint8_t concrete_ops = concretize;
            concrete_ops |= info->l1 == 0 ? 1 : 0;
            concrete_ops |= info->l2 == 0 ? 2 : 0;
            if (concrete_ops == 3) {
              // well, both sides have been concretized, simplify the node
              node->set_kind(rgd::Bool);
              node->set_boolvalue(eval_icmp(info->op, info->op1.i, info->op2.i));
            } else {
              auto itr = OP_MAP.find(info->op);
              if (unlikely(itr == OP_MAP.end())) {
                WARNF("invalid icmp op: %d\n", info->op);
                return INVALID_NODE;
              }
              node->set_kind(itr->second.first);
              node->set_label(curr);
#ifdef DEBUG
              subroots.insert(curr);
#endif
            }
          } else if (node->children_size() == 1) {
            // one side has another icmp, must be simplifiable
            if (!is_rel_cmp(info->op, __dfsan::bveq) && !is_rel_cmp(info->op, __dfsan::bvneq)) {
              WARNF("unexpected icmp: %d\n", info->op);
              // unexpected icmp, set as a constant boolean
              node->set_kind(rgd::Bool);
              node->set_boolvalue(eval_icmp(info->op, info->op1.i, info->op2.i));
            } else {
              if (nested_cmp_cache[info->l1]) {
                // nested icmp in the lhs
                rgd::AstNode *left = node->mutable_children(0);
                if (unlikely(left->bits() != 1)) {
                  WARNF("nested icmp lhs bits != 1\n");
                  return INVALID_NODE;
                }
                if (likely(info->l2 == 0)) {
                  if (is_rel_cmp(info->op, __dfsan::bveq)) {
                    if (info->op2.i == 1) { // checking bool == true
                      node->CopyFrom(*left);
                    } else { // checking bool == false
                      node->set_kind(rgd::LNot);
                    }
                  } else { // bvneq
                    if (info->op2.i == 0) { // checking bool != false
                      node->CopyFrom(*left);
                    } else { // checking bool != true
                      node->set_kind(rgd::LNot);
                    }
                  }
                } else {
                  // l2 != 0, bool icmp bool ?!
                  WARNF("bool icmp bool ?!\n");
                  node->set_kind(rgd::Bool);
                  node->set_boolvalue(0);
                  node->clear_children();
                }
              } else if (nested_cmp_cache[info->l2] > 0) {
                // nested icmp in the rhs
                rgd::AstNode *right = node->mutable_children(0);
                if (unlikely(right->bits() != 1)) {
                  WARNF("nested icmp rhs bits != 1\n");
                  return INVALID_NODE;
                }
                if (likely(info->l1 == 0)) {
                  if (is_rel_cmp(info->op, __dfsan::bveq)) {
                    if (info->op1.i == 1) { // checking true == bool
                      node->CopyFrom(*right);
                    } else { // checking false == bool
                      node->set_kind(rgd::LNot);
                    }
                  } else { // bvneq
                    if (info->op1.i == 0) { // checking false != bool
                      node->CopyFrom(*right);
                    } else { // checking true != bool
                      node->set_kind(rgd::LNot);
                    }
                  }
                } else {
                  // l1 != 0, bool icmp bool ?!
                  WARNF("bool icmp bool ?!\n");
                  node->set_kind(rgd::Bool);
                  node->set_boolvalue(0);
                  node->clear_children();
                }
              } else {
                WARNF("icmp with child yet no nested icmp?!\n");
                return INVALID_NODE;
              }
            }
          } else {
            // both sides have another icmp, set as a constant boolean
            node->set_kind(rgd::Bool);
            node->set_boolvalue(eval_icmp(info->op, info->op1.i, info->op2.i));
            node->clear_children();
          }
        } else if (info->op == __dfsan::fmemcmp) {
          // memcmp is also considered as a root node (relational comparison)
          if (unlikely(node->children_size() != 0)) {
            WARNF("memcmp should not have additional icmp");
            return INVALID_NODE;
          }
          node->set_bits(1); // XXX: treat memcmp as a boolean
          node->set_kind(rgd::Memcmp); // fix later
          node->set_label(curr);
#ifdef DEBUG
          subroots.insert(curr);
#endif
        } else {
          WARNF("Invalid AST node: op = %d\n", info->op);
          return INVALID_NODE;
        }

        // mark as visited and pop from stack
        visited.insert(curr);
        prev = curr;
        stack.pop_back();
        node_stack.pop_back();
      }
    }
  }
  } catch (std::out_of_range &e) {
    WARNF("AST %u goes out of range at %s\n", label, e.what());
    return INVALID_NODE;
  }

  return 0;
}

static void printAst(const rgd::AstNode *node, int indent) {
  fprintf(stderr, "(%s, ", rgd::AstKindName[node->kind()]);
  fprintf(stderr, "%d, ", node->label());
  fprintf(stderr, "%d, ", node->bits());
  for(int i = 0; i < node->children_size(); i++) {
    printAst(&node->children(i), indent + 1);
    if (i != node->children_size() - 1) {
      fprintf(stderr, ", ");
    }
  }
  fprintf(stderr, ")");
}

[[nodiscard]]
static int to_nnf(bool expected_r, rgd::AstNode *node) {
  int ret = 0;
  if (!expected_r) {
    // we're looking for a negated formula
    if (node->kind() == rgd::LNot) {
      // double negation
      if (unlikely(node->children_size() != 1)) {
        WARNF("LNot expect a singple child\n");
        return INVALID_NODE;
      }
      rgd::AstNode *child = node->mutable_children(0);
      // transform the child, now looking for a true formula
      ret = to_nnf(true, child);
      if (unlikely(ret != 0)) { return ret; }
      node->CopyFrom(*child);
    } else if (node->kind() == rgd::LAnd) {
      // De Morgan's law
      if (unlikely(node->children_size() != 2)) {
        WARNF("LAnd expect two children\n");
        return INVALID_NODE;
      }
      node->set_kind(rgd::LOr);
      ret = to_nnf(false, node->mutable_children(0));
      if (unlikely(ret != 0)) { return ret; }
      ret = to_nnf(false, node->mutable_children(1));
      if (unlikely(ret != 0)) { return ret; }
    } else if (node->kind() == rgd::LOr) {
      // De Morgan's law
      if (unlikely(node->children_size() != 2)) {
        WARNF("LOr expect two children\n");
        return INVALID_NODE;
      }
      node->set_kind(rgd::LAnd);
      ret = to_nnf(false, node->mutable_children(0));
      if (unlikely(ret != 0)) { return ret; }
      ret = to_nnf(false, node->mutable_children(1));
      if (unlikely(ret != 0)) { return ret; }
    } else {
      // leaf node
      if (rgd::isRelationalKind(node->kind())) {
        node->set_kind(rgd::negate_cmp(node->kind()));
      } else if (node->kind() == rgd::Memcmp) {
        // memcmp is also considered as a leaf node (relational comparison)
        // memcmp == 0 actually means s1 == s2
        // so we don't need to negate it
      } else {
        WARNF("Unexpected node kind %d\n", node->kind());
        return INVALID_NODE;
      }
    }
  } else {
    // we're looking for a true formula
    if (node->kind() == rgd::LNot) {
      if (unlikely(node->children_size() != 1)) {
        WARNF("LNot expect a singple child\n");
        return INVALID_NODE;
      }
      rgd::AstNode *child = node->mutable_children(0);
      // negate the child, now looking for a false formula
      ret = to_nnf(false, child);
      if (unlikely(ret != 0)) { return ret; }
      node->CopyFrom(*child);
    } else if (node->kind() == rgd::Memcmp) {
      // memcmp is also considered as a leaf node (relational comparison)
      // memcmp == 1 actually means s1 != s2
      // so we negate it
      node->set_kind(rgd::MemcmpN);
    } else {
      for (int i = 0; i < node->children_size(); i++) {
        ret = to_nnf(expected_r, node->mutable_children(i));
        if (unlikely(ret != 0)) { return ret; }
      }
    }
  }

  return 0;
}

using formula_t = std::vector<std::vector<const rgd::AstNode*> > ;

static void to_dnf(const rgd::AstNode *node, formula_t &formula) {
  if (node->kind() == rgd::LAnd) {
    formula_t left, right;
    to_dnf(&node->children(0), left);
    to_dnf(&node->children(1), right);
    for (auto const& sub1: left) {
      for (auto const& sub2: right) {
        std::vector<const rgd::AstNode*> clause;
        clause.insert(clause.end(), sub1.begin(), sub1.end());
        clause.insert(clause.end(), sub2.begin(), sub2.end());
        formula.push_back(clause);
      }
    }
    if (left.size() == 0) {
      formula = right;
    }
  } else if (node->kind() == rgd::LOr) {
    // copy the clauses from the children
    to_dnf(&node->children(0), formula);
    to_dnf(&node->children(1), formula);
  } else {
    std::vector<const rgd::AstNode*> clause;
    clause.push_back(node);
    formula.push_back(clause);
  }
}

[[nodiscard]]
static bool scan_labels(dfsan_label label, size_t buf_size) {
  // assuming label has been checked by caller
  // assuming the last label scanned is the size of the cache
  // turns out linear scan is way faster than tree traversal
  for (size_t i = ast_size_cache.size(); i <= label; i++) {
    if (i == 0) { // the constant label
      ast_size_cache.push_back(1); // constant takes one node too
      branch_to_inputs.emplace_back(input_dep_t(buf_size));
      nested_cmp_cache.push_back(0);
      continue;
    }
    dfsan_label_info *info = get_label_info(i);
    if (info->op == 0) {
      // AST nodes
      ast_size_cache.push_back(1); // one Read node
      // input deps
      branch_to_inputs.emplace_back(input_dep_t(buf_size));
      // skip if invalid
      if (unlikely(info->op1.i >= buf_size)) {
        WARNF("invalid input offset: %lu\n", info->op1.i);
        return false;
      }
      auto &itr = branch_to_inputs[i];
      itr.set(info->op1.i); // input offset
#if DEBUG
      assert(branch_to_inputs[i].find_first() == info->op1.i);
#endif
      // nested cmp?
      nested_cmp_cache.push_back(0);
    } else if (info->op == __dfsan::Load) {
      // AST nodes
      ast_size_cache.push_back(1); // one Read node
      // input deps
      branch_to_inputs.emplace_back(input_dep_t(buf_size));
      auto &itr = branch_to_inputs[i];
      auto offset = get_label_info(info->l1)->op1.i;
      // skip if invalid
      if (unlikely(offset + info->l2 > buf_size)) {
        WARNF("invalid input offset: %lu + %u > %lu\n", offset, info->l2, buf_size);
        return false;
      }
      for (size_t n = 0; n < info->l2; ++n) {
        // DEBUGF("adding input: %lu <- %lu\n", i, offset + n);
        itr.set(offset + n); // input offsets
      }
#if DEBUG
      if (likely(info->l2 > 0))
        assert(branch_to_inputs[i].find_first() == offset);
#endif
      // nested cmp?
      nested_cmp_cache.push_back(0);
    } else {
      // AST nodes
      uint32_t left  = info->l1 == 0? 1 : ast_size_cache[info->l1];
      uint32_t right = info->l2 == 0? 1 : ast_size_cache[info->l2];
      ast_size_cache.push_back(left + right + 1);
      // input deps
      branch_to_inputs.emplace_back(input_dep_t(buf_size));
      auto &itr = branch_to_inputs[i];
      if (info->l1 != 0) itr |= branch_to_inputs[info->l1];
      if (info->l2 != 0) itr |= branch_to_inputs[info->l2];
      // nested cmp?
      uint8_t nested = 0;
      nested += info->l1 == 0? 0 : nested_cmp_cache[info->l1];
      nested += info->l2 == 0? 0 : nested_cmp_cache[info->l2];
      if (info->op == __dfsan::fmemcmp || (info->op & 0xff) == __dfsan::ICmp)
        nested += 1;
      nested_cmp_cache.push_back(nested);
    }
  }
#if DEBUG
  DEBUGF("ast_size: %d = %u\n", label, ast_size_cache[label]);
  DEBUGF("input deps %d:", label);
  auto &itr = branch_to_inputs[label];
  for (auto i = itr.find_first(); i != input_dep_t::npos; i = itr.find_next(i)) {
    DEBUGF("%lu ", i);
  }
  DEBUGF("\n");
  DEBUGF("nested cmp: %d = %d\n", label, nested_cmp_cache[label]);
#endif
  return true;
}

[[nodiscard]]
static inline expr_t get_root_expr(dfsan_label label, size_t buf_size) {
  if (label < CONST_OFFSET || label == kInitializingLabel || label >= MAX_LABEL) {
    WARNF("invalid label: %d\n", label);
    return nullptr;
  }

  expr_t root = nullptr;
  auto itr = root_expr_cache.find(label);
  if (itr != root_expr_cache.end()) {
    root = itr->second;
  } else {
    // update ast_size and branch_to_inputs caches
    if (!scan_labels(label, buf_size)) {
      return nullptr;
    }
    root = std::make_shared<rgd::AstNode>();
    std::unordered_set<dfsan_label> subroots;
    // we start by constructing a boolean formula with relational expressions
    // as leaf nodes
    if (find_roots(label, root.get(), subroots) != 0) {
      return nullptr;
    }
    root_expr_cache.insert({label, root});
#if DEBUG
    for (auto const& subroot : subroots) {
      DEBUGF("subroot: %d\n", subroot);
    }
#endif
  }
#if DEBUG
  printAst(root.get(), 0);
  fprintf(stderr, "\n");
#endif
  return root;
}

static bool construct_tasks(bool target_direction, dfsan_label label,
                            const u8 *buf, size_t buf_size,
                            std::vector<task_t> &tasks) {

  // given a condition, we want to parse them into a DNF form of
  // relational sub-expressions, where each sub-expression only contains
  // one relational operator at the root
  expr_t orig_root = get_root_expr(label, buf_size);
  if (orig_root == nullptr || orig_root->kind() == rgd::Bool) {
    // if the simplified formula is a boolean constant, nothing to do
    return false;
  }

  // duplication the original root for transformation
  expr_t root = std::make_shared<rgd::AstNode>();
  root->CopyFrom(*orig_root);

  // next, convert the formula to NNF form, possibly negate the root
  // if we are looking for a false formula
  if (to_nnf(target_direction, root.get()) != 0) {
    return false;
  }
#if DEBUG
  printAst(root.get(), 0);
  fprintf(stderr, "\n");
#endif
  // then we need to convert the boolean formula into a DNF form
  formula_t dnf;
  to_dnf(root.get(), dnf);

  // finally, we construct a search task for each clause in the DNF
  for (auto const& clause : dnf) {
    task_t task = construct_task(clause, buf, buf_size);
    if (task != nullptr) {
      tasks.push_back(task);
    } else {
      continue; // skip the nested task if the current task is invalid
    }

    if (NestedSolving) {
      // collect dependencies based on data-flow (i.e., shared input bytes)
      std::vector<const rgd::AstNode*> nested_caluse;
      std::unordered_set<dfsan_label> inserted;
      // first, copy the last branch constraints
      nested_caluse.insert(nested_caluse.end(), clause.begin(), clause.end());
      for (auto const& var : clause) inserted.insert(var->label());
      bool has_nested = false;
      // then, iterate each var in the clause
      for (auto const& var: clause) {
        const dfsan_label l = var->label();
        assert(branch_to_inputs.size() > l);
        auto &itr = branch_to_inputs[l];
        auto citr = concretize_node.find(l);
        if (unlikely(citr != concretize_node.end())) {
          if (citr->second == 1) {
            // if the lhs is concretized, use the rhs deps only
            itr = branch_to_inputs[get_label_info(l)->l2];
          } else if (citr->second == 2) {
            // if the rhs is concretized, use the lhs deps only
            itr = branch_to_inputs[get_label_info(l)->l1];
          }
        }
        assert(itr.find_first() != input_dep_t::npos);
        // for each input byte used in the var, we collect additional constraints
        // first, we use union find to add additional related input bytes
        std::unordered_set<size_t> related_inputs;
        for (auto input = itr.find_first(); input != input_dep_t::npos;
             input = itr.find_next(input)) {
          data_flow_deps.get_set(input, related_inputs);
        }
        // then, we collect the branch constraints for each related input byte
        for (auto input: related_inputs) {
          auto const& bucket = input_to_branches[input];
          for (auto const& nc : bucket) {
            if (inserted.count(nc->label())) continue;
            inserted.insert(nc->label());
            has_nested = true;
#if DEBUG
            fprintf(stderr, "add nested constraint: (%d, %d)\n", nc->label(), nc->kind());
#endif
            nested_caluse.push_back(nc.get()); // XXX: borrow the raw ptr, should be fine?
          }
        }
      }
      if (has_nested) { // only add nested task if there are additional constraints
        task_t nested_task = construct_task(nested_caluse, buf, buf_size);
        if (nested_task != nullptr) {
          nested_task->base_task = task;
          tasks.push_back(nested_task);
        }
      }
    }
  }

  return true;
}

static bool add_data_flow_constraints(bool direction, dfsan_label label,
                                      const u8 *buf, size_t buf_size) {
  // similar to solving tasks, we parse the original branch constraint
  // into a DNF form of relational sub-expressions, where each sub-expression
  // only contains one relational operator at the root
  expr_t orig_root = get_root_expr(label, buf_size);
  if (orig_root == nullptr || orig_root->kind() == rgd::Bool) {
    // if the simplified formula is a boolean constant, nothing to do
    return false;
  }

  // duplication the original root for transformation
  expr_t root = std::make_shared<rgd::AstNode>();
  root->CopyFrom(*orig_root);

  // next, convert the formula to NNF form, possibly negate the root
  // if we are looking for a false formula
  if (to_nnf(direction, root.get()) != 0) {
    return false;
  }
#if DEBUG
  printAst(root.get(), 0);
  fprintf(stderr, "\n");
#endif
  // then we need to convert the boolean formula into a DNF form
  formula_t dnf;
  to_dnf(root.get(), dnf);

  // now we associate the constraints with input bytes
  for (auto const& clause : dnf) {
    // each clause is a conjunction of relational expressions
    // that need to be evaluated to true (satisfied)
    // we associate that with the corresponding input bytes
    for (auto const& var : clause) {
      // get the input bytes
      expr_t node = std::make_shared<rgd::AstNode>();
      node->CopyFrom(*var);
      const dfsan_label l = node->label();
      assert(branch_to_inputs.size() > l);
      auto &itr = branch_to_inputs[l];
      auto citr = concretize_node.find(l);
      if (unlikely(citr != concretize_node.end())) {
        if (citr->second == 1) {
          // if the lhs is concretized, use the rhs deps only
          itr = branch_to_inputs[get_label_info(l)->l2];
        } else if (citr->second == 2) {
          // if the rhs is concretized, use the lhs deps only
          itr = branch_to_inputs[get_label_info(l)->l1];
        }
      }
      auto root = itr.find_first();
      if (root == input_dep_t::npos) {
        // not actual input dependency, skip
        // this can happen for atoi
        continue;
      }
      // update uion find
      for (auto input = itr.find_next(root); input != input_dep_t::npos;
           input = itr.find_next(input)) {
#if DEBUG
        DEBUGF("union input bytes: (%zu, %zu)\n", root, input);
#endif
        root = data_flow_deps.merge(root, input);
      }
      // add the constraint
      auto &bucket = input_to_branches[root];
      bucket.push_back(node);
      // we need to record the kind as it may be negated during transformation
#if DEBUG
      DEBUGF("add df constraint: %zu <- (%d, %d)\n", root, l, node->kind());
#endif
    }
  }

  return true;
}

static void handle_cond(pipe_msg &msg, const u8 *buf, size_t buf_size,
                        my_mutator_t *my_mutator) {
  if (unlikely(msg.label == 0)) {
    return;
  } else if (unlikely(msg.label == kInitializingLabel)) {
    WARNF("UBI branch cond @%p\n", (void*)msg.addr);
    return;
  }

  total_branches += 1;

  // apply a local (per input) branch filter
  auto &lc = local_counter[msg.id];
  if (lc > MAX_LOCAL_BRANCH_COUNTER) {
    return;
  } else {
    lc += 1;
  }

  const branch_ctx_t ctx = my_mutator->cov_mgr->add_branch((void*)msg.addr,
      msg.id, msg.result != 0, msg.context, false, false);

  branch_ctx_t neg_ctx = std::make_shared<rgd::BranchContext>();
  *neg_ctx = *ctx;
  neg_ctx->direction = !ctx->direction;

  if (my_mutator->cov_mgr->is_branch_interesting(neg_ctx)) {
    // parse the uniont table AST to solving tasks
    std::vector<task_t> tasks;
    construct_tasks(neg_ctx->direction, msg.label, buf, buf_size, tasks);

    // add the tasks to the task manager
    for (auto const& task : tasks) {
      my_mutator->task_mgr->add_task(neg_ctx, task);
#if PRINT_STATS
      task_size_dist[task->constraints.size()] += 1;
#endif
    }

    total_tasks += tasks.size();
    branches_to_solve += 1;
  }

  if (NestedSolving && (msg.flags & F_ADD_CONS)) {
    // add the current branch direction as nested conditions
    add_data_flow_constraints(ctx->direction, msg.label, buf, buf_size);
  }
}

static void handle_gep(gep_msg &gmsg, pipe_msg &msg) {
}

/// no splice input
extern "C" void afl_custom_splice_optout(my_mutator_t *data) {
  (void)(data);
}

/// @brief init the custom mutator
/// @param afl aflpp state
/// @param seed not used
/// @return custom mutator state
extern "C" my_mutator_t *afl_custom_init(afl_state *afl, unsigned int seed) {

  (void)(seed);

  struct stat st;
  rgd::TaskManager *tmgr = new rgd::FIFOTaskManager();
  rgd::CovManager *cmgr = new rgd::EdgeCovManager();
  my_mutator_t *data = new my_mutator_t(afl, tmgr, cmgr);
  if (!data) {
    FATAL("afl_custom_init alloc");
    return NULL;
  }
  // always use the simpler i2s solver
  data->solvers.emplace_back(std::make_shared<rgd::I2SSolver>());
  if (getenv("SYMSAN_USE_JIGSAW"))
    data->solvers.emplace_back(std::make_shared<rgd::JITSolver>());
  if (getenv("SYMSAN_USE_Z3"))
    data->solvers.emplace_back(std::make_shared<rgd::Z3Solver>());
  // make nested solving optional too
  if (getenv("SYMSAN_USE_NESTED")) {
    NestedSolving = true;
  }
  // enable trace bounds?
  if (getenv("SYMSAN_TRACE_BOUNDS")) {
    TraceBounds = 1;
  }

  if (!(data->symsan_bin = getenv("SYMSAN_TARGET"))) {
    FATAL(
        "SYMSAN_TARGET not defined, this should point to the full path of the "
        "symsan compiled binary.");
  }

  if (!(data->out_dir = getenv("SYMSAN_OUTPUT_DIR"))) {
    data->out_dir = alloc_printf("%s/symsan", afl->out_dir);
  }

  if (stat(data->out_dir, &st) && mkdir(data->out_dir, 0755)) {
    PFATAL("Could not create the output directory %s", data->out_dir);
  }

  // setup output file
  char *out_file;
  if (afl->file_extension) {
    out_file = alloc_printf("%s/.cur_input.%s", data->out_dir, afl->file_extension);
  } else {
    out_file = alloc_printf("%s/.cur_input", data->out_dir);
  }
  if (data->out_dir[0] == '/') {
    data->out_file = out_file;
  } else {
    char cwd[PATH_MAX];
    if (getcwd(cwd, (size_t)sizeof(cwd)) == NULL) { PFATAL("getcwd() failed"); }
    data->out_file = alloc_printf("%s/%s", cwd, out_file);
    ck_free(out_file);
  }

  // create the output file
  data->out_fd = open(data->out_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (data->out_fd < 0) {
    FATAL("Failed to create output file %s: %s\n", data->out_file, strerror(errno));
  }

  // setup shmem for label info
  data->shm_name = alloc_printf("/symsan-union-table-%d", afl->_id);
  data->shm_fd = shm_open(data->shm_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);;
  if (data->shm_fd == -1) {
    FATAL("Failed to open shm(%s): %s\n", data->shm_name, strerror(errno));
  }

  if (ftruncate(data->shm_fd, uniontable_size) == -1) {
    FATAL("Failed to truncate shmem: %s\n", strerror(errno));
  }

  __dfsan_label_info = (dfsan_label_info *)mmap(NULL, uniontable_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, data->shm_fd, 0);
  if (__dfsan_label_info == (void *)-1) {
    FATAL("Failed to map shm(%d): %s\n", data->shm_fd, strerror(errno));
  }

  // clear O_CLOEXEC flag
  fcntl(data->shm_fd, F_SETFD, fcntl(data->shm_fd, F_GETFD) & ~FD_CLOEXEC);

  // allocate output buffer
  data->output_buf = (u8 *)malloc(MAX_FILE+1);
  if (!data->output_buf) {
    FATAL("Failed to alloc output buffer\n");
  }

#if PRINT_STATS
  char *log_f = getenv("SYMSAN_LOG_FILE");
  if (log_f) {
    data->log_fd = open(log_f, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (data->log_fd < 0) {
      FATAL("Failed to create log file: %s\n", strerror(errno));
    }
  } else {
    data->log_fd = 2; // stderr by default
  }
#endif

  return data;
}

extern "C" void afl_custom_deinit(my_mutator_t *data) {
  shmdt(__dfsan_label_info);
  delete data;
}

static int spawn_symsan_child(my_mutator_t *data, const u8 *buf, size_t buf_size,
                              int pipefds[2]) {
  // setup argv in case of initialized
  if (unlikely(!data->argv)) {
    int argc = 0;
    while (data->afl->argv[argc]) { argc++; }
    data->argv = (char **)calloc(argc + 1, sizeof(char *));
    if (!data->argv) {
      FATAL("Failed to alloc argv\n");
    }
    for (int i = 0; i < argc; i++) {
      if (strstr(data->afl->argv[i], (char*)data->afl->tmp_dir)) {
        DEBUGF("Replacing %s with %s\n", data->afl->argv[i], data->out_file);
        data->argv[i] = data->out_file;
      } else {
        data->argv[i] = data->afl->argv[i];
      }
    }
    data->argv[argc] = NULL;
  }

  // FIXME: should we use the afl->queue_cur->fname instead?
  // write the buf to the file
  lseek(data->out_fd, 0, SEEK_SET);
  ck_write(data->out_fd, buf, buf_size, data->out_file);
  fsync(data->out_fd);
  if (ftruncate(data->out_fd, buf_size)) {
    WARNF("Failed to truncate output file: %s\n", strerror(errno));
    return 0;
  }

  // setup the env vars for SYMSAN
  const char *taint_file = data->afl->fsrv.use_stdin ? "stdin" : data->out_file;
  char *options = alloc_printf("taint_file=%s:shm_fd=%d:pipe_fd=%d:debug=%d:trace_bound=%d",
                                taint_file, data->shm_fd, pipefds[1], DEBUG, TraceBounds);
#if DEBUG
  DEBUGF("TAINT_OPTIONS=%s\n", options);
#endif
  
  int pid = fork();
  if (pid == 0) {
    close(pipefds[0]); // close the read fd
    setenv("TAINT_OPTIONS", (char*)options, 1);
    unsetenv("LD_PRELOAD"); // don't preload anything
    if (data->afl->fsrv.use_stdin) {
      close(0);
      lseek(data->out_fd, 0, SEEK_SET);
      dup2(data->out_fd, 0);
    }
#if !DEBUG
    close(1);
    close(2);
    dup2(data->afl->fsrv.dev_null_fd, 1);
    dup2(data->afl->fsrv.dev_null_fd, 2);
#endif
    execv(data->symsan_bin, data->argv);
    DEBUGF("Failed to execv: %s: %s", data->symsan_bin, strerror(errno));
    exit(-1);
  } if (pid < 0) {
    WARNF("Failed to fork: %s\n", strerror(errno));
  }

  // free options
  ck_free(options);

  return pid;

}

static ssize_t timed_read(int fd, void *buf, size_t count, uint32_t timeout, bool &timedout) {
  fd_set rfds;
  struct timeval tv;
  ssize_t ret;

  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);

  tv.tv_sec = (timeout / 1000);
  tv.tv_usec = (timeout % 1000) * 1000;
  timedout = false;

  ret = select(fd + 1, &rfds, NULL, NULL, &tv);
  if (ret == -1) {
    WARNF("Failed to select: %s\n", strerror(errno));
    return -1;
  } else if (ret == 0) {
    WARNF("Timeout\n");
    timedout = true;
    return -1;
  }

  return read(fd, buf, count);
}

/// @brief the trace stage for symsan
/// @param data the custom mutator state
/// @param buf input buffer
/// @param buf_size 
/// @return the number of solving tasks
extern "C" u32 afl_custom_fuzz_count(my_mutator_t *data, const u8 *buf,
                                     size_t buf_size) {

  // check the input id to see if it's been run before
  // we don't use the afl_custom_queue_new_entry() because we may not
  // want to solve all the tasks
  u32 input_id = data->afl->queue_cur->id;
  u32 timeout = std::min(MIN_TIMEOUT, data->afl->fsrv.exec_tmout);
  if (data->fuzzed_inputs.find(input_id) != data->fuzzed_inputs.end()) {
    return 0;
  }
  data->fuzzed_inputs.insert(input_id);

  // record the name of the current queue entry
  data->cur_queue_entry = data->afl->queue_cur->fname;
  DEBUGF("Fuzzing %s\n", data->cur_queue_entry);

  // create pipe for communication
  int pipefds[2];
  if (pipe(pipefds) != 0) {
    WARNF("Failed to create pipe fds: %s\n", strerror(errno));
    return 0;
  }

  // spawn the symsan child
  int pid = spawn_symsan_child(data, buf, buf_size, pipefds);
  close(pipefds[1]); // close the write fd

  if (pid < 0) {
    close(pipefds[0]);
    return 0;
  }
 
  pipe_msg msg;
  gep_msg gmsg;
  memcmp_msg *mmsg;
  dfsan_label_info *info;
  size_t msg_size;
  std::unique_ptr<uint8_t[]> memcmp_const;
  u32 num_tasks = 0;
  u32 num_msgs = 0;
  bool timedout = false;
  struct timeval start, end;
  gettimeofday(&start, NULL);

  // clear all caches
  reset_global_caches(buf_size);

  while (timed_read(pipefds[0], &msg, sizeof(msg), timeout, timedout) > 0) {
    // create solving tasks
    switch (msg.msg_type) {
      // conditional branch
      case cond_type:
        handle_cond(msg, buf, buf_size, data);
        break;
      case gep_type:
        if (read(pipefds[0], &gmsg, sizeof(gmsg)) != sizeof(gmsg)) {
          WARNF("Failed to receive gep msg: %s\n", strerror(errno));
          break;
        }
        // double check
        if (msg.label != gmsg.index_label) {
          WARNF("Incorrect gep msg: %d vs %d\n", msg.label, gmsg.index_label);
          break;
        }
        handle_gep(gmsg, msg);
        break;
      case memcmp_type:
        if (msg.label == 0 || msg.label >= MAX_LABEL) {
          WARNF("Invalid memcmp label: %d\n", msg.label);
          break;
        }
        info = get_label_info(msg.label);
        // if both operands are symbolic, no content to be read
        if (info->l1 != CONST_LABEL && info->l2 != CONST_LABEL)
          break;
        msg_size = sizeof(memcmp_msg) + msg.result;
        mmsg = (memcmp_msg*)malloc(msg_size);
        if (read(pipefds[0], mmsg, msg_size) != msg_size) {
          WARNF("Failed to receive memcmp msg: %s\n", strerror(errno));
          free(mmsg);
          break;
        }
        // double check
        if (msg.label != mmsg->label) {
          WARNF("Incorrect memcmp msg: %d vs %d\n", msg.label, mmsg->label);
          free(mmsg);
          break;
        }
        // save the content
        memcmp_const = std::make_unique<uint8_t[]>(msg.result); // use unique_ptr to avoid memory leak
        memcpy(memcmp_const.get(), mmsg->content, msg.result);
        memcmp_cache.insert({msg.label, std::move(memcmp_const)});
        free(mmsg);
        break;
      case fsize_type:
        break;
      case memerr_type:
        WARNF("Memory error detected @%p, type = %d\n", (void*)msg.addr, msg.flags);
        break;
      default:
        break;
    }
    // naive deadloop detection
    num_msgs += 1;
    if (unlikely((num_msgs & 0xffffe000) != 0)) {
      gettimeofday(&end, NULL);
      if ((end.tv_sec - start.tv_sec) * 10 > timeout) {
        // allow 100x slowdown, sec * 1000 > ms * 100
        WARNF("Possible deadloop, break\n");
        timedout = true;
        break;
      }
    }
  }

  if (timedout) {
    // kill the child process
    kill(pid, SIGKILL);
  }

  pid = waitpid(pid, NULL, 0);

  // clean up
  close(pipefds[0]);

  // reinit solving state
  data->cur_task = nullptr;

  size_t max_stages = data->solvers.size();
  // to be conservative, we return the maximum number of possible mutations
  return (u32)(data->task_mgr->get_num_tasks() * max_stages);

}

static void print_stats(my_mutator_t *data) {
  dprintf(data->log_fd,
    "Total branches: %zu,\n"\
    "Total tasks: %zu,\n"\
    "Solved tasks: %zu,\n"\
    "Solved branches: %zu\n",
    total_branches, total_tasks, solved_tasks, solved_branches);
  dprintf(data->log_fd, "Task size distribution:\n");
  for (auto const& kv : task_size_dist) {
    dprintf(data->log_fd, "\t %zu: %zu\n", kv.first, kv.second);
  }
  for (auto &solver : data->solvers) {
    solver->print_stats(data->log_fd);
  }
}

extern "C"
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  (void)(add_buf);
  (void)(add_buf_size);
  (void)(max_size);
  if (buf_size > MAX_FILE) {
    *out_buf = buf;
    return 0;
  }

  // try to get a task if we don't already have one
  // or if we've find a valid solution from the previous mutation
  if (!data->cur_task || data->cur_mutation_state == MUTATION_VALIDATED) {
    data->cur_task = data->task_mgr->get_next_task();
    if (!data->cur_task) {
      DEBUGF("No more tasks to solve\n");
      data->cur_mutation_state = MUTATION_INVALID;
      *out_buf = buf;
#if PRINT_STATS
      print_stats(data);
#endif
      return 0;
    }
    // reset the solver and state
    data->cur_solver_index = 0;
    data->cur_mutation_state = MUTATION_INVALID;
  }

  // check the previous mutation state
  if (data->cur_mutation_state == MUTATION_IN_VALIDATION) {
    // oops, not solve, move on to next solver
    data->cur_solver_index++;
    if (data->cur_solver_index >= data->solvers.size()) {
      // if reached the max solver, move on to the next task
      data->cur_task = data->task_mgr->get_next_task();
      if (!data->cur_task) {
        DEBUGF("No more tasks to solve\n");
        data->cur_mutation_state = MUTATION_INVALID;
        *out_buf = buf;
#if PRINT_STATS
        print_stats(data);
#endif
        return 0;
      }
      data->cur_solver_index = 0; // reset solver index
    }
  }

  // default return values
  size_t new_buf_size = 0;
  *out_buf = buf;
  auto &solver = data->solvers[data->cur_solver_index];
  auto ret = solver->solve(data->cur_task, buf, buf_size,
      data->output_buf, new_buf_size);
  if (likely(ret == rgd::SOLVER_SAT)) {
    DEBUGF("task solved\n");
    data->cur_mutation_state = MUTATION_IN_VALIDATION;
    *out_buf = data->output_buf;
    solved_tasks += 1;
  } else if (ret == rgd::SOLVER_TIMEOUT) {
    // if not solved, move on to next stage
    data->cur_mutation_state = MUTATION_IN_VALIDATION;
  } else if (ret == rgd::SOLVER_UNSAT) {
    // at any stage if the task is deemed unsolvable, just skip it
    DEBUGF("task not solvable\n");
    data->cur_task->skip_next = true;
    data->cur_task = nullptr;
  } else {
    WARNF("Unknown solver return value %d\n", ret);
    *out_buf = NULL;
    new_buf_size = 0;
  }

  return new_buf_size;
}


// FIXME: use new queue entry as feedback to see if the last mutation is successful
extern "C"
uint8_t afl_custom_queue_new_entry(my_mutator_t * data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {
  // if we're in validation state and the current queue entry is the same as
  // mark the constraints as solved
  DEBUGF("new queue entry: %s\n", filename_new_queue);
  if (data->cur_queue_entry == filename_orig_queue &&
      data->cur_mutation_state == MUTATION_IN_VALIDATION) {
    data->cur_mutation_state = MUTATION_VALIDATED;
    if (data->cur_task) {
      data->cur_task->skip_next = true;
      solved_branches += 1;
    }
  }
  return 0;
}
