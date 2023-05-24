/*
  a custom mutator for AFL++
  (c) 2023 by Chengyu Song <csong@cs.ucr.edu>
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
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

using namespace __dfsan;

#ifndef DEBUG
#define DEBUG 1
#endif

#if !DEBUG
#define DEBUGF(_str...) do { } while (0)
#endif

#define NEED_OFFLINE 0

static bool NestedSolving = true;

#undef alloc_printf
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = (char*)ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

typedef std::shared_ptr<rgd::AstNode> expr_t;
typedef std::shared_ptr<rgd::Constraint> constraint_t;
typedef std::shared_ptr<rgd::SearchTask> task_t;
typedef std::shared_ptr<rgd::Solver> solver_t;
typedef std::shared_ptr<rgd::BranchContext> branch_ctx_t;

enum mutation_state_t {
  MUTATION_INVALID,
  MUTATION_IN_VALIDATION,
  MUTATION_VALIDATED,
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
    delete task_mgr;
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

dfsan_label_info* __dfsan::get_label_info(dfsan_label label) {
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
  {__dfsan::UDiv,    {rgd::UDiv, "udiv"}},
  {__dfsan::SDiv,    {rgd::SDiv, "sdiv"}},
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

// FIXME: global caches
static std::unordered_map<dfsan_label, expr_t> root_expr_cache;
static std::unordered_map<dfsan_label, constraint_t> constraint_cache;
static std::unordered_map<dfsan_label, std::unordered_set<size_t> > branch_to_inputs;
static std::unordered_map<dfsan_label, std::shared_ptr<uint8_t[]>> memcmp_cache;
// FIXME: global input dependency forests
static rgd::UnionFind data_flow_deps;
static std::vector<std::vector<expr_t> > input_to_branches;

static void reset_global_caches(size_t buf_size) {
  root_expr_cache.clear();
  constraint_cache.clear();
  branch_to_inputs.clear();
  memcmp_cache.clear();
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
static bool do_uta_rel(dfsan_label label, rgd::AstNode *ret,
                       const u8 *buf, size_t buf_size,
                       std::shared_ptr<rgd::Constraint> constraint,
                       std::unordered_set<dfsan_label> &visited) {

  if (label < CONST_OFFSET || label == kInitializingLabel) {
    WARNF("invalid label: %d\n", label);
    return false;
  }

  dfsan_label_info *info = get_label_info(label);
  DEBUGF("%u = (l1:%u, l2:%u, op:%u, size:%u, op1:%lu, op2:%lu)\n",
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
    assert(offset < buf_size);
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
    assert(offset + info->l2 <= buf_size);
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
    if (info->l1 >= CONST_OFFSET) {
      if (!do_uta_rel(info->l1, s1, buf, buf_size, constraint, visited)) {
        return false;
      }
      visited.insert(info->l1);
    } else {
      // s1 is a constant array
      s1->set_kind(rgd::MemcmpConst);
      s1->set_bits(info->size * 8);
      s1->set_label(0);
      // map arg
      auto itr = memcmp_cache.find(label);
      assert(itr != memcmp_cache.end());
      uint32_t arg_index = (uint32_t)constraint->memcmp_const.size();
      s1->set_index(arg_index);
      constraint->memcmp_const.push_back(itr->second);
      uint32_t hash = rgd::xxhash(info->size, rgd::MemcmpConst, arg_index);
      s1->set_hash(hash);
#if NEED_OFFLINE
      std::string val;
      rgd::buf_to_hex_string(itr->second, info->size, val);
      ret->set_value(std::move(val));
      ret->set_name("memcmp_const");
#endif
    }
    assert(info->l2 >= CONST_OFFSET);
    rgd::AstNode *s2 = ret->add_children();
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

  // now we visit the children
  rgd::AstNode *left = ret->add_children();
  if (info->l1 >= CONST_OFFSET) {
    if (!do_uta_rel(info->l1, left, buf, buf_size, constraint, visited)) {
      return false;
    }
    visited.insert(info->l1);
  } else {
    // constant
    left->set_kind(rgd::Constant);
    left->set_label(0);
    uint32_t size = info->size;
    // size of concat the sum of the two operands
    // to get the size of the constant, we need to subtract the size
    // of the other operand
    if (info->op == __dfsan::Concat) {
      assert(info->l2 >= CONST_OFFSET);
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
  if (info->l2 >= CONST_OFFSET) {
    if (!do_uta_rel(info->l2, right, buf, buf_size, constraint, visited)) {
      return false;
    }
    visited.insert(info->l2);
  } else {
    // constant
    right->set_kind(rgd::Constant);
    right->set_label(0);
    uint32_t size = info->size;
    // size of concat the sum of the two operands
    // to get the size of the constant, we need to subtract the size
    // of the other operand
    if (info->op == __dfsan::Concat) {
      assert(info->l1 >= CONST_OFFSET);
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

  // binary ops, we don't really care about comparison ops in jigsaw,
  // as long as the operands are the same, we can reuse the AST/function
  uint32_t kind = rgd::isRelationalKind(ret->kind()) ? rgd::Bool : ret->kind();
  uint32_t hash = rgd::xxhash(left->hash(), (kind << 16) | ret->bits(), right->hash());
  ret->set_hash(hash);

  return true;
}

static constraint_t
parse_constraint(dfsan_label label, const u8 *buf, size_t buf_size) {
  DEBUGF("constructing constraint for label %u\n", label);
  // make sure root is a comparison node
  dfsan_label_info *info = get_label_info(label);
  assert(((info->op & 0xff) == __dfsan::ICmp) || (info->op == __dfsan::fmemcmp));

  std::unordered_set<dfsan_label> visited;
  constraint_t constraint = std::make_shared<rgd::Constraint>();
  if (!do_uta_rel(label, constraint->ast.get(), buf, buf_size, constraint, visited)) {
    return nullptr;
  }
  return constraint;
}

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

static bool find_roots(dfsan_label label, rgd::AstNode *ret,
                       std::unordered_set<size_t> &input_deps,
                       std::unordered_set<dfsan_label> &subroots,
                       std::unordered_set<dfsan_label> &visited);

// sometimes llvm will zext bool
static dfsan_label strip_zext(dfsan_label label) {
  dfsan_label_info *info = get_label_info(label);
  while (info->op == __dfsan::ZExt) {
    info = get_label_info(info->l1);
    if (info->size == 1) {
      // extending a boolean value
      return info->l1;
    } else if (info->op == __dfsan::fmemcmp) {
      // extending the result of memcmp
      return info->l1;
    }
  }
  return label;
}

static bool simplify_land(dfsan_label_info *info, rgd::AstNode *ret,
                          std::unordered_set<size_t> &input_deps,
                          std::unordered_set<dfsan_label> &subroots,
                          std::unordered_set<dfsan_label> &visited) {
  // try some simplification, 0 LAnd x = 0, 1 LAnd x = x
  // symsan always keeps rhs as symbolic
  dfsan_label lhs = info->l1 >= CONST_OFFSET ? strip_zext(info->l1) : 0;
  dfsan_label rhs = strip_zext(info->l2);
  if (likely(rhs == info->l2 && lhs == info->l1 && info->size != 1)) {
    // if nothing go stripped, we can't simplify
    bool r = find_roots(rhs, ret, input_deps, subroots, visited);
    if (lhs >= CONST_OFFSET) {
      r |= find_roots(lhs, ret, input_deps, subroots, visited);
    }
    return r;
  }

  // by communicative, we can parse the rhs first
  DEBUGF("simplify land: %d LAnd %d, %d\n", lhs, rhs, info->size);
  rgd::AstNode *right = ret->add_children();
  bool rr = find_roots(rhs, right, input_deps, subroots, visited);
  assert(right->bits() == 1); // rhs must be a boolean after parsing
  // if nothing added, rhs must be a constant
  if (unlikely(!rr)) {
    assert(right->kind() == rgd::Bool);
    if (right->boolvalue() == 0) { // x LAnd 0 = 0
      ret->set_kind(rgd::Bool);
      ret->set_boolvalue(0);
      ret->clear_children();
      return false;
    } // rhs is 1, fall through
  }
  if (unlikely(lhs == 0)) {
    // lhs is a constant
    if (info->op1.i == 0) { // 0 LAnd x = 0
      ret->set_kind(rgd::Bool);
      ret->set_boolvalue(0);
      ret->clear_children();
      return false;
    } else {
      assert(info->op1.i == 1); // 1 LAnd x = x
      rgd::AstNode temp;
      temp.CopyFrom(*right);
      ret->CopyFrom(temp); // XXX: CopyFrom will clear the children?
      return rr;
    }
  } else {
    rgd::AstNode *left = ret->add_children();
    bool lr = find_roots(lhs, left, input_deps, subroots, visited);
    assert(left->bits() == 1); // lhs must be a boolean after parsing
    // if nothing added, lhs must be a constant
    if (unlikely(!lr)) {
      assert(left->kind() == rgd::Bool);
      if (left->boolvalue() == 0) { // 0 LAnd x = 0
        ret->set_kind(rgd::Bool);
        ret->set_boolvalue(0);
        ret->clear_children();
        return false;
      } else if (!rr) {
        // both lhs and rhs are constants
        ret->set_kind(rgd::Bool);
        ret->set_boolvalue(1); // 1 LAnd 1 = 1 // rhs == 0 has returned earlier
        ret->clear_children();
        return false;
      } else { // 1 LAnd x = x
        // lhs is 1, rhs is not
        rgd::AstNode temp;
        temp.CopyFrom(*right);
        ret->CopyFrom(temp);
        return rr;
      }
    }
  }

  ret->set_kind(rgd::LAnd);
  ret->set_bits(1);
  return true;
}

static bool simplify_lor(dfsan_label_info *info, rgd::AstNode *ret,
                         std::unordered_set<size_t> &input_deps,
                         std::unordered_set<dfsan_label> &subroots,
                         std::unordered_set<dfsan_label> &visited) {
  // try some simplification, x LOr 0 = x, x LOr 1 = 1
  // symsan always keeps rhs as symbolic
  dfsan_label lhs = info->l1 >= CONST_OFFSET ? strip_zext(info->l1) : 0;
  dfsan_label rhs = strip_zext(info->l2);
  if (likely(rhs == info->l2 && lhs == info->l1 && info->size != 1)) {
    // if nothing go stripped, we can't simplify
    bool r = find_roots(rhs, ret, input_deps, subroots, visited);
    if (lhs >= CONST_OFFSET) {
      r |= find_roots(lhs, ret, input_deps, subroots, visited);
    }
    return r;
  }

  // by communicative, we can parse the rhs first
  rgd::AstNode *right = ret->add_children();
  bool rr = find_roots(rhs, right, input_deps, subroots, visited);
  assert(right->bits() == 1); // rhs must be a boolean after parsing
  // if nothing added, rhs must be a constant
  if (unlikely(!rr)) {
    assert(right->kind() == rgd::Bool);
    if (right->boolvalue() == 1) { // x LOr 1 = 1
      ret->set_kind(rgd::Bool);
      ret->set_boolvalue(1);
      ret->clear_children();
      return false;
    } // rhs is 0, fall through
  }
  if (unlikely(lhs == 0)) {
    // lhs is a constant
    if (info->op1.i == 1) { // x LOr 1 = 1
      ret->set_kind(rgd::Bool);
      ret->set_boolvalue(1);
      ret->clear_children();
      return false;
    } else { // 0 LOr x = x
      assert(info->op1.i == 0);
      rgd::AstNode temp;
      temp.CopyFrom(*right);
      ret->CopyFrom(temp);
      return rr;
    }
  } else {
    rgd::AstNode *left = ret->add_children();
    bool lr = find_roots(lhs, left, input_deps, subroots, visited);
    assert(left->bits() == 1); // lhs must be a boolean after parsing
    // if nothing added, lhs must be a constant
    if (unlikely(!lr)) {
      assert(left->kind() == rgd::Bool);
      if (left->boolvalue() == 1) { // 1 LOr x = 1
        ret->set_kind(rgd::Bool);
        ret->set_boolvalue(1);
        ret->clear_children();
        return false;
      } else if (!rr) {
        // both lhs and rhs are constants
        ret->set_kind(rgd::Bool);
        ret->set_boolvalue(0); // 0 LOr 0 = 0 // rhs == 1 has returned earlier
        ret->clear_children();
        return false;
      } else { // 0 LOr x = x
        // lhs is 0, rhs is not
        rgd::AstNode temp;
        temp.CopyFrom(*right);
        ret->CopyFrom(temp);
        return rr;
      }
    }
  }

  ret->set_kind(rgd::LOr);
  ret->set_bits(1);
  return true;
}

static bool simplify_xor(dfsan_label_info *info, rgd::AstNode *ret,
                         std::unordered_set<size_t> &input_deps,
                         std::unordered_set<dfsan_label> &subroots,
                         std::unordered_set<dfsan_label> &visited) {
  // llvm uses xor to do LNot
  // symsan always keeps rhs as symbolic
  dfsan_label lhs = info->l1 >= CONST_OFFSET ? strip_zext(info->l1) : 0;
  dfsan_label rhs = strip_zext(info->l2);
  if (likely(rhs == info->l2 && lhs == info->l1 && info->size != 1)) {
    // if nothing go stripped, we can't simplify
    bool r = find_roots(rhs, ret, input_deps, subroots, visited);
    if (lhs >= CONST_OFFSET) {
      r |= find_roots(lhs, ret, input_deps, subroots, visited);
    }
    return r;
  }

  // by communicative, we can parse the rhs first
  rgd::AstNode *right = ret->add_children();
  bool rr = find_roots(rhs, right, input_deps, subroots, visited);
  assert(right->bits() == 1); // rhs must be a boolean after parsing
  ret->set_bits(1);
  if (unlikely(!rr)) {
    // if nothing added, rhs must be a constant
    assert(right->kind() == rgd::Bool);
    ret->set_kind(rgd::Bool);
    if (likely(info->l1 == 0)) { // left is a constant
      ret->set_boolvalue(right->boolvalue() ^ (uint32_t)info->op1.i);
      ret->clear_children();
      return false;
    } // left is symbolic, fall through
  }
  
  if (likely(lhs == 0)) {
    // when reach here, rhs must not be a constant
    if (info->op1.i == 1) { // 1 LXor x = LNot x
      ret->set_kind(rgd::LNot);
      return true;
    } else { // 0 LXor x = x
      rgd::AstNode temp;
      temp.CopyFrom(*right);
      ret->CopyFrom(temp);
      return rr;
    }
  } else {
    rgd::AstNode *left = ret->add_children();
    bool lr = find_roots(lhs, left, input_deps, subroots, visited);
    if (unlikely(!lr)) {
      // if nothing added, lhs must be a constant
      assert(left->kind() == rgd::Bool);
      if (left->boolvalue() == 0) { // 0 LXor x = x
        rgd::AstNode temp;
        temp.CopyFrom(*right);
        ret->CopyFrom(temp);
      } else { // 1 LXor x = LNot x
        ret->set_kind(rgd::LNot);
      }
      return rr;
    }
  }
  ret->set_kind(rgd::Xor);
  return true;
}

static bool find_roots(dfsan_label label, rgd::AstNode *ret,
                       std::unordered_set<size_t> &input_deps,
                       std::unordered_set<dfsan_label> &subroots,
                       std::unordered_set<dfsan_label> &visited) {
  if (label < CONST_OFFSET || label == kInitializingLabel) {
    WARNF("invalid label: %d\n", label);
    return false;
  }

  dfsan_label_info *info = get_label_info(label);

  if (info->op == 0) {
    input_deps.insert(info->op1.i);
    return false;
  } else if (info->op == __dfsan::Load) {
    uint64_t offset = get_label_info(info->l1)->op1.i;
    for (size_t i = 0; i < info->l2; ++i)
      input_deps.insert(offset + i);
    return false;
  }

  // check for visited after input deps have been added
  if (visited.count(label)) {
    return false;
  }
  visited.insert(label);

  // possible boolean operations
  if (info->op == __dfsan::And) {
    return simplify_land(info, ret, input_deps, subroots, visited);
  } else if (info->op == __dfsan::Or) {
    return simplify_lor(info, ret, input_deps, subroots, visited);
  } else if (info->op == __dfsan::Xor) {
    return simplify_xor(info, ret, input_deps, subroots, visited);
  } else if ((info->op & 0xff) == __dfsan::ICmp) {
    // if it's a comparison, we need to make sure both operands don't
    // contain any additional comparison operator
    bool lr = false, rr = false;
    std::shared_ptr<rgd::AstNode> left = std::make_shared<rgd::AstNode>();
    std::shared_ptr<rgd::AstNode> right = std::make_shared<rgd::AstNode>();
    auto &deps = branch_to_inputs[label]; // get the input deps of this branch
    if (info->l1 >= CONST_OFFSET) {
      lr = find_roots(strip_zext(info->l1), left.get(), deps, subroots, visited);
    }
    if (info->l2 >= CONST_OFFSET) {
      rr = find_roots(strip_zext(info->l2), right.get(), deps, subroots, visited);
    }
    input_deps.insert(deps.begin(), deps.end()); // propagate input deps
    if (unlikely(lr)) {
      // if there are additional icmp in lhs, this icmp must be simplifiable
      assert(left->bits() == 1);
      assert(is_rel_cmp(info->op, __dfsan::bveq) || is_rel_cmp(info->op, __dfsan::bvneq));
      if (likely(info->l2 == 0)) {
        if (is_rel_cmp(info->op, __dfsan::bveq)) {
          if (info->op2.i == 1) { // checking bool == true
            ret->CopyFrom(*left);
          } else { // checking bool == false
            ret->set_kind(rgd::LNot);
            ret->add_children()->CopyFrom(*left);
          }
        } else { // bvneq
          if (info->op2.i == 0) { // checking bool != false
            ret->CopyFrom(*left);
          } else { // checking bool != true
            ret->set_kind(rgd::LNot);
            ret->add_children()->CopyFrom(*left);
          }
        }
      } else {
        // bool icmp bool ?!
        WARNF("bool icmp bool ?!\n");
        ret->set_kind(rgd::Bool);
        ret->set_boolvalue(0);
        return false;
      }
    } else if (unlikely(rr)) {
      // if there are additional icmp in rhs, this icmp must be simplifiable
      assert(right->bits() == 1);
      assert(is_rel_cmp(info->op, __dfsan::bveq) || is_rel_cmp(info->op, __dfsan::bvneq));
      if (likely(info->l1 == 0)) {
        if (is_rel_cmp(info->op, __dfsan::bveq)) {
          if (info->op1.i == 1) { // checking true == bool
            ret->CopyFrom(*right);
          } else { // checking false == bool
            ret->set_kind(rgd::LNot);
            ret->add_children()->CopyFrom(*right);
          }
        } else { // bvneq
          if (info->op1.i == 0) { // checking false != bool
            ret->CopyFrom(*right);
          } else { // checking true != bool
            ret->set_kind(rgd::LNot);
            ret->add_children()->CopyFrom(*right);
          }
        }
      } else {
        // bool icmp bool ?!
        WARNF("bool icmp bool ?!\n");
        ret->set_kind(rgd::Bool);
        ret->set_boolvalue(0);
        return false;
      }
    } else {
      // !lr && !rr when reach here
      ret->set_bits(1);
      auto itr = OP_MAP.find(info->op);
      assert(itr != OP_MAP.end());
      ret->set_kind(itr->second.first);
      ret->set_label(label);
#ifdef DEBUG
      subroots.insert(label);
#endif
      return true;
    }
  } else if (info->op == __dfsan::fmemcmp) {
    // memcmp is also considered as a root node (relational comparison)
    bool s1_r = false, s2_r = false;
    std::shared_ptr<rgd::AstNode> s1 = std::make_shared<rgd::AstNode>();
    std::shared_ptr<rgd::AstNode> s2 = std::make_shared<rgd::AstNode>();
    auto &deps = branch_to_inputs[label]; // get the input deps of this branch
    if (info->l1 >= CONST_OFFSET) {
      s1_r = find_roots(info->l1, s1.get(), deps, subroots, visited);
    }
    assert(info->l2 >= CONST_OFFSET);
    s2_r = find_roots(info->l2, s2.get(), deps, subroots, visited);
    input_deps.insert(deps.begin(), deps.end()); // propagate input deps
    assert(!s1_r && !s2_r && "memcmp should not have additional icmp");
    ret->set_bits(1); // XXX: treat memcmp as a boolean
    ret->set_kind(rgd::Memcmp); // fix later
    ret->set_label(label);
#ifdef DEBUG
    subroots.insert(label);
#endif
    return true;
  }

  // for all other cases, just visit the operands
  bool r = false;
  if (likely(info->l2 >= CONST_OFFSET)) {
    r |= find_roots(info->l2, ret, input_deps, subroots, visited);
  }
  if (info->l1 >= CONST_OFFSET) {
    r |= find_roots(info->l1, ret, input_deps, subroots, visited);
  }
  return r;
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

static void to_nnf(bool expected_r, rgd::AstNode *node) {
  if (!expected_r) {
    // we're looking for a negated formula
    if (node->kind() == rgd::LNot) {
      // double negation
      assert(node->children_size() == 1);
      rgd::AstNode *child = node->mutable_children(0);
      // transform the child, now looking for a true formula
      to_nnf(true, child);
      rgd::AstNode tmp;
      tmp.CopyFrom(*child);
      node->CopyFrom(tmp);
    } else if (node->kind() == rgd::LAnd) {
      // De Morgan's law
      assert(node->children_size() == 2);
      node->set_kind(rgd::LOr);
      to_nnf(false, node->mutable_children(0));
      to_nnf(false, node->mutable_children(1));
    } else if (node->kind() == rgd::LOr) {
      // De Morgan's law
      assert(node->children_size() == 2);
      node->set_kind(rgd::LAnd);
      to_nnf(false, node->mutable_children(0));
      to_nnf(false, node->mutable_children(1));
    } else {
      // leaf node
      if (rgd::isRelationalKind(node->kind())) {
        node->set_kind(rgd::negate_cmp(node->kind()));
      } else if (node->kind() == rgd::Memcmp) {
        // memcmp is also considered as a leaf node (relational comparison)
        // memcmp == 0 actually means s1 == s2
        // so we don't need to negate it
      } else {
        assert(false && "unexpected node kind");
      }
    }
  } else {
    // we're looking for a true formula
    if (node->kind() == rgd::LNot) {
      assert(node->children_size() == 1);
      rgd::AstNode *child = node->mutable_children(0);
      // negate the child, now looking for a false formula
      to_nnf(false, child);
      rgd::AstNode tmp;
      tmp.CopyFrom(*child);
      node->CopyFrom(tmp);
    } else if (node->kind() == rgd::Memcmp) {
      // memcmp is also considered as a leaf node (relational comparison)
      // memcmp == 1 actually means s1 != s2
      // so we negate it
      node->set_kind(rgd::MemcmpN);
    } else {
      for (int i = 0; i < node->children_size(); i++) {
        to_nnf(expected_r, node->mutable_children(i));
      }
    }
  }
}

typedef std::vector<std::vector<const rgd::AstNode*> > formula_t;

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

static inline expr_t get_root_expr(dfsan_label label) {
  expr_t root = nullptr;
  auto itr = root_expr_cache.find(label);
  if (itr != root_expr_cache.end()) {
    root = itr->second;
  } else {
    root = std::make_shared<rgd::AstNode>();
    std::unordered_set<dfsan_label> subroots;
    std::unordered_set<dfsan_label> visited;
    // FIXME: implicitly updated here, not very clean
    auto &deps = branch_to_inputs[label];
    // we start by constructing a boolean formula with relational expressions
    // as leaf nodes
    find_roots(label, root.get(), deps, subroots, visited);
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
  expr_t orig_root = get_root_expr(label);
  if (orig_root->kind() == rgd::Bool) {
    // if the simplified formula is a boolean constant, nothing to do
    return false;
  }

  // duplication the original root for transformation
  expr_t root = std::make_shared<rgd::AstNode>();
  root->CopyFrom(*orig_root);

  // next, convert the formula to NNF form, possibly negate the root
  // if we are looking for a false formula
  to_nnf(target_direction, root.get());
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
    }

    if (NestedSolving) {
      // collect dependencies based on data-flow (i.e., shared input bytes)
      std::vector<const rgd::AstNode*> nested_caluse;
      // first, copy the last branch constraints
      nested_caluse.insert(nested_caluse.end(), clause.begin(), clause.end());
      // then, iterate each var in the clause
      for (auto const& var: clause) {
        const dfsan_label l = var->label();
        auto itr = branch_to_inputs.find(l);
        assert(itr != branch_to_inputs.end());
        assert(itr->second.size() > 0);
        // for each input byte used in the var, we collect additional constraints
        // first, we use union find to add additional related input bytes
        std::unordered_set<size_t> related_inputs;
        for (auto input: itr->second) {
          data_flow_deps.get_set(input, related_inputs);
        }
        // then, we collect the branch constraints for each related input byte
        for (auto input: related_inputs) {
          auto const& bucket = input_to_branches[input];
          for (auto const& nc : bucket) {
#if DEBUG
            fprintf(stderr, "add nested constraint: (%d, %d)\n", nc->label(), nc->kind());
#endif
            nested_caluse.push_back(nc.get()); // XXX: borrow the raw ptr, should be fine?
          }
        }
      }
      task_t nested_task = construct_task(nested_caluse, buf, buf_size);
      if (nested_task != nullptr) {
        nested_task->base_task = task;
        tasks.push_back(nested_task);
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
  expr_t orig_root = get_root_expr(label);
  if (orig_root->kind() == rgd::Bool) {
    // if the simplified formula is a boolean constant, nothing to do
    return false;
  }

  // duplication the original root for transformation
  expr_t root = std::make_shared<rgd::AstNode>();
  root->CopyFrom(*orig_root);

  // next, convert the formula to NNF form, possibly negate the root
  // if we are looking for a false formula
  to_nnf(direction, root.get());
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
      auto itr = branch_to_inputs.find(l);
      assert(itr != branch_to_inputs.end());
      assert(itr->second.size() > 0);
      // update uion find
      size_t root = *(itr->second.begin());
      for (auto iitr = ++itr->second.begin(); iitr != itr->second.end(); ++iitr) {
#if DEBUG
        DEBUGF("union input bytes: (%zu, %zu)\n", root, *iitr);
#endif
        root = data_flow_deps.merge(root, *iitr);
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
    }
  }

  if (msg.flags & F_ADD_CONS) {
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
  // try jigsaw first
  //data->solvers.emplace_back(std::make_shared<rgd::JITSolver>());
  data->solvers.emplace_back(std::make_shared<rgd::Z3Solver>());

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
    data->argv = (char **)calloc(argc, sizeof(char *));
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
  char *options = alloc_printf("taint_file=%s:shm_fd=%d:pipe_fd=%d:debug=%d",
                                taint_file, data->shm_fd, pipefds[1], DEBUG);
#if DEBUG
  DEBUGF("TAINT_OPTIONS=%s\n", options);
#endif
  
  int pid = fork();
  if (pid == 0) {
    close(pipefds[0]); // close the read fd
    setenv("TAINT_OPTIONS", (char*)options, 1);
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
    DEBUGF("Failed to execv: %s", data->symsan_bin);
    exit(-1);
  } if (pid < 0) {
    WARNF("Failed to fork: %s\n", strerror(errno));
  }

  // free options
  ck_free(options);

  return pid;

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
  std::shared_ptr<uint8_t[]> memcmp_const;
  u32 num_tasks = 0;

  // clear all caches
  reset_global_caches(buf_size);

  while (read(pipefds[0], &msg, sizeof(msg)) > 0) {
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
        memcmp_const = std::make_shared<uint8_t[]>(msg.result); // use shared_ptr to avoid memory leak
        memcpy(memcmp_const.get(), mmsg->content, msg.result);
        memcmp_cache[msg.label] = memcmp_const;
        free(mmsg);
        break;
      case fsize_type:
        break;
      default:
        break;
    }
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

extern "C"
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  (void)(add_buf);
  (void)(add_buf_size);
  (void)(max_size);
  assert(buf_size <= MAX_FILE);

  // try to get a task if we don't already have one
  // or if we've find a valid solution from the previous mutation
  if (!data->cur_task || data->cur_mutation_state == MUTATION_VALIDATED) {
    data->cur_task = data->task_mgr->get_next_task();
    if (!data->cur_task) {
      DEBUGF("No more tasks to solve\n");
      data->cur_mutation_state = MUTATION_INVALID;
      *out_buf = buf;
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
  } else if (ret == rgd::SOLVER_TIMEOUT) {
    // if not solved, move on to next stage
    data->cur_mutation_state = MUTATION_INVALID;
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
    if (data->cur_task)
      data->cur_task->skip_next = true;
  }
  return 0;
}