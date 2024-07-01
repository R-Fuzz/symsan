#include "dfsan/dfsan.h"

#include "ast.h"
#include "task.h"
#include "union_find.h"
#include "parse-rgd.h"

#include <unordered_map>

using namespace rgd;

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define DEBUGF(_str...) do { fprintf(stderr, _str); } while (0)
#else
#undef DEBUGF
#define DEBUGF(_str...) do { } while (0)
#endif

#ifndef WARNF
#define WARNF(_str...) do { fprintf(stderr, _str); } while (0)
// #define WARNF(x...) do { \
//     SAYF(cYEL "[!] " cBRI "WARNING: " cRST x); \
//     SAYF(cRST "\n"); \
//   } while (0)
#endif

#define NEED_OFFLINE 0

#if defined(__GNUC__)
static inline bool (likely)(bool x) { return __builtin_expect((x), true); }
static inline bool (unlikely)(bool x) { return __builtin_expect((x), false); }
#else
static inline bool (likely)(bool x) { return x; }
static inline bool (unlikely)(bool x) { return x; }
#endif

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
  return ((op & 0xff) == __dfsan::ICmp) && ((op >> 8) == pred);
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

static void printAst(FILE* f, const rgd::AstNode *node, int indent) {
  fprintf(f, "(%s, ", rgd::AstKindName[node->kind()]);
  fprintf(f, "%d, ", node->label());
  fprintf(f, "%d, ", node->bits());
  for(int i = 0; i < node->children_size(); i++) {
    printAst(f, &node->children(i), indent + 1);
    if (i != node->children_size() - 1) {
      fprintf(f, ", ");
    }
  }
  fprintf(f, ")\n");
}

int RGDAstParser::restart(std::vector<symsan::input_t> &inputs) {
  // save a copy of the inputs
  inputs_cache = inputs;
  // clear caches
  memcmp_cache_.clear(); // inherited from ASTParser
  root_expr_cache.clear();
  constraint_cache.clear();
  ast_size_cache.clear();
  nested_cmp_cache.clear();
  concretize_node.clear();
  branch_to_inputs.clear();

  // reset data-flow dependencies
  input_size_ = 0;
  for (auto &i: inputs) {
    input_size_ += i.second;
  }
  data_flow_deps.reset(input_size_);
  for (auto &s: input_to_branches) {
    s.clear();
  }
  input_to_branches.resize(input_size_);

  return 0;
}

uint32_t RGDAstParser::map_arg(uint32_t input_id, uint32_t offset, uint32_t length,
                               constraint_t constraint) {
  uint32_t hash = 0;
  auto *buf = inputs_cache[input_id].first;
  for (uint32_t i = 0; i < length; ++i, ++offset) {
    uint8_t val = buf[offset];
    uint32_t arg_index = 0;
    auto itr = constraint->local_map.find(offset); // FIXME: support input_id
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
[[gnu::hot]]
bool RGDAstParser::do_uta_rel(dfsan_label label, rgd::AstNode *ret,
                              constraint_t constraint,
                              std::unordered_set<dfsan_label> &visited) {

  // needed for recursion?
  if (unlikely(label < CONST_OFFSET || label == __dfsan::kInitializingLabel)) {
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
    uint32_t input_id = info->op2.i;
    uint32_t offset = info->op1.i;
    // this check should have been done during label scanning
    // if (unlikely(offset >= buf_size)) {
    //   WARNF("invalid offset: %lu >= %lu\n", offset, buf_size);
    //   return false;
    // }
    ret->set_index(offset);
    // map arg
    uint32_t hash = map_arg(input_id, offset, 1, constraint);
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
    uint32_t input_id = get_label_info(info->l1)->op2.i;
    uint32_t offset = get_label_info(info->l1)->op1.i;
    // this check should have been done during label scanning
    // if (unlikely(offset + info->l2 > buf_size)) {
    //   WARNF("invalid offset: %lu + %u > %lu\n", offset, info->l2, buf_size);
    //   return false;
    // }
    ret->set_index(offset);
    // map arg
    uint32_t hash = map_arg(input_id, offset, info->l2, constraint);
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
      if (!do_uta_rel(info->l1, s1, constraint, visited)) {
        return false;
      }
      visited.insert(info->l1);
    } else {
      // s1 is a constant array
      s1->set_kind(rgd::Constant);
      s1->set_bits(info->size * 8);
      s1->set_label(0);
      // use constant args to pass the array
      auto itr = memcmp_cache_.find(label);
      if (unlikely(itr == memcmp_cache_.end())) {
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
    if (!do_uta_rel(info->l2, s2, constraint, visited)) {
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
    uint32_t input_id = get_label_info(src->l1)->op2.i;
    uint32_t offset = get_label_info(src->l1)->op1.i;
    // this check should have been done during label scanning
    // if (unlikely(offset >= buf_size)) {
    //   WARNF("invalid offset: %lu >= %lu\n", offset, buf_size);
    //   return false;
    // }
    ret->set_bits(info->size);
    ret->set_label(label);
    ret->set_index(offset);
    // special handling for atoi, we are introducing the result/output of
    // atoi as fake inputs, and solve constraints over the output,
    // once solved, we convert it back to string
    // however, because the input is fake, we need to map it specially
    ret->set_kind(rgd::Read);
    auto itr = constraint->local_map.find(offset); // FIXME: support input_id
    if (itr != constraint->local_map.end()) {
      WARNF("atoi inputs should not be involved in other constraints\n");
      return false;
    }
    uint32_t hash = 0;
    uint32_t length = info->size / 8; // bits to bytes
    // record the offset, base, and original length
    constraint->atoi_info[offset] = std::make_tuple(length, (uint32_t)info->op1.i, (uint32_t)info->op2.i);
    for (uint32_t i = 0; i < length; ++i, ++offset) {
      uint8_t val = 0; // XXX: use 0 as initial value?
      // because this is fake input, we always map it to a new index
      uint32_t arg_index = (uint32_t)constraint->input_args.size();
      constraint->inputs.insert({offset, val});
      constraint->local_map[offset] = arg_index; // FIXME: support input_id
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
  } else if (info->op == __dfsan::fsize) {
    // do nothing now
    WARNF("fsize not supported yet\n");
    return false;
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
    if (!do_uta_rel(info->l1, left, constraint, visited)) {
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
    if (!do_uta_rel(info->l2, right, constraint, visited)) {
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

[[gnu::hot]]
RGDAstParser::constraint_t RGDAstParser::parse_constraint(dfsan_label label) {
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
    if (!do_uta_rel(label, constraint->ast.get(), constraint, visited)) {
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

[[gnu::hot]]
task_t RGDAstParser::construct_task(const clause_t &clause) {
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
    constraint_t constraint = parse_constraint(node->label());
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
dfsan_label RGDAstParser::strip_zext(dfsan_label label) {
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

[[gnu::hot]]
int RGDAstParser::find_roots(dfsan_label label, AstNode *ret,
                             std::unordered_set<dfsan_label> &subroots) {
  // assume the root label has been checked by the caller
  // if (label < CONST_OFFSET || label == kInitializingLabel) {
  //   WARNF("invalid label: %d\n", label);
  //   return INVALID_NODE;
  // }

  std::vector<dfsan_label> stack;
  dfsan_label root = label;
  dfsan_label prev = 0;
  std::vector<AstNode*> node_stack;
  AstNode *root_node = ret;
  std::unordered_set<dfsan_label> visited;

  try{
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
            uint8_t concretize = (itr != concretize_node.end() ? itr->second : 0);
            if (size > max_ast_size_) {
              DEBUGF("AST size too large: %d = %u\n", curr, size);
              auto left_size = ast_size_cache.at(info->l1);
              auto right_size = ast_size_cache.at(info->l2);
              if (left_size > max_ast_size_) {
                // concretize left
                concretize |= 1;
                // update new size
                size -= (left_size - 1);
              }
              if (right_size > max_ast_size_) {
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

[[gnu::hot]]
bool RGDAstParser::scan_labels(dfsan_label label) {
  // assuming label has been checked by caller
  // assuming the last label scanned is the size of the cache
  // turns out linear scan is way faster than tree traversal
  for (size_t i = ast_size_cache.size(); i <= label; i++) {
    if (i == 0) { // the constant label
      ast_size_cache.push_back(1); // constant takes one node too
      branch_to_inputs.emplace_back(input_dep_t(input_size_));
      nested_cmp_cache.push_back(0);
      continue;
    }
    dfsan_label_info *info = get_label_info(i);
    // conservatively check validity of labels
    // so following parsing will not throw exceptions
    if (unlikely(info->l1 >= size_ || info->l2 >= size_)) {
      WARNF("invalid label: %lu, l1=%u, l2=%u\n", i, info->l1, info->l2);
      return false;
    }
    if (info->op == 0) {
      // AST nodes
      ast_size_cache.push_back(1); // one Read node
      // input deps
      uint32_t input_id = info->op2.i;
      uint32_t offset = info->op1.i;
      // skip if invalid
      if (unlikely(input_id >= inputs_cache.size())) {
        WARNF("invalid input id: %u\n", input_id);
        return false;
      }
      size_t buf_size = inputs_cache[input_id].second;
      if (unlikely(offset >= buf_size)) {
        WARNF("invalid input offset: %u >= %lu\n", offset, buf_size);
        return false;
      }
      branch_to_inputs.emplace_back(input_dep_t(input_size_));
      // get flattened index
      size_t idx = input_to_dep_idx(input_id, offset);
      auto &itr = branch_to_inputs[i];
      itr.set(idx); // flattened location
#if DEBUG
      assert(branch_to_inputs[i].find_first() == idx);
#endif
      // nested cmp?
      nested_cmp_cache.push_back(0);
    } else if (info->op == __dfsan::Load) {
      // AST nodes
      ast_size_cache.push_back(1); // one Read node
      // input deps
      uint32_t input_id = get_label_info(info->l1)->op2.i;
      uint32_t offset = get_label_info(info->l1)->op1.i;
      // skip if invalid
      if (unlikely(input_id >= inputs_cache.size())) {
        WARNF("invalid input id: %u\n", input_id);
        return false;
      }
      size_t buf_size = inputs_cache[input_id].second;
      if (unlikely(offset + info->l2 > buf_size)) {
        WARNF("invalid input offset: %u + %u > %lu\n", offset, info->l2, buf_size);
        return false;
      }
      branch_to_inputs.emplace_back(input_dep_t(input_size_));
      // get flattened index
      size_t idx = input_to_dep_idx(input_id, offset);
      auto &itr = branch_to_inputs[i];
      for (size_t n = 0; n < info->l2; ++n) {
        // DEBUGF("adding input: %lu <- %lu\n", i, offset + n);
        itr.set(idx + n); // input offsets
      }
#if DEBUG
      if (likely(info->l2 > 0))
        assert(branch_to_inputs[i].find_first() == idx);
#endif
      // nested cmp?
      nested_cmp_cache.push_back(0);
    } else {
      // AST nodes
      uint32_t left  = info->l1 == 0 ? 1 : ast_size_cache[info->l1];
      uint32_t right = info->l2 == 0 ? 1 : ast_size_cache[info->l2];
      ast_size_cache.push_back(left + right + 1);
      // input deps
      branch_to_inputs.emplace_back(input_dep_t(input_size_));
      auto &itr = branch_to_inputs[i];
      if (info->l1 != 0) itr |= branch_to_inputs[info->l1];
      if (info->l2 != 0) itr |= branch_to_inputs[info->l2];
      // nested cmp?
      uint8_t nested = 0;
      nested += info->l1 == 0 ? 0 : nested_cmp_cache[info->l1];
      nested += info->l2 == 0 ? 0 : nested_cmp_cache[info->l2];
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

RGDAstParser::expr_t RGDAstParser::get_root_expr(dfsan_label label) {
  if (label < CONST_OFFSET || label == __dfsan::kInitializingLabel || label >= size_) {
    return nullptr;
  }

  expr_t root = nullptr;
  auto itr = root_expr_cache.find(label);
  if (itr != root_expr_cache.end()) {
    root = itr->second;
  } else {
    // update ast_size and branch_to_inputs caches
    if (!scan_labels(label)) {
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
  printAst(stderr, root.get(), 0);
#endif

  return root;
}

[[gnu::hot]]
int RGDAstParser::to_nnf(bool expected_r, rgd::AstNode *node) {
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

[[gnu::hot]]
void RGDAstParser::to_dnf(const rgd::AstNode *node, formula_t &formula) {
  if (node->kind() == rgd::LAnd) {
    formula_t left, right;
    to_dnf(&node->children(0), left);
    to_dnf(&node->children(1), right);
    for (auto const& sub1: left) {
      for (auto const& sub2: right) {
        clause_t clause;
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
    clause_t clause;
    clause.push_back(node);
    formula.push_back(clause);
  }
}

int RGDAstParser::parse_cond(dfsan_label label, bool result, bool add_nested,
                             std::vector<uint64_t> &tasks) {

  // given a condition, we want to parse them into a DNF form of
  // relational sub-expressions, where each sub-expression only contains
  // one relational operator at the root
  expr_t orig_root = get_root_expr(label);
  if (orig_root == nullptr) {
    WARNF("failed to get root expr for label %u\n", label);
    return -1;
  } else if (orig_root->kind() == rgd::Bool) {
    // if the simplified formula is a boolean constant, nothing to do
    DEBUGF("cond simplified to be a constant\n");
    return 0;
  }

  // duplication the original root for transformation
  expr_t root = std::make_shared<rgd::AstNode>();
  root->CopyFrom(*orig_root);

  // next, convert the formula to NNF form, possibly negate the root
  // if we are looking for a false formula
  bool target_direction = !result;
  if (to_nnf(target_direction, root.get()) != 0) {
    WARNF("failed to convert to NNF\n");
    return -1;
  }
#if DEBUG
  printAst(stderr, root.get(), 0);
#endif
  // then we need to convert the boolean formula into a DNF form
  formula_t dnf;
  to_dnf(root.get(), dnf);

  // finally, we construct a search task for each clause in the DNF
  for (auto const& clause : dnf) {
    task_t task = construct_task(clause);
    if (task != nullptr) {
      tasks.push_back(save_task(task));
    } else {
      WARNF("failed to construct task for clause\n");
      continue; // skip the nested task if the current task is invalid
    }

    if (solve_nested_) {
      // collect dependencies based on data-flow (i.e., shared input bytes)
      clause_t nested_caluse;
      std::unordered_set<dfsan_label> inserted;
      // first, copy the last branch constraints
      nested_caluse.insert(nested_caluse.end(), clause.begin(), clause.end());
      for (auto const& var : clause) inserted.insert(var->label());
      bool has_nested = false;
      // then, iterate each var in the clause
      for (auto const& var: clause) {
        const dfsan_label l = var->label();
        // assert(branch_to_inputs.size() > l);
        auto &itr = branch_to_inputs[l];
        auto citr = concretize_node.find(l);
        if (unlikely(citr != concretize_node.end())) {
          // skip dependencies if the operand is concretized
          if (citr->second == 1) {
            // if the lhs is concretized, use the rhs deps only
            itr = branch_to_inputs[get_label_info(l)->l2];
          } else if (citr->second == 2) {
            // if the rhs is concretized, use the lhs deps only
            itr = branch_to_inputs[get_label_info(l)->l1];
          }
        }
        if (unlikely(itr.find_first() == input_dep_t::npos)) {
          // not actual input dependency, skip
          continue;
        }
        // for each input byte used in the var, we collect additional constraints
        // first, we use union find to add additional related input bytes
        std::unordered_set<size_t> related_inputs;
        for (auto input = itr.find_first(); input != input_dep_t::npos;
             input = itr.find_next(input)) {
          data_flow_deps.get_set(input, related_inputs); // FIXME: should be fine?
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
        task_t nested_task = construct_task(nested_caluse);
        if (nested_task != nullptr) {
          nested_task->base_task = task;
          tasks.push_back(save_task(nested_task));
        }
      }
    }
  }

  if (solve_nested_ && add_nested) {
    save_constraint(orig_root, result);
  }

  return 0;
}

bool RGDAstParser::save_constraint(expr_t expr, bool result) {
  // assumes scan_labels has been called

  // make a copy of the expr, just in case
  expr_t root = std::make_shared<rgd::AstNode>();
  root->CopyFrom(*expr);

  // first, convert the formula to NNF form, possibly negate the root
  // if we are looking for a false formula
  if (to_nnf(result, root.get()) != 0) {
    return false;
  }
#if DEBUG
  printAst(stderr, root.get(), 0);
#endif
  // then we need to convert the boolean formula into a DNF form
  // NOTE: all ptrs in the formula are raw ptrs *temporarily*
  // burrowed from the root expr, they will be gone after return
  formula_t dnf;
  to_dnf(root.get(), dnf);

  // now we associate the constraints with input bytes
  for (auto const& clause : dnf) {
    // each clause is a conjunction of relational expressions
    // that need to be evaluated to true (satisfied)
    // we associate that with the corresponding input bytes
    for (auto const& var : clause) {
      // copy the node, as the original node will be gone after return
      expr_t node = std::make_shared<rgd::AstNode>();
      node->CopyFrom(*var);
      // get the input bytes
      const dfsan_label l = node->label();
#if DEBUG
      assert(branch_to_inputs.size() > l);
#endif
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
        if (unlikely(root == rgd::UnionFind::INVALID)) {
          WARNF("invalid input to union find\n");
          return false;
        }
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

void RGDAstParser::add_nested_constraint(task_t task, const clause_t &nested_caluse) {
  for (auto const& node: nested_caluse) {
    // check cache, should happen most of the time
    auto itr = constraint_cache.find(node->label());
    if (likely(itr != constraint_cache.end())) {
      task->constraints.push_back(itr->second);
      task->comparisons.push_back(node->kind());
      continue;
    }
    // otherwise, parse the AST into a constraint
    constraint_t constraint = parse_constraint(node->label());
    if (likely(constraint != nullptr)) {
      task->constraints.push_back(constraint);
      task->comparisons.push_back(node->kind());
      constraint_cache.insert({node->label(), constraint});
    }
  }
}

int RGDAstParser::parse_gep(dfsan_label ptr_label, uptr ptr,
                            dfsan_label index_label, int64_t index,
                            uint64_t num_elems, uint64_t elem_size,
                            int64_t current_offset, bool enum_index,
                            std::vector<uint64_t> &tasks) {
  // check validity of the labels
  if (index_label < CONST_OFFSET || index_label == __dfsan::kInitializingLabel || index_label >= size_) {
    return -1;
  }

  // update ast_size and branch_to_inputs caches
  // if the index_label has been scanned before, it won't be scanned again
  if (!scan_labels(index_label)) {
    return -1;
  }

  // sanity checks
  if (unlikely(ast_size_cache.size() <= index_label)) {
    WARNF("invalid label %u, larger than ast_size_cache: %lu\n", index_label, ast_size_cache.size());
    return -1;
  }
  if (unlikely(nested_cmp_cache.at(index_label) > 0)) {
    WARNF("unexpected nested cmp in parse_gep for %u, skip\n", index_label);
    return -1;
  }

  auto ast_size = ast_size_cache.at(index_label);
  if (unlikely(ast_size == 0)) {
    WARNF("invalid label %u, ast_size_cache is 0\n", index_label);
    return 0;
  } else if (unlikely(ast_size > max_ast_size_)) {
    DEBUGF("skip large AST (%lu) in parse_gep for %u\n", ast_size, index_label);
    return 0; // not an error, just skip
  }

  // early return if nothing to check
  if (!enum_index) {
    if (num_elems == 0 &&
        (ptr_label == 0 || get_label_info(ptr_label)->op != __dfsan::Alloca)) {
      return 0;
    }
  }

  // hmm, since the gep constraints we want to solve are not in the union table,
  // which means parse_constraint will not work,
  // so we have to construct the tasks directly here
  //

  // first, parse the index_label into a partial constraint
  // again, the index_label is not a cmp node
  constraint_t partial_constraint = nullptr;
  // check cache first
  auto itr = constraint_cache.find(index_label);
  if (itr != constraint_cache.end()) {
    partial_constraint = itr->second;
  } else {
    // otherwise, parse the AST into a constraint
    std::unordered_set<dfsan_label> visited;
    partial_constraint = std::make_shared<rgd::Constraint>(ast_size + 3); // leave extra one buffer?

    // add the constant node first
    auto const_node = partial_constraint->ast->add_children();
    const_node->set_kind(rgd::Constant);
    const_node->set_label(0);
    uint32_t size = get_label_info(index_label)->size;
    const_node->set_bits(size); // size of the index
    // map args
    uint32_t arg_index = 0; // first arg
    const_node->set_index(arg_index);
    partial_constraint->input_args.push_back(std::make_pair(false, 0)); // use 0 as a temporary placeholder
    partial_constraint->const_num += 1;
    uint32_t hash = rgd::xxhash(size, rgd::Constant, arg_index);
    const_node->set_hash(hash);

    // now, parse the index_label
    auto index_node = partial_constraint->ast->add_children();
    try {
      if (!do_uta_rel(index_label, index_node, partial_constraint, visited)) {
        WARNF("failed to parse index_label %u\n", index_label);
        return -1;
      }
    } catch (std::bad_alloc &e) {
      WARNF("failed to allocate memory for gep constraint\n");
      return -1;
    } catch (std::out_of_range &e) {
      WARNF("AST %u goes out of range at %s\n", index_label, e.what());
      return -1;
    }

    // setup root cmp node
    auto cmp_node = partial_constraint->ast.get();
    cmp_node->set_kind(rgd::Equal); // a placeholder, not really useful
    cmp_node->set_label(0); // so jigsaw will not cache it as visited
    cmp_node->set_bits(1);
    // again, in jigsaw, we don't care about actual cmp kind
    hash = rgd::xxhash(const_node->hash(), (rgd::Bool << 16) | 1, index_node->hash());
    cmp_node->set_hash(hash);

    // done parsing, add to cache
    constraint_cache.insert({index_label, partial_constraint});
  }

  if (unlikely(partial_constraint == nullptr)) {
    WARNF("failed to parse index_label %u\n", index_label);
    return -1;
  }

  // next, retrive nested constraints if needed
  clause_t nested_caluse;
  if (solve_nested_) {
    auto &itr = branch_to_inputs[index_label];
    if (unlikely(itr.find_first() != input_dep_t::npos)) {
      // use union find to add additional related input bytes
      std::unordered_set<size_t> related_inputs;
      for (auto input = itr.find_first(); input != input_dep_t::npos;
           input = itr.find_next(input)) {
        data_flow_deps.get_set(input, related_inputs); // FIXME: should be fine?
      }
      // collect the branch constraints for each related input byte
      std::unordered_set<dfsan_label> inserted;
      for (auto input: related_inputs) {
        auto const& bucket = input_to_branches[input];
        for (auto const& nc : bucket) {
          if (inserted.insert(nc->label()).second) {
#if DEBUG
            fprintf(stderr, "add nested constraint for gep: (%d, %d)\n", nc->label(), nc->kind());
#endif
            nested_caluse.push_back(nc.get()); // XXX: borrow the raw ptr, should be fine?
          }
        }
      }
    }
  }

  // finally, we are ready to construct GEP tasks
  //

  if (enum_index) {
    // TODO:
  }

  // bounds check
  if (num_elems > 0) {
    // array with known size
    //
    // check underflow, 0 > index
    constraint_t underflow = std::make_shared<rgd::Constraint>(*partial_constraint);
    underflow->op1 = 0;
    underflow->op2 = index;
    task_t uf_task = std::make_shared<rgd::SearchTask>();
    uf_task->constraints.push_back(underflow);
    uf_task->comparisons.push_back(rgd::Sgt); // signed GT
    uf_task->finalize();
    tasks.push_back(save_task(uf_task));
    if (solve_nested_) {
      task_t nested_task = std::make_shared<rgd::SearchTask>();
      uf_task->constraints.push_back(underflow);
      uf_task->comparisons.push_back(rgd::Sgt);
      add_nested_constraint(nested_task, nested_caluse);
      nested_task->finalize();
      tasks.push_back(save_task(nested_task));
    }
    // check overflow, num_elems <= index
    constraint_t overflow = std::make_shared<rgd::Constraint>(*partial_constraint);
    overflow->input_args[0].second = num_elems; // IMPORTANT: fix the constant arg
    overflow->op1 = num_elems;
    overflow->op2 = index;
    task_t of_task = std::make_shared<rgd::SearchTask>();
    of_task->constraints.push_back(overflow);
    of_task->comparisons.push_back(rgd::Ule); // unsigned LE
    of_task->finalize();
    tasks.push_back(save_task(of_task));
    if (solve_nested_) {
      task_t nested_task = std::make_shared<rgd::SearchTask>();
      of_task->constraints.push_back(overflow);
      of_task->comparisons.push_back(rgd::Ule);
      add_nested_constraint(nested_task, nested_caluse);
      nested_task->finalize();
      tasks.push_back(save_task(nested_task));
    }
  } else {
    // struct or array with unknown compile time size
    auto bounds_info = get_label_info(ptr_label);
    if (bounds_info->op == __dfsan::Alloca) {
      // bounds information is available, check if allocation size is symbolic
      if (bounds_info->l2 ==0) {
        // concrete allocation size, check bounds
        // check underflow, lower_bound > index * elem_size + current_offset + ptr
        // => (lower_bound - current_offset - ptr) / elem_size > index
        constraint_t underflow = std::make_shared<rgd::Constraint>(*partial_constraint);
        uint64_t lower_bound = (bounds_info->op1.i - current_offset - ptr) / elem_size;
        underflow->input_args[0].second = lower_bound; // IMPORTANT: fix the constant arg
        underflow->op1 = lower_bound;
        underflow->op2 = index;
        task_t uf_task = std::make_shared<rgd::SearchTask>();
        uf_task->constraints.push_back(underflow);
        uf_task->comparisons.push_back(rgd::Ugt); // unsigned GT, automatically detects integer overflow
        uf_task->finalize();
        tasks.push_back(save_task(uf_task));
        if (solve_nested_) {
          task_t nested_task = std::make_shared<rgd::SearchTask>();
          uf_task->constraints.push_back(underflow);
          uf_task->comparisons.push_back(rgd::Ugt);
          add_nested_constraint(nested_task, nested_caluse);
          nested_task->finalize();
          tasks.push_back(save_task(nested_task));
        }
        // check overflow, upper_bound <= index * elem_size + current_offset + ptr
        // => (upper_bound - current_offset - ptr) / elem_size <= index
        constraint_t overflow = std::make_shared<rgd::Constraint>(*partial_constraint);
        uint64_t upper_bound = (bounds_info->op2.i - current_offset - ptr) / elem_size;
        overflow->input_args[0].second = upper_bound; // IMPORTANT: fix the constant arg
        overflow->op1 = upper_bound;
        overflow->op2 = index;
        task_t of_task = std::make_shared<rgd::SearchTask>();
        of_task->constraints.push_back(overflow);
        of_task->comparisons.push_back(rgd::Ule); // unsigned LE
        of_task->finalize();
        tasks.push_back(save_task(of_task));
        if (solve_nested_) {
          task_t nested_task = std::make_shared<rgd::SearchTask>();
          of_task->constraints.push_back(overflow);
          of_task->comparisons.push_back(rgd::Ule);
          add_nested_constraint(nested_task, nested_caluse);
          nested_task->finalize();
          tasks.push_back(save_task(nested_task));
        }
      } else {
        // TODO: check size overflow
        // index * elem_size + current_offset + ptr > array_size * alloc_elem_size
      }
    }
  }

  return 0;
}

int RGDAstParser::add_constraints(dfsan_label label, uint64_t result) {
  // offset constraint should be in the form of r = (offset == label) = true
  if (!solve_nested_) {
    // only matters in nested mode
    return 0;
  }

  // check validity of the label
  if (label < CONST_OFFSET || label == __dfsan::kInitializingLabel || label >= size_) {
    return -1;
  }
  // check validity of the result
  if (result != 1) {
    WARNF("unexpected result in add_constraints: %lu\n", result);
    return -1;
  }

  expr_t root = nullptr;
  auto itr = root_expr_cache.find(label);
  if (itr != root_expr_cache.end()) {
    // the constraint has already been added, skip
    return 0;
  }

  // update ast_size and branch_to_inputs caches
  if (!scan_labels(label)) {
    return -1;
  }
  // other sanitity checks
  // 1. there shouldn't be any nested cmp
  if (nested_cmp_cache[label] > 0) {
    WARNF("unexpected nested cmp in add_constraints for %u\n", label);
    return -1;
  }
  dfsan_label_info *info = get_label_info(label);
  // 2. the label should be a bveq one
  if (!is_rel_cmp(info->op, __dfsan::bveq)) {
    WARNF("unexpected cmp op (%d) in add_constraints for %u\n", info->op, label);
    return -1;
  }
  // 3. one operand should be a constant
  if (info->l1 != 0) {
    WARNF("unexpected non-constant operand1 (%u) in add_constraints for %u\n", info->l1, label);
    return -1;
  }
  // check for ast size
  if (ast_size_cache[info->l2] > max_ast_size_) {
    DEBUGF("skip large AST (%lu) in add_constraints for %u\n", ast_size_cache[label], label);
    return 0; // not an error, just skip
  }
  // setup node
  root = std::make_shared<rgd::AstNode>(1);
  root->set_bits(1);
  root->set_kind(rgd::Equal);
  root->set_label(label);
  root_expr_cache.insert({label, root});

  if (!save_constraint(root, true)) {
    return -1;
  }

  return 0;
}
