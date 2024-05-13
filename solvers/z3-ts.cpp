#include "parse.h"

#include "dfsan/dfsan.h"

#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace symsan;

Z3AstParser::Z3AstParser(void *base, size_t size, z3::context &context)
  : ASTParser(base, size), context_(context) {
    input_name_format = "input-%u-%u";
    atoi_name_format = "atoi-%u-%u-%d";
  }

int Z3AstParser::restart(std::vector<input_t> &inputs) {

  // reset caches
  memcmp_cache_.clear();
  tsize_cache_.clear();
  deps_cache_.clear();
  expr_cache_.clear();
  branch_deps_.clear();
  branch_deps_.resize(inputs.size());

  for (size_t i = 0; i < inputs.size(); i++) {
    auto &input = inputs[i];
    // z3parser doesn't use inputs, so we don't need to make a copy of it
    // resize branch_deps_
    branch_deps_[i].resize(input.second);
  }

  return 0;
}

z3::expr Z3AstParser::read_concrete(dfsan_label label, uint16_t size) {
  auto itr = memcmp_cache_.find(label);
  if (itr == memcmp_cache_.end()) {
    throw z3::exception("cannot find memcmp content");
  }

  z3::expr val = context_.bv_val(itr->second[0], 8);
  for (uint8_t i = 1; i < size; i++) {
    val = z3::concat(context_.bv_val(itr->second[i], 8), val);
  }
  return val;
}

static z3::expr get_cmd(z3::expr const &lhs, z3::expr const &rhs, uint32_t predicate) {
  switch (predicate) {
    case __dfsan::bveq:  return lhs == rhs;
    case __dfsan::bvneq: return lhs != rhs;
    case __dfsan::bvugt: return z3::ugt(lhs, rhs);
    case __dfsan::bvuge: return z3::uge(lhs, rhs);
    case __dfsan::bvult: return z3::ult(lhs, rhs);
    case __dfsan::bvule: return z3::ule(lhs, rhs);
    case __dfsan::bvsgt: return lhs > rhs;
    case __dfsan::bvsge: return lhs >= rhs;
    case __dfsan::bvslt: return lhs < rhs;
    case __dfsan::bvsle: return lhs <= rhs;
    default:
      throw z3::exception("unsupported predicate");
      break;
  }
  // should never reach here
  // std::unreachable();
}

z3::expr Z3AstParser::serialize(dfsan_label label, input_dep_set_t &deps) {
  if (label < CONST_OFFSET || label == __dfsan::kInitializingLabel) {
    throw z3::exception("invalid label");
  }

  dfsan_label_info *info = get_label_info(label);
  // printf("%u = (l1:%u, l2:%u, op:%u, size:%u, op1:%lu, op2:%lu)\n",
  //       label, info->l1, info->l2, info->op, info->size, info->op1.i, info->op2.i);

  auto expr_itr = expr_cache_.find(label);
  if (expr_itr != expr_cache_.end()) {
    auto deps_itr = deps_cache_.find(label);
    deps.insert(deps_itr->second.begin(), deps_itr->second.end());
    return expr_itr->second;
  }

  // special ops
  char name[256];
  if (info->op == 0) {
    // input
    uint32_t offset = info->op1.i; // legacy: offset in op1
    uint32_t input = info->op2.i;
    snprintf(name, sizeof(name), input_name_format, input, offset);
    z3::symbol symbol = context_.str_symbol(name);
    z3::sort sort = context_.bv_sort(8);
    tsize_cache_[label] = 1; // lazy init
    deps.insert(std::make_pair(input, offset));
    // caching is not super helpful
    return context_.constant(symbol, sort);
  } else if (info->op == __dfsan::Load) {
    uint32_t offset = get_label_info(info->l1)->op1.i; // legacy: offset in op1
    uint32_t input = get_label_info(info->l1)->op2.i;
    snprintf(name, sizeof(name), input_name_format, input, offset);
    z3::symbol symbol = context_.str_symbol(name);
    z3::sort sort = context_.bv_sort(8);
    z3::expr out = context_.constant(symbol, sort);
    deps.insert(std::make_pair(input, offset));
    for (uint32_t i = 1; i < info->l2; i++) {
      snprintf(name, sizeof(name), input_name_format, input, offset + i);
      symbol = context_.str_symbol(name);
      out = z3::concat(context_.constant(symbol, sort), out);
      deps.insert(std::make_pair(input, offset + i));
    }
    tsize_cache_[label] = 1; // lazy init
    return cache_expr(label, out, deps);
  } else if (info->op == __dfsan::ZExt) {
    z3::expr base = serialize(info->l1, deps);
    if (base.is_bool()) // dirty hack since llvm lacks bool
      base = z3::ite(base, context_.bv_val(1, 1),
                           context_.bv_val(0, 1));
    uint32_t base_size = base.get_sort().bv_size();
    tsize_cache_[label] = tsize_cache_[info->l1]; // lazy init
    return cache_expr(label, z3::zext(base, info->size - base_size), deps);
  } else if (info->op == __dfsan::SExt) {
    z3::expr base = serialize(info->l1, deps);
    uint32_t base_size = base.get_sort().bv_size();
    tsize_cache_[label] = tsize_cache_[info->l1]; // lazy init
    return cache_expr(label, z3::sext(base, info->size - base_size), deps);
  } else if (info->op == __dfsan::Trunc) {
    z3::expr base = serialize(info->l1, deps);
    tsize_cache_[label] = tsize_cache_[info->l1]; // lazy init
    return cache_expr(label, base.extract(info->size - 1, 0), deps);
  } else if (info->op == __dfsan::IntToPtr) {
    z3::expr e = serialize(info->l1, deps);
    tsize_cache_[label] = tsize_cache_[info->l1]; // lazy init
    return cache_expr(label, e, deps);
  } //FIXME: other casting ops (PtrToInt, BitCast)?
  // symsan-defined
  else if (info->op == __dfsan::Extract) {
    z3::expr base = serialize(info->l1, deps);
    tsize_cache_[label] = tsize_cache_[info->l1]; // lazy init
    return cache_expr(label, base.extract((info->op2.i + info->size) - 1, info->op2.i), deps);
  } else if (info->op == __dfsan::Not) {
    if (info->l2 == 0 || info->size != 1) {
      throw z3::exception("invalid Not operation");
    }
    z3::expr e = serialize(info->l2, deps);
    tsize_cache_[label] = tsize_cache_[info->l2]; // lazy init
    if (!e.is_bool()) {
      throw z3::exception("Only LNot should be recorded");
    }
    return cache_expr(label, !e, deps);
  } else if (info->op == __dfsan::Neg) {
    if (info->l2 == 0) {
      throw z3::exception("invalid Neg predicate");
    }
    z3::expr e = serialize(info->l2, deps);
    tsize_cache_[label] = tsize_cache_[info->l2]; // lazy init
    return cache_expr(label, -e, deps);
  }
  // higher-order
  else if (info->op == __dfsan::fmemcmp) {
    z3::expr op1 = (info->l1 >= CONST_OFFSET) ? serialize(info->l1, deps) :
                   read_concrete(label, info->size); // memcmp size in bytes
    if (info->l2 < CONST_OFFSET) {
      throw z3::exception("invalid memcmp operand2");
    }
    z3::expr op2 = serialize(info->l2, deps);
    tsize_cache_[label] = 1; // lazy init
    z3::expr e = z3::ite(op1 == op2, context_.bv_val(0, 32),
                                     context_.bv_val(1, 32));
    return cache_expr(label, e, deps);
  } else if (info->op == __dfsan::fsize) {
    // file size
    z3::symbol symbol = context_.str_symbol("fsize");
    z3::sort sort = context_.bv_sort(info->size);
    z3::expr base = context_.constant(symbol, sort);
    tsize_cache_[label] = 1; // lazy init
    has_fsize = true; // XXX: set a flag
    // don't cache because of deps
    if (info->op1.i) {
      // minus the offset stored in op1
      z3::expr offset = context_.bv_val((uint64_t)info->op1.i, info->size);
      return base - offset;
    } else {
      return base;
    }
  } else if (info->op == __dfsan::fatoi) {
    // string to integer conversion
    assert(info->l1 == 0 && info->l2 >= CONST_OFFSET);
    dfsan_label_info *src = get_label_info(info->l2);
    assert(src->op == __dfsan::Load);
    uint32_t offset = get_label_info(src->l1)->op1.i; // legacy: offset in op1
    uint32_t input = get_label_info(src->l1)->op2.i;
    int base = info->op1.i;
    // FIXME: dependencies?
    tsize_cache_[label] = 1; // lazy init
    // XXX: hacky, avoid string theory
    snprintf(name, sizeof(name), atoi_name_format, input, offset, base);
    z3::symbol symbol = context_.str_symbol(name);
    z3::sort sort = context_.bv_sort(info->size);
    return context_.constant(symbol, sort);
  }

  // common ops
  uint8_t size = info->size;
  // size for concat is a bit complicated ...
  if (info->op == __dfsan::Concat && info->l1 == 0) {
    assert(info->l2 >= CONST_OFFSET);
    size = info->size - get_label_info(info->l2)->size;
  }
  z3::expr op1 = context_.bv_val((uint64_t)info->op1.i, size);
  if (info->l1 >= CONST_OFFSET) {
    op1 = serialize(info->l1, deps).simplify();
  } else if (info->size == 1) {
    op1 = context_.bool_val(info->op1.i == 1);
  }
  if (info->op == __dfsan::Concat && info->l2 == 0) {
    assert(info->l1 >= CONST_OFFSET);
    size = info->size - get_label_info(info->l1)->size;
  }
  z3::expr op2 = context_.bv_val((uint64_t)info->op2.i, size);
  if (info->l2 >= CONST_OFFSET) {
    input_dep_set_t deps2;
    op2 = serialize(info->l2, deps2).simplify();
    deps.insert(deps2.begin(), deps2.end());
  } else if (info->size == 1) {
    op2 = context_.bool_val(info->op2.i == 1);
  }
  // update tree_size
  tsize_cache_[label] = tsize_cache_[info->l1] + tsize_cache_[info->l2];

  switch((info->op & 0xff)) {
    // llvm doesn't distinguish between logical and bitwise and/or/xor
    case __dfsan::And:     return cache_expr(label, info->size != 1 ? (op1 & op2) : (op1 && op2), deps);
    case __dfsan::Or:      return cache_expr(label, info->size != 1 ? (op1 | op2) : (op1 || op2), deps);
    case __dfsan::Xor:     return cache_expr(label, op1 ^ op2, deps);
    case __dfsan::Shl:     return cache_expr(label, z3::shl(op1, op2), deps);
    case __dfsan::LShr:    return cache_expr(label, z3::lshr(op1, op2), deps);
    case __dfsan::AShr:    return cache_expr(label, z3::ashr(op1, op2), deps);
    case __dfsan::Add:     return cache_expr(label, op1 + op2, deps);
    case __dfsan::Sub:     return cache_expr(label, op1 - op2, deps);
    case __dfsan::Mul:     return cache_expr(label, op1 * op2, deps);
    case __dfsan::UDiv:    return cache_expr(label, z3::udiv(op1, op2), deps);
    case __dfsan::SDiv:    return cache_expr(label, op1 / op2, deps);
    case __dfsan::URem:    return cache_expr(label, z3::urem(op1, op2), deps);
    case __dfsan::SRem:    return cache_expr(label, z3::srem(op1, op2), deps);
    // relational
    case __dfsan::ICmp:    return cache_expr(label, get_cmd(op1, op2, info->op >> 8), deps);
    // concat
    case __dfsan::Concat:  return cache_expr(label, z3::concat(op2, op1), deps); // little endian
    default:
      throw z3::exception("unsupported operator");
      break;
  }
  // should never reach here
  // std::unreachable();
}

int Z3AstParser::parse_cond(dfsan_label label, bool result, bool add_nested, std::vector<uint64_t> &tasks) {

  // allocate a new task
  auto task = std::make_shared<z3_task_t>();
  try {
    // reset has_fsize flag
    has_fsize = false;

    // parse last branch cond
    input_dep_set_t inputs;
    z3::expr cond = serialize(label, inputs);

    // add negated last branch condition
    z3::expr r = context_.bool_val(result);
    task->push_back((cond != r));

    // collect additional input deps
    collect_more_deps(inputs);
  
    // add nested constraints
    add_nested_constraints(inputs, task.get());

    // save the task
    tasks.push_back(save_task(task));

    // save nested unless it's a fsize constraints
    if (add_nested && !has_fsize) {
      save_constraint(cond == r, inputs);
    }

    return 0; // success
  } catch (z3::exception e) {
    // logf("WARNING: solving error: %s\n", e.msg());
  }

  // exception happened, nothing added
  return -1;
}

void Z3AstParser::construct_index_tasks(z3::expr &index, uint64_t curr,
                                        uint64_t lb, uint64_t ub, uint64_t step,
                                        z3_task_t &nested, std::vector<uint64_t> &tasks) {

  std::shared_ptr<z3_task_t> task = nullptr;

  // enumerate indices
  for (uint64_t i = lb; i < ub; i += step) {
    if (i == curr) continue;
    z3::expr idx = context_.bv_val(i, 64);
    z3::expr e = (index == idx);
    // allocate a new task
    task = std::make_shared<z3_task_t>();
    task->push_back(e);
    // add nested constraints
    task->insert(task->end(), nested.begin(), nested.end());
    // save the task
    tasks.push_back(save_task(task));
  }

  // check feasibility for OOB
  // upper bound
  z3::expr u = context_.bv_val(ub, 64);
  z3::expr e = z3::uge(index, u);
  task = std::make_shared<z3_task_t>();
  task->push_back(e);
  task->insert(task->end(), nested.begin(), nested.end());
  tasks.push_back(save_task(task));

  // lower bound
  if (lb == 0) {
    e = (index < 0);
  } else {
    z3::expr l = context_.bv_val(lb, 64);
    e = z3::ult(index, l);
  }
  task = std::make_shared<z3_task_t>();
  task->push_back(e);
  task->insert(task->end(), nested.begin(), nested.end());
  tasks.push_back(save_task(task));
}

int Z3AstParser::parse_gep(dfsan_label ptr_label, uptr ptr, dfsan_label index_label, int64_t index,
                           uint64_t num_elems, uint64_t elem_size, int64_t current_offset,
                           std::vector<uint64_t> &tasks) {

  try {
    // prepare current index
    uint8_t size = get_label_info(index_label)->size;
    z3::expr r = context_.bv_val(index, size);

    input_dep_set_t inputs;
    z3::expr i = serialize(index_label, inputs);

    // collect nested constraints
    collect_more_deps(inputs);
    z3_task_t nested_tasks;
    add_nested_constraints(inputs, &nested_tasks);

    // first, check against fixed array bounds if available
    z3::expr idx = z3::zext(i, 64 - size);
    if (num_elems > 0) {
      construct_index_tasks(idx, index, 0, num_elems, 1, nested_tasks, tasks);
    } else {
      dfsan_label_info *bounds = get_label_info(ptr_label);
      // if the array is not with fixed size, check bound info
      if (bounds->op == __dfsan::Alloca) {
        z3::expr es = context_.bv_val(elem_size, 64);
        z3::expr co = context_.bv_val(current_offset, 64);
        if (bounds->l2 == 0) {
          // only perform index enumeration and bound check
          // when the size of the buffer is fixed
          z3::expr p = context_.bv_val(ptr, 64);
          z3::expr np = idx * es + co + p;
          construct_index_tasks(np, index, (uint64_t)bounds->op1.i, (uint64_t)bounds->op2.i, elem_size, nested_tasks, tasks);
        } else {
          // if the buffer size is input-dependent (not fixed)
          // check if over flow is possible
          input_dep_set_t dummy;
          z3::expr bs = serialize(bounds->l2, dummy); // size label
          if (bounds->l1) {
            dummy.clear();
            z3::expr be = serialize(bounds->l1, dummy); // elements label
            bs = bs * be;
          }
          z3::expr e = z3::ugt(idx * es * co, bs);
          auto task = std::make_shared<z3_task_t>();
          task->push_back(e);
          task->insert(task->end(), nested_tasks.begin(), nested_tasks.end());
          tasks.push_back(save_task(task));
        }
      }
    }

    // always preserve
    save_constraint(i == r, inputs);

    return 0; // success
  } catch (z3::exception e) {
    // logf("WARNING: solving error: %s\n", e.msg());
  }

  // exception happened, nothing added
  return -1;
}

int Z3AstParser::add_constraints(dfsan_label label, uint64_t result) {
  try {
    input_dep_set_t inputs;
    z3::expr expr = serialize(label, inputs);
    collect_more_deps(inputs);
    // prepare result
    uint8_t size = get_label_info(label)->size;
    z3::expr r = context_.bv_val(result, size);
    // add constraint
    if (expr.is_bool()) r = context_.bool_val(result);
    save_constraint(expr == r, inputs);
  } catch (z3::exception e) {
    return -1;
  }

  return 0;
}

void Z3AstParser::save_constraint(z3::expr expr, input_dep_set_t &inputs) {
  for (auto off : inputs) {
    auto c = get_branch_dep(off);
    if (c == nullptr) {
      auto nc = std::make_unique<struct branch_dependency>();
      c = nc.get();
      set_branch_dep(off, std::move(nc));
    }
    if (c == nullptr) {
      throw z3::exception("out of memory");
    } else {
      c->input_deps.insert(inputs.begin(), inputs.end());
      c->expr_deps.insert(expr);
    }
  }
}

void Z3AstParser::collect_more_deps(input_dep_set_t &inputs) {
  // collect additional input deps
  std::vector<offset_t> worklist;
  worklist.insert(worklist.begin(), inputs.begin(), inputs.end());
  while (!worklist.empty()) {
    auto off = worklist.back();
    worklist.pop_back();

    auto deps = get_branch_dep(off);
    if (deps != nullptr) {
      for (auto &i : deps->input_deps) {
        if (inputs.insert(i).second)
          worklist.push_back(i);
      }
    }
  }
}

size_t Z3AstParser::add_nested_constraints(input_dep_set_t &inputs, z3_task_t *task) {
  expr_set_t added;
  for (auto &off : inputs) {
    //logf("adding offset %d\n", i.second);
    auto deps = get_branch_dep(off);
    if (deps != nullptr) {
      for (auto &expr : deps->expr_deps) {
        if (added.insert(expr).second) {
          //logf("adding expr: %s\n", expr.to_string().c_str());
          task->push_back(expr);
        }
      }
    }
  }
  return added.size();
}

Z3ParserSolver::solving_status
Z3ParserSolver::solve_task(uint64_t task_id, unsigned timeout, solution_t &solutions) {
  solving_status ret = unknown_error;
  auto task = retrieve_task(task_id);
  if (task == nullptr) {
    return invalid_task;
  }

  try {
    // setup global solver
    z3::solver solver(context_, "QF_BV");
    solver.set("timeout", timeout);
    // solve the first constraint (optimistic)
    z3::expr e = task->at(0);
    solver.add(e);
    z3::check_result res = solver.check();
    if (res == z3::sat) {
      ret = opt_sat;
      // optimistic sat, save a model
      z3::model m = solver.get_model();
      // check nested, if any
      if (task->size() > 1) {
        solver.push();
        // add nested constraints
        for (size_t i = 1; i < task->size(); i++) {
          solver.add(task->at(i));
        }
        res = solver.check();
        if (res == z3::sat) {
          ret = nested_sat;
          m = solver.get_model();
        } else if (res == z3::unsat) {
          ret = opt_sat_nested_unsat;
        } else {
          ret = opt_sat_nested_timeout;
        }
      } else {
        ret = nested_sat; // XXX: upgrade to nested_sat?
      }
      generate_solution(m, solutions);
    } else if (res == z3::unsat) {
      ret = opt_unsat;
      //AOUT("\n%s\n", __z3_solver.to_smt2().c_str());
      //AOUT("  tree_size = %d", __dfsan_label_info[label].tree_size);
    } else {
      ret = opt_timeout;
    }
  } catch (z3::exception ze) {
    ret = unknown_error;
  }

  return ret;
}

void Z3ParserSolver::generate_solution(z3::model &m, solution_t &solutions) {
  // from qsym
  unsigned num_constants = m.num_consts();
  for (unsigned i = 0; i < num_constants; i++) {
    z3::func_decl decl = m.get_const_decl(i);
    z3::expr e = m.get_const_interp(decl);
    z3::symbol name = decl.name();

    // all values should be string symbols
    if (name.kind() == Z3_STRING_SYMBOL) {
      if (name.str().find("input") == 0) {
        uint32_t input;
        uint32_t offset;
        sscanf(name.str().c_str(), input_name_format, &input, &offset);
        uint8_t value = (uint8_t)e.get_numeral_int();
        solutions.push_back({input, offset, value});
      } else if (!name.str().compare("fsize")) {
        // FIXME:
        // off_t size = (off_t)e.get_numeral_int64();
        // if (size > input_size) { // grow
        //   lseek(fd, size, SEEK_SET);
        //   uint8_t dummy = 0;
        //   write(fd, &dummy, sizeof(dummy));
        // } else {
        //   AOUT("truncate file to %ld\n", size);
        //   ftruncate(fd, size);
        // }
        throw z3::exception("skip fsize constraints");
      } else if (name.str().find("atoi") == 0) {
        uint32_t input;
        uint32_t offset;
        int base;
        char buf[64];
        sscanf(name.str().c_str(), atoi_name_format, &input, &offset, &base);
        const char *format = NULL;
        switch (base) {
          case 2: format = "%lb"; break;
          case 8: format = "%lo"; break;
          case 10: format = "%ld"; break;
          case 16: format = "%lx"; break;
          default: throw z3::exception("unsupported base");
        }
        // XXX: assumed signed
        int len = snprintf(buf, 64, format, (int)e.get_numeral_int());
        // len excludes \0
        for (int i = 0; i < len; ++i) {
          solutions.push_back({input, offset + i, (uint8_t)buf[i]});
        }
        solutions.push_back({input, offset + len, 0});
      } else {
        throw z3::exception("unknown symbol");
      }
    }
  }
}
