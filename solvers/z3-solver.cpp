#include "solver.h"

extern "C" {
#include "afl-fuzz.h"
}

using namespace rgd;

#if !DEBUG
#undef DEBUGF
#define DEBUGF(_str...) do { } while (0)
#endif

z3::context g_z3_context;
const unsigned kSolverTimeout = 10000; // 10 seconds

Z3Solver::Z3Solver()
    : context_(g_z3_context), solver_(z3::solver(context_, "QF_BV"))
{
  // Set timeout for solver
  z3::params p(context_);
  p.set(":timeout", kSolverTimeout);
  solver_.set(p);
}

static inline z3::expr
cache_expr(uint32_t label, z3::expr const &e, 
           std::unordered_map<uint32_t, z3::expr> &expr_cache) {	
  if (label != 0)
    expr_cache.insert({label, e});
  return e;
}

z3::expr Z3Solver::serialize(const AstNode* node,
    const std::vector<std::pair<bool, uint64_t>> &input_args,
    std::unordered_map<uint32_t, z3::expr> &expr_cache) {

  auto itr = expr_cache.find(node->label());
  if (node->label() != 0 && itr != expr_cache.end())
    return itr->second;

  switch (node->kind()) {
    case rgd::Bool: {
      // getTrue is actually 1 bit integer 1
      return context_.bool_val(node->boolvalue());
    }
    case rgd::Constant: {
      uint64_t val = input_args[node->index()].second;
      if (node->bits() == 1) {
        return context_.bool_val(val == 1);
      } else if (node->bits() <= 64) {
        return context_.bv_val(val, node->bits());
      } else {
        uint32_t chunks = node->bits() / 64;
        uint32_t remain = node->bits() % 64;
        z3::expr ret = context_.bv_val(val, 64);
        for (uint32_t i = 1; i < chunks; i++) {
          val = input_args[node->index() + i].second;
          ret = z3::concat(context_.bv_val(val, 64), ret);
        }
        if (remain > 0) {
          val = input_args[node->index() + chunks].second;
          ret = z3::concat(context_.bv_val(val, remain), ret);
        }
        return ret;
      }
    }
    case rgd::Read: {
      z3::symbol symbol = context_.int_symbol(node->index());
      z3::sort sort = context_.bv_sort(8);
      z3::expr out = context_.constant(symbol, sort);
      for (uint32_t i = 1; i < node->bits() / 8; i++) {
        symbol = context_.int_symbol(node->index() + i);
        out = z3::concat(context_.constant(symbol, sort), out);
      }
      return cache_expr(node->label(), out, expr_cache);
    }
    case rgd::Concat: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), z3::concat(c2, c1), expr_cache);
    }
    case rgd::Extract: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      return cache_expr(node->label(),
                        c1.extract(node->index() + node->bits() - 1, node->index()),
                        expr_cache);
    }
    case rgd::ZExt: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      if (c1.is_bool())
        c1 = z3::ite(c1, context_.bv_val(1,1), context_.bv_val(0, 1));
      return cache_expr(node->label(),
                        z3::zext(c1, node->bits() - node->children(0).bits()),
                        expr_cache);
    }
    case rgd::SExt: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      return cache_expr(node->label(),
                        z3::sext(c1, node->bits() - node->children(0).bits()),
                        expr_cache);
    }
    case rgd::Add: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), c1 + c2, expr_cache);
    }
    case rgd::Sub: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), c1 - c2, expr_cache);
    }
    case rgd::Mul: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), c1 * c2, expr_cache);
    }
    case rgd::UDiv: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), z3::udiv(c1, c2), expr_cache);
    }
    case rgd::SDiv: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), c1 / c2, expr_cache); 
    }
    case rgd::URem: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), z3::urem(c1, c2), expr_cache);
    }
    case rgd::SRem: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), z3::srem(c1, c2), expr_cache);
    }
    case rgd::Neg: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      return cache_expr(node->label(), -c1, expr_cache);
    }
    case rgd::Not: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      return cache_expr(node->label(), ~c1, expr_cache);
    }
    case rgd::And: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), c1 & c2, expr_cache);
    }
    case rgd::Or: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), c1 | c2, expr_cache);
    }
    case rgd::Xor: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), c1 ^ c2, expr_cache);
    }
    case rgd::Shl: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), z3::shl(c1, c2), expr_cache);
    }
    case rgd::LShr: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), z3::lshr(c1, c2), expr_cache);
    }
    case rgd::AShr: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      return cache_expr(node->label(), z3::ashr(c1, c2), expr_cache);
    }
    // case rgd::LOr: {
    //   z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
    //   z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
    //   return cache_expr(node->label(), c1 || c2, expr_cache);
    // }
    // case rgd::LAnd: {
    //   z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
    //   z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
    //   return cache_expr(node->label(), c1 && c2, expr_cache);
    // }
    // case rgd::LNot: {
    //   z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
    //   return cache_expr(node->label(), !c1, expr_cache);
    // }
    default:
      WARNF("unhandler expr: ");
      throw z3::exception("unsupported operator");
      break;
  }
}

z3::expr Z3Solver::serialize_rel(uint32_t comparison,
    const AstNode* node,
    const std::vector<std::pair<bool, uint64_t>> &input_args,
    std::unordered_map<uint32_t,z3::expr> &expr_cache) {

  if (node->children_size() != 2) {
    throw z3::exception("invalid children size");
  }
  z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
  z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);

  switch(comparison) {
    case rgd::Equal:
    case rgd::Memcmp:
      return c1 == c2;
    case rgd::Distinct:
    case rgd::MemcmpN:
      return c1 != c2;
    case rgd::Ult:
      return z3::ult(c1, c2);
    case rgd::Ule:
      return z3::ule(c1, c2);
    case rgd::Ugt:
      return z3::ugt(c1, c2);
    case rgd::Uge:
      return z3::uge(c1, c2);
    case rgd::Slt:
      return c1 < c2;
    case rgd::Sle:
      return c1 <= c2;
    case rgd::Sgt:
      return c1 > c2;
    case rgd::Sge:
      return c1 >= c2;
    default:
      WARNF("unhandler comparison: %d", comparison);
      throw z3::exception("unsupported operator");
      break;
  }
}

static inline void extract_model(z3::model &m, uint8_t *buf, size_t buf_size,
                                 std::unordered_map<size_t, uint8_t> &solution) {
  unsigned num_constants = m.num_consts();
  for (unsigned i = 0; i< num_constants; i++) {
    z3::func_decl decl = m.get_const_decl(i);
    z3::expr e = m.get_const_interp(decl);
    z3::symbol name = decl.name();
    if (name.kind() == Z3_INT_SYMBOL) {
      uint8_t value = (uint8_t)e.get_numeral_int();
      size_t offset = name.to_int();
      if (offset < buf_size) {
        buf[offset] = value;
        solution[offset] = value;
        DEBUGF("generate_input offset:%zu => %u\n", offset, value);
      } else {
        WARNF("offset %zu out of range %zu\n", offset, buf_size);
      }
    }
  }
}

solver_result_t
Z3Solver::solve(std::shared_ptr<SearchTask> task,
                const uint8_t *in_buf, size_t in_size,
                uint8_t *out_buf, size_t &out_size) {

  try {
    solver_.reset(); // reset solver
    auto base_task = task->base_task;
    std::vector<z3::expr> assumptions;
    while (base_task != nullptr) {
      // no need to solve
      if (base_task->skip_next) {
        DEBUGF("skipping task\n");
        task->skip_next = true; // set the flag for following tasks
        out_size = in_size;
        memcpy(out_buf, in_buf, in_size);
        if (base_task->solved) {
          for (auto const &[offset, value] : base_task->solution) {
            out_buf[offset] = value;
          }
          return SOLVER_SAT;
        } else {
          return SOLVER_UNSAT;
        }
      } else if (base_task->solved) {
        for (auto const &[offset, value] : base_task->solution) {
          z3::symbol symbol = context_.int_symbol(offset);
          z3::sort sort = context_.bv_sort(8);
          z3::expr i = context_.constant(symbol, sort);
          assumptions.push_back(i == value);
        }
      }
      base_task = base_task->base_task;
    }

    std::unordered_map<uint32_t, z3::expr> expr_cache;
    for (size_t i = 0; i < task->constraints.size(); i++) {
      auto const &c = task->constraints[i];
      z3::expr z3expr = serialize_rel(task->comparisons[i], c->get_root(), c->input_args, expr_cache);
      DEBUGF("adding expr %s\n", z3expr.to_string().c_str());
      solver_.add(z3expr);
    }
    auto ret = solver_.check();
    if (ret == z3::sat) {
      memcpy(out_buf, in_buf, in_size);
      out_size = in_size;
      z3::model m = solver_.get_model();
      extract_model(m, out_buf, out_size, task->solution);
      if (unlikely(!task->atoi_info.empty())) {
        // if there are atoi bytes, handle them
        for (auto const &[offset, info] : task->atoi_info) {
          uint64_t val = 0;
          uint32_t length = std::get<0>(info);
          memcpy(out_buf + offset, in_buf + offset, length); // restore?
          for (auto i = length; i != 0; --i) {
            DEBUGF("generate_input atoi offset:%d => %lu\n", offset + i - 1, val);
            auto itr = task->solution.find(offset + i - 1);
            if (itr != task->solution.end())
              val |= itr->second << (8 * (i - 1));
            else
              val |= 0 << (8 * (i - 1));
          }
          uint32_t base = std::get<1>(info);
          uint32_t orig_len = std::get<2>(info);
          DEBUGF("generate_input atoi offset:%d => %lu, base = %d, original len = %d\n",
              offset, val, base, orig_len);
          const char *format = nullptr;
          switch (base) {
            case 2: format = "%lb"; break;
            case 8: format = "%lo"; break;
            case 10: format = "%ld"; break;
            case 16: format = "%lx"; break;
            default: WARNF("unsupported base %d\n", base);
          }
          if (format) {
            snprintf((char*)out_buf + offset, in_size - offset, format, val);
          }
        }
      }
      task->solved = true;
      return SOLVER_SAT;
    } else if (ret == z3::unsat) {
      return SOLVER_UNSAT;
    } else {
      return SOLVER_TIMEOUT;
    }
  } catch (z3::exception e) {
    WARNF("z3 exception %s\n", e.msg());
  }
  return SOLVER_ERROR;
}
