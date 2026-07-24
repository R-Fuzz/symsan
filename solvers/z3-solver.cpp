#include "solver.h"

#include <z3++.h>

#include <string.h>

using namespace rgd;

#define DEBUG 0

#if !DEBUG
#undef DEBUGF
#define DEBUGF(_str...) do { } while (0)
#elif !defined (DEBUGF)
#define DEBUGF(_str...) do { fprintf(stderr, _str); } while (0)
#endif

#ifndef WARNF
#define WARNF(_str...) do { fprintf(stderr, _str); } while (0)
#endif

z3::context g_z3_context;
const unsigned kSolverTimeout = 10000; // 10 seconds

Z3Solver::Z3Solver()
    // QF_BVFP (bit-vectors + floating point) rather than QF_BV: FP constraints
    // built for FCmp/FP-arith need the floating-point theory.  Under plain
    // QF_BV z3 treats the FloatingPoint sort as uninterpreted (finite-universe
    // model) and returns spurious SAT with a bogus all-zero solution.  BVFP is
    // still a quantifier-free, bit-blasted logic, so the common BV-only tasks
    // are unaffected.
    : context_(g_z3_context), solver_(z3::solver(context_, "QF_BVFP"))
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

//===----------------------------------------------------------------------===//
// Floating-point helpers (mirror solvers/z3-ts.cpp)
//
// FP-typed labels are represented as bit-vectors holding the IEEE-754 encoding
// (matching how the runtime stores operands and how inputs are byte-BVs).  The
// RGD AstNode tree keeps FP operands/results as BV children; these helpers lift
// a BV to the fpa theory, lower a fpa result back to a BV, and build/evaluate
// FCmp.  Rounding follows the z3 context default (RNE), matching LLVM's default
// FP environment.  Rounding-mode selectors match __dfsan::fp_rounding_mode
// (rna=0, rne=1, rtp=2, rtn=3, rtz=4); FpRound carries one in AstNode::index().
//===----------------------------------------------------------------------===//

static z3::sort fpa_sort_for(z3::context &ctx, unsigned bits) {
  switch (bits) {
    case 16: return ctx.fpa_sort<16>();
    case 32: return ctx.fpa_sort<32>();
    case 64: return ctx.fpa_sort<64>();
    default: throw z3::exception("unsupported floating-point width");
  }
}

// Reinterpret an IEEE-754 bit-vector as a floating-point value.
static z3::expr bv_to_fp(z3::context &ctx, const z3::expr &bv, unsigned bits) {
  return bv.mk_from_ieee_bv(fpa_sort_for(ctx, bits));
}

// Lower a floating-point value back to its IEEE-754 bit-vector encoding.
static z3::expr fp_to_bv(const z3::expr &fp) {
  return fp.mk_to_ieee_bv();
}

// Build a z3 rounding-mode expression from an fp_rounding_mode selector.
static z3::expr get_rm(z3::context &ctx, uint32_t sel) {
  switch (sel) {
    case 0:  return z3::expr(ctx, Z3_mk_fpa_rna(ctx)); // rna
    case 1:  return z3::expr(ctx, Z3_mk_fpa_rne(ctx)); // rne
    case 2:  return z3::expr(ctx, Z3_mk_fpa_rtp(ctx)); // rtp
    case 3:  return z3::expr(ctx, Z3_mk_fpa_rtn(ctx)); // rtn
    case 4:  return z3::expr(ctx, Z3_mk_fpa_rtz(ctx)); // rtz
    default: return z3::expr(ctx, Z3_mk_fpa_rne(ctx));
  }
}

// Build a boolean expression for an FCmp with the given LLVM predicate (0..15).
// lhs/rhs must be fpa-sorted.  Ordered (O*) predicates are false when either
// operand is NaN; unordered (U*) predicates are true when either is NaN.
static z3::expr get_fcmp(z3::expr const &lhs, z3::expr const &rhs, uint32_t predicate) {
  z3::context &ctx = lhs.ctx();
  z3::expr nan_a(ctx, Z3_mk_fpa_is_nan(ctx, lhs));
  z3::expr nan_b(ctx, Z3_mk_fpa_is_nan(ctx, rhs));
  z3::expr unordered = (nan_a || nan_b);
  z3::expr eq(ctx, Z3_mk_fpa_eq(ctx, lhs, rhs));   // ordered equality (false on NaN)
  z3::expr lt(ctx, Z3_mk_fpa_lt(ctx, lhs, rhs));
  z3::expr gt(ctx, Z3_mk_fpa_gt(ctx, lhs, rhs));
  z3::expr le(ctx, Z3_mk_fpa_leq(ctx, lhs, rhs));
  z3::expr ge(ctx, Z3_mk_fpa_geq(ctx, lhs, rhs));
  switch (predicate) {
    case 0:  return ctx.bool_val(false);  // FCMP_FALSE
    case 1:  return eq;                    // FCMP_OEQ
    case 2:  return gt;                    // FCMP_OGT
    case 3:  return ge;                    // FCMP_OGE
    case 4:  return lt;                    // FCMP_OLT
    case 5:  return le;                    // FCMP_OLE
    case 6:  return (lt || gt);            // FCMP_ONE (ordered and not equal)
    case 7:  return (!unordered);          // FCMP_ORD (no NaN)
    case 8:  return unordered;             // FCMP_UNO (either NaN)
    case 9:  return (unordered || eq);     // FCMP_UEQ
    case 10: return (unordered || gt);     // FCMP_UGT
    case 11: return (unordered || ge);     // FCMP_UGE
    case 12: return (unordered || lt);     // FCMP_ULT
    case 13: return (unordered || le);     // FCMP_ULE
    case 14: return (!eq);                 // FCMP_UNE (unordered or not equal)
    case 15: return ctx.bool_val(true);    // FCMP_TRUE
    default: throw z3::exception("unsupported fcmp predicate");
  }
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
    // floating-point arithmetic.  FP operands/results are IEEE-754 bit-vectors of
    // the same width; lift both children to fpa, compute (rounding = context
    // default RNE), lower back to BV.
    case rgd::FAdd:
    case rgd::FSub:
    case rgd::FMul:
    case rgd::FDiv:
    case rgd::FRem: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      unsigned bits = node->children(0).bits();
      z3::expr f1 = bv_to_fp(context_, c1, bits);
      z3::expr f2 = bv_to_fp(context_, c2, bits);
      z3::expr fr(context_);
      switch (node->kind()) {
        case rgd::FAdd: fr = f1 + f2; break;
        case rgd::FSub: fr = f1 - f2; break;
        case rgd::FMul: fr = f1 * f2; break;
        case rgd::FDiv: fr = f1 / f2; break;
        // NOTE: z3 fpa_rem is the IEEE-754 remainder, which differs from
        // LLVM frem / C fmod for some inputs (sign/magnitude of result).
        case rgd::FRem: fr = z3::rem(f1, f2); break;
      }
      return cache_expr(node->label(), fp_to_bv(fr), expr_cache);
    }
    case rgd::FNeg: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr fp = bv_to_fp(context_, c1, node->children(0).bits());
      z3::expr r(context_, Z3_mk_fpa_neg(context_, fp));
      return cache_expr(node->label(), fp_to_bv(r), expr_cache);
    }
    // floating-point casts.  FP-typed operands carry the IEEE-754 encoding as a
    // bit-vector, so we lift the source to fpa, convert, then (for FP results)
    // lower back to a BV.  Int results (FpToSi/FpToUi/FpLrint) stay as BV.
    case rgd::FpToSi:
    case rgd::FpToUi: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      unsigned src_bits = node->children(0).bits();
      z3::expr fp = bv_to_fp(context_, c1, src_bits);
      z3::expr r = (node->kind() == rgd::FpToSi) ?
        z3::expr(context_, Z3_mk_fpa_to_sbv(context_, get_rm(context_, 4 /*rtz*/), fp, node->bits())) :
        z3::expr(context_, Z3_mk_fpa_to_ubv(context_, get_rm(context_, 4 /*rtz*/), fp, node->bits()));
      // z3's fpa.to_sbv/to_ubv is a *partial* function: for NaN/inf and values
      // outside the target integer range the result is unconstrained, letting the
      // solver pick an out-of-range operand and assign the result freely (a bogus
      // solution that doesn't match C truncation).  Constrain the operand to the
      // representable range so the conversion is well-defined.  See z3-ts.cpp for
      // the rationale on the 2^63-1024 / 2^64-2048 upper bounds (INT64_MAX and
      // UINT64_MAX are not representable as doubles and round *up* out of range).
      { z3::sort ssort = fpa_sort_for(context_, src_bits);
        double lo, hi;
        if (node->kind() == rgd::FpToSi) {
          if (node->bits() >= 64) { lo = -9223372036854775808.0; hi = 9223372036854774784.0; }
          else { lo = -(double)(1ULL << (node->bits() - 1)); hi = (double)((1ULL << (node->bits() - 1)) - 1); }
        } else {
          lo = 0.0;
          hi = (node->bits() >= 64) ? 18446744073709549568.0 : (double)((1ULL << node->bits()) - 1);
        }
        z3::expr flo(context_, Z3_mk_fpa_numeral_double(context_, lo, ssort));
        z3::expr fhi(context_, Z3_mk_fpa_numeral_double(context_, hi, ssort));
        aux_constraints_.push_back(z3::expr(context_, Z3_mk_fpa_geq(context_, fp, flo)));
        aux_constraints_.push_back(z3::expr(context_, Z3_mk_fpa_leq(context_, fp, fhi)));
      }
      return cache_expr(node->label(), r, expr_cache);
    }
    case rgd::SiToFp:
    case rgd::UiToFp: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::sort fs = fpa_sort_for(context_, node->bits());
      z3::expr fp = (node->kind() == rgd::SiToFp) ?
        z3::expr(context_, Z3_mk_fpa_to_fp_signed(context_, get_rm(context_, 1 /*rne*/), c1, fs)) :
        z3::expr(context_, Z3_mk_fpa_to_fp_unsigned(context_, get_rm(context_, 1 /*rne*/), c1, fs));
      return cache_expr(node->label(), fp_to_bv(fp), expr_cache);
    }
    case rgd::FpTrunc:
    case rgd::FpExt: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr fp = bv_to_fp(context_, c1, node->children(0).bits());
      z3::expr fp2(context_, Z3_mk_fpa_to_fp_float(context_, get_rm(context_, 1 /*rne*/), fp,
                                                   fpa_sort_for(context_, node->bits())));
      return cache_expr(node->label(), fp_to_bv(fp2), expr_cache);
    }
    // floating-point unary intrinsics.  FpRound carries the rounding-mode
    // selector (fp_rounding_mode) in AstNode::index().
    case rgd::FpFabs:
    case rgd::FpSqrt:
    case rgd::FpRound: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr fp = bv_to_fp(context_, c1, node->children(0).bits());
      z3::expr r(context_);
      switch (node->kind()) {
        case rgd::FpFabs:
          r = z3::expr(context_, Z3_mk_fpa_abs(context_, fp)); break;
        case rgd::FpSqrt:
          r = z3::expr(context_, Z3_mk_fpa_sqrt(context_, get_rm(context_, 1 /*rne*/), fp)); break;
        case rgd::FpRound:
          r = z3::expr(context_, Z3_mk_fpa_round_to_integral(context_, get_rm(context_, node->index()), fp)); break;
      }
      return cache_expr(node->label(), fp_to_bv(r), expr_cache);
    }
    // floating-point binary intrinsics (minnum/maxnum/copysign).
    case rgd::FpMin:
    case rgd::FpMax:
    case rgd::FpCopysign: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      z3::expr c2 = serialize(&node->children(1), input_args, expr_cache);
      unsigned bits = node->children(0).bits();
      if (node->kind() == rgd::FpCopysign) {
        // copysign is pure bit manipulation: magnitude of x, sign bit of y.
        z3::expr signmask = context_.bv_val((uint64_t)1 << (bits - 1), bits);
        return cache_expr(node->label(), (c1 & ~signmask) | (c2 & signmask), expr_cache);
      }
      z3::expr f1 = bv_to_fp(context_, c1, bits);
      z3::expr f2 = bv_to_fp(context_, c2, bits);
      z3::expr r = (node->kind() == rgd::FpMin) ?
        z3::expr(context_, Z3_mk_fpa_min(context_, f1, f2)) :
        z3::expr(context_, Z3_mk_fpa_max(context_, f1, f2));
      return cache_expr(node->label(), fp_to_bv(r), expr_cache);
    }
    // floating-point predicates (isnan/isinf/finite/signbit).  Unary FP operand;
    // integer result of width node->bits() feeding a normal ICmp.
    case rgd::FpIsNan:
    case rgd::FpIsInf:
    case rgd::FpIsFinite:
    case rgd::FpSignbit: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      unsigned src_bits = node->children(0).bits();
      if (node->kind() == rgd::FpSignbit) {
        // signbit is a pure bit read: the IEEE sign bit is the MSB of the BV.
        // Zero-extend that 1-bit value to the int result width (correct for -0).
        z3::expr sign = c1.extract(src_bits - 1, src_bits - 1);
        return cache_expr(node->label(), z3::zext(sign, node->bits() - 1), expr_cache);
      }
      z3::expr fp = bv_to_fp(context_, c1, src_bits);
      z3::expr cond(context_);
      switch (node->kind()) {
        case rgd::FpIsNan:
          cond = z3::expr(context_, Z3_mk_fpa_is_nan(context_, fp)); break;
        case rgd::FpIsInf:
          cond = z3::expr(context_, Z3_mk_fpa_is_infinite(context_, fp)); break;
        case rgd::FpIsFinite: {
          z3::expr nan(context_, Z3_mk_fpa_is_nan(context_, fp));
          z3::expr inf(context_, Z3_mk_fpa_is_infinite(context_, fp));
          cond = !nan && !inf; break;
        }
      }
      return cache_expr(node->label(),
                        z3::ite(cond, context_.bv_val(1, node->bits()),
                                context_.bv_val(0, node->bits())),
                        expr_cache);
    }
    // round-to-nearest-integer libcalls (lrint/llrint).  Round with the default
    // mode (RNE) then convert to a signed integer of width node->bits().  Like
    // FpToSi, z3's fpa.to_sbv is a partial function, so constrain the operand.
    case rgd::FpLrint: {
      z3::expr c1 = serialize(&node->children(0), input_args, expr_cache);
      unsigned src_bits = node->children(0).bits();
      z3::expr fp = bv_to_fp(context_, c1, src_bits);
      z3::expr r(context_, Z3_mk_fpa_to_sbv(context_, get_rm(context_, 1 /*rne*/), fp, node->bits()));
      { z3::sort ssort = fpa_sort_for(context_, src_bits);
        double lo, hi;
        if (node->bits() >= 64) { lo = -9223372036854775808.0; hi = 9223372036854774784.0; }
        else { lo = -(double)(1ULL << (node->bits() - 1)); hi = (double)((1ULL << (node->bits() - 1)) - 1); }
        z3::expr flo(context_, Z3_mk_fpa_numeral_double(context_, lo, ssort));
        z3::expr fhi(context_, Z3_mk_fpa_numeral_double(context_, hi, ssort));
        aux_constraints_.push_back(z3::expr(context_, Z3_mk_fpa_geq(context_, fp, flo)));
        aux_constraints_.push_back(z3::expr(context_, Z3_mk_fpa_leq(context_, fp, fhi)));
      }
      return cache_expr(node->label(), r, expr_cache);
    }
    // FP transcendentals (exp/exp2/log/log2/log10/log1p/pow) are i2s-only: z3's
    // fpa theory has no operation to invert them, so reject explicitly and let
    // the chain fall back (the i2s solver, tried first, handles these).
    case rgd::FpExp:
    case rgd::FpExp2:
    case rgd::FpLog:
    case rgd::FpLog2:
    case rgd::FpLog10:
    case rgd::FpLog1p:
    case rgd::FpPow:
      throw z3::exception("unsupported FP transcendental (i2s-only)");
      break;
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

  // floating-point comparison: operands are IEEE-754 bit-vectors; lift both to
  // fpa and build a NaN-aware boolean.  The FP relational kinds map directly to
  // LLVM FCmp predicates 1..14 (FOeq..FUne), i.e. (kind - FOeq + 1).
  if (rgd::isFPRelationalKind(comparison)) {
    unsigned bits = node->children(0).bits();
    z3::expr f1 = bv_to_fp(context_, c1, bits);
    z3::expr f2 = bv_to_fp(context_, c2, bits);
    return get_fcmp(f1, f2, comparison - rgd::FOeq + 1);
  }

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
    aux_constraints_.clear(); // drop any FP range constraints from a prior solve
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
    for (size_t i = 0, n = task->size(); i < n; i++) {
      auto const &c = task->constraints(i);
      z3::expr z3expr = serialize_rel(task->comparisons(i), c->get_root(), c->input_args, expr_cache);
      DEBUGF("adding expr %s\n", z3expr.to_string().c_str());
      solver_.add(z3expr);
    }
    // add any auxiliary FP range constraints gathered during serialization so
    // partial fpa.to_sbv/to_ubv conversions stay well-defined.
    for (auto const &aux : aux_constraints_) {
      DEBUGF("adding aux constraint %s\n", aux.to_string().c_str());
      solver_.add(aux);
    }
    auto ret = solver_.check();
    if (ret == z3::sat) {
      memcpy(out_buf, in_buf, in_size);
      out_size = in_size;
      z3::model m = solver_.get_model();
      extract_model(m, out_buf, out_size, task->solution);
      if (!task->atoi_info().empty()) {
        // if there are atoi bytes, handle them
        for (auto const &[offset, info] : task->atoi_info()) {
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
