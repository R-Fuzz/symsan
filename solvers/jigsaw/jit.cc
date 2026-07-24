#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/GVN.h"

#include <cassert>
#include <iostream>
#include <unordered_map>

#include "jit.h"
#include "ast.h"
#include "rgdJit.h"

using namespace llvm;
using namespace rgd;

std::unique_ptr<GradJit> JIT;

// --- floating-point codegen helpers --------------------------------------
// Node values in this JIT are always integers of node->bits() width; for an FP
// node that integer holds the raw IEEE-754 encoding.  as_fp() reinterprets such
// an integer as the matching float/double so we can emit native FP ops, and
// as_bits() reinterprets an FP result back to the integer bit-pattern that the
// rest of codegen (and the value cache) expects.
static inline llvm::Type* fp_type(llvm::IRBuilder<> &Builder, unsigned bits) {
  return bits == 32 ? Builder.getFloatTy() : Builder.getDoubleTy();
}
static inline llvm::Value* as_fp(llvm::IRBuilder<> &Builder, llvm::Value* v,
                                 unsigned bits) {
  return Builder.CreateBitCast(v, fp_type(Builder, bits));
}
static inline llvm::Value* as_bits(llvm::IRBuilder<> &Builder, llvm::Value* v,
                                   unsigned bits) {
  return Builder.CreateBitCast(v,
      llvm::Type::getIntNTy(Builder.getContext(), bits));
}

// --- over-width shift / divide-by-zero semantics -------------------------
// Over-width shifts (amount >= bit-width) and integer div/rem by zero are
// UNDEFINED in C/C++ (x86 masks the shift count; integer /0 traps), but are
// fully DEFINED in SMT-LIB2:
//   bvshl / bvlshr by >= width -> 0 ;   bvashr by >= width -> sign fill
//   bvudiv x 0 -> ~0 (all ones)     ;   bvurem x 0 -> x (the dividend)
//   bvsdiv x 0 -> (x s>= 0 ? ~0 : 1);   bvsrem x 0 -> x (the dividend)
// SymSan's z3 backends (z3-solver.cpp / z3-ts.cpp) model these with SMT-LIB
// semantics, so jigsaw must match to keep the i2s->jigsaw->z3 chain sound --
// otherwise jigsaw can report a SAT that its own z3 oracle rejects.  Define
// JIGSAW_HW_SEMANTICS to instead use the legacy hardware behavior (raw LLVM
// shift, relying on x86 count masking; the divisor=1 div-by-zero hack), e.g.
// to match a C/C++ program's concrete execution rather than the SMT-LIB model.
#ifndef JIGSAW_HW_SEMANTICS
#define JIGSAW_SMTLIB_SEMANTICS 1
#endif

static inline llvm::Value* int_const(llvm::IRBuilder<> &B, unsigned bits,
                                     uint64_t v) {
  return llvm::ConstantInt::get(
      llvm::Type::getIntNTy(B.getContext(), bits), v);
}

static llvm::Value* build_shl(llvm::IRBuilder<> &B, llvm::Value* a,
                              llvm::Value* b, unsigned bits) {
#ifdef JIGSAW_SMTLIB_SEMANTICS
  // (amount < width) ? (a << b) : 0
  llvm::Value* in_range = B.CreateICmpULT(b, int_const(B, bits, bits));
  return B.CreateSelect(in_range, B.CreateShl(a, b), int_const(B, bits, 0));
#else
  return B.CreateShl(a, b); // legacy: relies on x86 shift-count masking
#endif
}

static llvm::Value* build_lshr(llvm::IRBuilder<> &B, llvm::Value* a,
                               llvm::Value* b, unsigned bits) {
#ifdef JIGSAW_SMTLIB_SEMANTICS
  // (amount < width) ? (a >>u b) : 0
  llvm::Value* in_range = B.CreateICmpULT(b, int_const(B, bits, bits));
  return B.CreateSelect(in_range, B.CreateLShr(a, b), int_const(B, bits, 0));
#else
  return B.CreateLShr(a, b); // legacy: relies on x86 shift-count masking
#endif
}

static llvm::Value* build_ashr(llvm::IRBuilder<> &B, llvm::Value* a,
                               llvm::Value* b, unsigned bits) {
#ifdef JIGSAW_SMTLIB_SEMANTICS
  // shift by >= width fills with the sign bit == shifting by (width-1)
  llvm::Value* in_range = B.CreateICmpULT(b, int_const(B, bits, bits));
  llvm::Value* amt = B.CreateSelect(in_range, b, int_const(B, bits, bits - 1));
  return B.CreateAShr(a, amt);
#else
  return B.CreateAShr(a, b); // legacy: relies on x86 shift-count masking
#endif
}

// a divisor that is never zero, so the hardware div/rem cannot trap/poison.
static inline llvm::Value* nonzero_divisor(llvm::IRBuilder<> &B, llvm::Value* d,
                                           unsigned bits) {
  // FIXME: this is a hack to avoid division by zero, but should use a better way
  // FIXME: should record the divisor to avoid gradient vanish
  llvm::Value* is_zero = B.CreateICmpEQ(d, int_const(B, bits, 0));
  return B.CreateSelect(is_zero, int_const(B, bits, 1), d);
}

static llvm::Value* build_udiv(llvm::IRBuilder<> &B, llvm::Value* a,
                               llvm::Value* b, unsigned bits) {
  llvm::Value* q = B.CreateUDiv(a, nonzero_divisor(B, b, bits));
#ifdef JIGSAW_SMTLIB_SEMANTICS
  llvm::Value* is_zero = B.CreateICmpEQ(b, int_const(B, bits, 0));
  return B.CreateSelect(is_zero, llvm::ConstantInt::getAllOnesValue(a->getType()), q);
#else
  return q; // legacy: divisor forced to 1
#endif
}

static llvm::Value* build_sdiv(llvm::IRBuilder<> &B, llvm::Value* a,
                               llvm::Value* b, unsigned bits) {
  llvm::Value* q = B.CreateSDiv(a, nonzero_divisor(B, b, bits));
#ifdef JIGSAW_SMTLIB_SEMANTICS
  // bvsdiv x 0 = (x s>= 0) ? ~0 : 1
  llvm::Value* is_zero = B.CreateICmpEQ(b, int_const(B, bits, 0));
  llvm::Value* nonneg = B.CreateICmpSGE(a, int_const(B, bits, 0));
  llvm::Value* zval = B.CreateSelect(nonneg,
      llvm::ConstantInt::getAllOnesValue(a->getType()), int_const(B, bits, 1));
  return B.CreateSelect(is_zero, zval, q);
#else
  return q; // legacy: divisor forced to 1
#endif
}

static llvm::Value* build_urem(llvm::IRBuilder<> &B, llvm::Value* a,
                               llvm::Value* b, unsigned bits) {
  llvm::Value* r = B.CreateURem(a, nonzero_divisor(B, b, bits));
#ifdef JIGSAW_SMTLIB_SEMANTICS
  llvm::Value* is_zero = B.CreateICmpEQ(b, int_const(B, bits, 0));
  return B.CreateSelect(is_zero, a, r); // bvurem x 0 = x
#else
  return r; // legacy: divisor forced to 1 -> x % 1 == 0
#endif
}

static llvm::Value* build_srem(llvm::IRBuilder<> &B, llvm::Value* a,
                               llvm::Value* b, unsigned bits) {
  llvm::Value* r = B.CreateSRem(a, nonzero_divisor(B, b, bits));
#ifdef JIGSAW_SMTLIB_SEMANTICS
  llvm::Value* is_zero = B.CreateICmpEQ(b, int_const(B, bits, 0));
  return B.CreateSelect(is_zero, a, r); // bvsrem x 0 = x
#else
  return r; // legacy: divisor forced to 1 -> x % 1 == 0
#endif
}

static llvm::Value* codegen(llvm::IRBuilder<> &Builder,
    const AstNode* node,
    std::map<size_t, uint32_t> const& local_map, llvm::Value* arg,
    std::unordered_map<uint32_t, llvm::Value*> &value_cache) {

  llvm::Value* ret = nullptr;
  //std::cout << "code gen and nargs is " << nargs << std::endl;

  auto itr = value_cache.find(node->label());
  if (node->label() != 0
      && itr != value_cache.end()) {
    //std::cout << " value cache hit and label is " << node->label() << std::endl;
    return itr->second;
  }

  llvm::Type *ArgTy = Builder.getInt64Ty();
  switch (node->kind()) {
    case rgd::Bool: {
      // getTrue is actually 1 bit integer 1
      if (node->boolvalue())
        ret = llvm::ConstantInt::getTrue(Builder.getContext());
      else
        ret = llvm::ConstantInt::getFalse(Builder.getContext());
      break;
    }
    case rgd::Constant: {
      // The constant is now loading from arguments
      uint32_t start = node->index();
      uint32_t length = node->bits() / 8;

      llvm::Value* idx[1];
      // calculate the offset
      idx[0] = llvm::ConstantInt::get(Builder.getInt32Ty(), start + RET_OFFSET);
      ret = Builder.CreateGEP(ArgTy, arg, idx);
      Type* CTy = llvm::Type::getIntNTy(Builder.getContext(), node->bits());
      llvm::PointerType* CPTy = llvm::PointerType::getUnqual(CTy);
      ret = Builder.CreateBitCast(ret, CPTy);
      ret = Builder.CreateLoad(CTy, ret); // load length bytes at once
      break;
    }
    case rgd::Read: {
      uint32_t start = local_map.at(node->index());
      size_t length = node->bits() / 8;
      //std::cout << "read index " << start << " length " << length << std::endl;
      llvm::Type *RTy = llvm::Type::getIntNTy(Builder.getContext(), node->bits());
      llvm::Value* idx[1];
      idx[0] = llvm::ConstantInt::get(Builder.getInt32Ty(), start + RET_OFFSET);
      ret = Builder.CreateGEP(ArgTy, arg, idx);
      ret = Builder.CreateLoad(ArgTy, ret);
      ret = Builder.CreateZExtOrTrunc(ret, RTy);
      for (uint32_t k = 1; k < length; k++) {
        idx[0] = llvm::ConstantInt::get(Builder.getInt32Ty(),
                                        start + k + RET_OFFSET);
        llvm::Value* tmp = Builder.CreateGEP(ArgTy, arg, idx);
        tmp = Builder.CreateLoad(ArgTy, tmp);
        tmp = Builder.CreateZExtOrTrunc(tmp, RTy);
        tmp = Builder.CreateShl(tmp, 8 * k);
        ret = Builder.CreateAdd(ret, tmp);
      }
      break;
    }
    case rgd::Concat: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      uint32_t bits = rc1->bits() + rc2->bits(); 
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = Builder.CreateOr(
          Builder.CreateShl(
            Builder.CreateZExt(c2,llvm::Type::getIntNTy(Builder.getContext(),bits)),
            rc1->bits()),
          Builder.CreateZExt(c1, llvm::Type::getIntNTy(Builder.getContext(), bits)));
      break;
    }
    case rgd::Extract: {
#if DEBUG
      //std::cerr << "Extract expression" << std::endl;
#endif
      const AstNode* rc = &node->children(0);
      llvm::Value* c = codegen(Builder, rc, local_map, arg, value_cache);
      ret = Builder.CreateTrunc(
          Builder.CreateLShr(c, node->index()),
          llvm::Type::getIntNTy(Builder.getContext(), node->bits()));
      break;
    }
    case rgd::ZExt: {
#if DEBUG
      // std::cerr << "ZExt the bits is " << node->bits() << std::endl;
#endif
      const AstNode* rc = &node->children(0);
      llvm::Value* c = codegen(Builder, rc, local_map, arg, value_cache);
      //FIXME: we may face ZEXT to boolean expr
      ret = Builder.CreateZExtOrTrunc(c,
          llvm::Type::getIntNTy(Builder.getContext(), node->bits()));
      break;
    }
    case rgd::SExt: {
#if DEBUG
      // std::cerr << "SExt the bits is " << node->bits() << std::endl;
#endif
      const AstNode* rc = &node->children(0);
      llvm::Value* c = codegen(Builder, rc,local_map, arg, value_cache);
      ret = Builder.CreateSExt(c,
          llvm::Type::getIntNTy(Builder.getContext(), node->bits()));
      break;
    }
    case rgd::Add: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = Builder.CreateAdd(c1, c2);
      break;
    }
    case rgd::Sub: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = Builder.CreateSub(c1, c2);
      break;
    }
    case rgd::Mul: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = Builder.CreateMul(c1, c2);
      break;
    }
    case rgd::UDiv: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = build_udiv(Builder, c1, c2, node->bits());
      break;
    }
    case rgd::SDiv: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = build_sdiv(Builder, c1, c2, node->bits());
      break;
    }
    case rgd::URem: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = build_urem(Builder, c1, c2, node->bits());
      break;
    }
    case rgd::SRem: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = build_srem(Builder, c1, c2, node->bits());
      break;
    }
    case rgd::Neg: {
      const AstNode* rc = &node->children(0);
      llvm::Value* c = codegen(Builder, rc, local_map, arg, value_cache);
      ret = Builder.CreateNeg(c);
      break;
    }
    case rgd::Not: {
      const AstNode* rc = &node->children(0);
      llvm::Value* c = codegen(Builder, rc, local_map, arg, value_cache);
      ret = Builder.CreateNot(c);
      break;
    }
    case rgd::And: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = Builder.CreateAnd(c1, c2);
      break;
    }
    case rgd::Or: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = Builder.CreateOr(c1, c2);
      break;
    }
    case rgd::Xor: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = Builder.CreateXor(c1, c2);
      break;
    }
    case rgd::Shl: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = build_shl(Builder, c1, c2, node->bits());
      break;
    }
    case rgd::LShr: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = build_lshr(Builder, c1, c2, node->bits());
      break;
    }
    case rgd::AShr: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      ret = build_ashr(Builder, c1, c2, node->bits());
      break;
    }
    // all the following ICmp expressions should be top level
    case rgd::Equal:
    case rgd::Distinct:
    case rgd::Ult:
    case rgd::Ule:
    case rgd::Ugt:
    case rgd::Uge:
    case rgd::Slt:
    case rgd::Sle:
    case rgd::Sgt:
    case rgd::Sge: {
    // we don't really care about the comparison, just need to save the operands
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      // extend to 64-bit to avoid overflow.  For SIGNED comparisons the operands
      // must be sign-extended, otherwise a negative sub-64-bit value (e.g. the
      // i32 0xFE000000) becomes a large positive i64 and get_distance's
      // (int64_t)a </<= (int64_t)b test in gd.cc is wrong -- jigsaw would report
      // an unsound SAT.  Unsigned/Equal/Distinct stay zero-extended.
      bool is_signed = (node->kind() == rgd::Slt || node->kind() == rgd::Sle ||
                        node->kind() == rgd::Sgt || node->kind() == rgd::Sge);
      llvm::Value* c1e = is_signed ? Builder.CreateSExt(c1, Builder.getInt64Ty())
                                   : Builder.CreateZExt(c1, Builder.getInt64Ty());
      llvm::Value* c2e = is_signed ? Builder.CreateSExt(c2, Builder.getInt64Ty())
                                   : Builder.CreateZExt(c2, Builder.getInt64Ty());

      // save the comparison operands to the output args
      // so it's easier to negate the condition
      llvm::Value* idx[1];
      idx[0] = llvm::ConstantInt::get(Builder.getInt32Ty(), 0);
      Builder.CreateStore(c1e,
                          Builder.CreateGEP(Builder.getInt64Ty(), arg, idx));
      idx[0] = llvm::ConstantInt::get(Builder.getInt32Ty(), 1);
      Builder.CreateStore(c2e,
                          Builder.CreateGEP(Builder.getInt64Ty(), arg, idx));

      ret = nullptr;
      break;
    }
    case rgd::Memcmp:
    case rgd::MemcmpN: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = codegen(Builder, rc1, local_map, arg, value_cache);
      llvm::Value* c2 = codegen(Builder, rc2, local_map, arg, value_cache);
      // c1 & c2 should be IntNty
      llvm::Value* ret = Builder.CreateICmpEQ(c1, c2);
      ret = Builder.CreateZExt(ret, Builder.getInt64Ty());

      // just save the results
      llvm::Value* idx[1];
      idx[0] = llvm::ConstantInt::get(Builder.getInt32Ty(), 0);
      Builder.CreateStore(ret,
                          Builder.CreateGEP(Builder.getInt64Ty(), arg, idx));

      ret = nullptr;
      break;
    }
    // this should never happen!
    case rgd::LOr: {
      throw std::invalid_argument("LOr expression");
      break;
    }
    case rgd::LAnd: {
      throw std::invalid_argument("LAnd expression");
      break;
    }
    case rgd::LNot: {
      throw std::invalid_argument("LNot expression");
      break;
    }
    case rgd::Ite: {
      // don't handle ITE for now, doesn't work with GD
      throw std::invalid_argument("Ite expression");
#if DEUBG
      std::cerr << "ITE expr codegen" << std::endl;
#endif
#if 0
      const AstNode* rcond = &node->children(0);
      const AstNode* rtv = &node->children(1);
      const AstNode* rfv = &node->children(2);
      llvm::Value* cond = codegen(rcond, local_map, arg, value_cache);
      llvm::Value* tv = codegen(rtv, local_map, arg, value_cache);
      llvm::Value* fv = codegen(rfv, local_map, arg, value_cache);
      ret = Builder.CreateSelect(cond, tv, fv);
#endif
      break;
    }
    // floating-point arithmetic: reinterpret the integer children as fp, emit
    // the native FP op, then reinterpret the result back to its bit-pattern.
    case rgd::FAdd:
    case rgd::FSub:
    case rgd::FMul:
    case rgd::FDiv:
    case rgd::FRem: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = as_fp(Builder,
          codegen(Builder, rc1, local_map, arg, value_cache), rc1->bits());
      llvm::Value* c2 = as_fp(Builder,
          codegen(Builder, rc2, local_map, arg, value_cache), rc2->bits());
      llvm::Value* r;
      switch (node->kind()) {
        case rgd::FAdd: r = Builder.CreateFAdd(c1, c2); break;
        case rgd::FSub: r = Builder.CreateFSub(c1, c2); break;
        case rgd::FMul: r = Builder.CreateFMul(c1, c2); break;
        case rgd::FDiv: r = Builder.CreateFDiv(c1, c2); break;
        default:        r = Builder.CreateFRem(c1, c2); break;
      }
      ret = as_bits(Builder, r, node->bits());
      break;
    }
    case rgd::FNeg: {
      const AstNode* rc = &node->children(0);
      llvm::Value* c = as_fp(Builder,
          codegen(Builder, rc, local_map, arg, value_cache), rc->bits());
      ret = as_bits(Builder, Builder.CreateFNeg(c), node->bits());
      break;
    }
    // FP -> integer casts (result is a plain integer of node->bits()).
    case rgd::FpToUi:
    case rgd::FpToSi: {
      const AstNode* rc = &node->children(0);
      llvm::Value* c = as_fp(Builder,
          codegen(Builder, rc, local_map, arg, value_cache), rc->bits());
      llvm::Type* iTy = llvm::Type::getIntNTy(Builder.getContext(), node->bits());
      ret = (node->kind() == rgd::FpToUi) ? Builder.CreateFPToUI(c, iTy)
                                          : Builder.CreateFPToSI(c, iTy);
      break;
    }
    // integer -> FP casts (child is a plain integer, result is fp bits).
    case rgd::UiToFp:
    case rgd::SiToFp: {
      const AstNode* rc = &node->children(0);
      llvm::Value* c = codegen(Builder, rc, local_map, arg, value_cache);
      llvm::Type* fTy = fp_type(Builder, node->bits());
      llvm::Value* r = (node->kind() == rgd::UiToFp) ? Builder.CreateUIToFP(c, fTy)
                                                     : Builder.CreateSIToFP(c, fTy);
      ret = as_bits(Builder, r, node->bits());
      break;
    }
    // FP -> FP width changes.
    case rgd::FpTrunc: {
      const AstNode* rc = &node->children(0);
      llvm::Value* c = as_fp(Builder,
          codegen(Builder, rc, local_map, arg, value_cache), rc->bits());
      ret = as_bits(Builder,
          Builder.CreateFPTrunc(c, fp_type(Builder, node->bits())), node->bits());
      break;
    }
    case rgd::FpExt: {
      const AstNode* rc = &node->children(0);
      llvm::Value* c = as_fp(Builder,
          codegen(Builder, rc, local_map, arg, value_cache), rc->bits());
      ret = as_bits(Builder,
          Builder.CreateFPExt(c, fp_type(Builder, node->bits())), node->bits());
      break;
    }
    // unary FP intrinsics (fabs/sqrt) and transcendentals lowered to libm calls
    // (exp/exp2/log/log2/log10).  The JIT resolves the libm symbols from the
    // solver process (see rgdJit.h).
    case rgd::FpFabs:
    case rgd::FpSqrt:
    case rgd::FpExp:
    case rgd::FpExp2:
    case rgd::FpLog:
    case rgd::FpLog2:
    case rgd::FpLog10: {
      const AstNode* rc = &node->children(0);
      llvm::Value* c = as_fp(Builder,
          codegen(Builder, rc, local_map, arg, value_cache), rc->bits());
      llvm::Intrinsic::ID id;
      switch (node->kind()) {
        case rgd::FpFabs:  id = llvm::Intrinsic::fabs;  break;
        case rgd::FpSqrt:  id = llvm::Intrinsic::sqrt;  break;
        case rgd::FpExp:   id = llvm::Intrinsic::exp;   break;
        case rgd::FpExp2:  id = llvm::Intrinsic::exp2;  break;
        case rgd::FpLog:   id = llvm::Intrinsic::log;   break;
        case rgd::FpLog2:  id = llvm::Intrinsic::log2;  break;
        default:           id = llvm::Intrinsic::log10; break;
      }
      ret = as_bits(Builder, Builder.CreateUnaryIntrinsic(id, c), node->bits());
      break;
    }
    // round-to-integral; rounding-mode selector (fp_rounding_mode) in index().
    case rgd::FpRound: {
      const AstNode* rc = &node->children(0);
      llvm::Value* c = as_fp(Builder,
          codegen(Builder, rc, local_map, arg, value_cache), rc->bits());
      llvm::Intrinsic::ID id;
      switch (node->index()) {
        case 0:  id = llvm::Intrinsic::round;     break; // rna: ties away
        case 1:  id = llvm::Intrinsic::roundeven; break; // rne: ties to even
        case 2:  id = llvm::Intrinsic::ceil;      break; // rtp: toward +inf
        case 3:  id = llvm::Intrinsic::floor;     break; // rtn: toward -inf
        default: id = llvm::Intrinsic::trunc;     break; // rtz: toward zero
      }
      ret = as_bits(Builder, Builder.CreateUnaryIntrinsic(id, c), node->bits());
      break;
    }
    // binary FP intrinsics (min/max/copysign) and pow (lowered to a libm call).
    case rgd::FpMin:
    case rgd::FpMax:
    case rgd::FpCopysign:
    case rgd::FpPow: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = as_fp(Builder,
          codegen(Builder, rc1, local_map, arg, value_cache), rc1->bits());
      llvm::Value* c2 = as_fp(Builder,
          codegen(Builder, rc2, local_map, arg, value_cache), rc2->bits());
      llvm::Intrinsic::ID id;
      switch (node->kind()) {
        case rgd::FpMin:      id = llvm::Intrinsic::minnum;   break;
        case rgd::FpMax:      id = llvm::Intrinsic::maxnum;   break;
        case rgd::FpCopysign: id = llvm::Intrinsic::copysign; break;
        default:              id = llvm::Intrinsic::pow;      break;
      }
      ret = as_bits(Builder, Builder.CreateBinaryIntrinsic(id, c1, c2), node->bits());
      break;
    }
    // lrint: round-to-nearest-integer returning an integer (node->bits()).
    case rgd::FpLrint: {
      const AstNode* rc = &node->children(0);
      llvm::Value* c = as_fp(Builder,
          codegen(Builder, rc, local_map, arg, value_cache), rc->bits());
      llvm::Type* iTy = llvm::Type::getIntNTy(Builder.getContext(), node->bits());
      ret = Builder.CreateIntrinsic(llvm::Intrinsic::lrint,
                                    {iTy, c->getType()}, {c});
      break;
    }
    // log1p has no LLVM intrinsic; call the libm function directly (resolved
    // from the solver process by the JIT's dynamic-library symbol generator).
    case rgd::FpLog1p: {
      const AstNode* rc = &node->children(0);
      unsigned bits = node->bits();
      llvm::Value* c = as_fp(Builder,
          codegen(Builder, rc, local_map, arg, value_cache), rc->bits());
      llvm::Type* fTy = fp_type(Builder, bits);
      llvm::Module* M = Builder.GetInsertBlock()->getModule();
      llvm::FunctionCallee fn = M->getOrInsertFunction(
          bits == 32 ? "log1pf" : "log1p", fTy, fTy);
      ret = as_bits(Builder, Builder.CreateCall(fn, {c}), bits);
      break;
    }
    // FP comparisons (top level, like the integer compare case): we don't apply
    // the predicate here, we just save the two operands so gd.cc get_distance()
    // can compute the per-predicate distance.  Promote both operands to double
    // and store their IEEE bits, so get_distance reinterprets arg[0]/arg[1]
    // uniformly as doubles regardless of the original float/double width.
    case rgd::FOeq:
    case rgd::FOgt:
    case rgd::FOge:
    case rgd::FOlt:
    case rgd::FOle:
    case rgd::FOne:
    case rgd::FOrd:
    case rgd::FUno:
    case rgd::FUeq:
    case rgd::FUgt:
    case rgd::FUge:
    case rgd::FUlt:
    case rgd::FUle:
    case rgd::FUne: {
      const AstNode* rc1 = &node->children(0);
      const AstNode* rc2 = &node->children(1);
      llvm::Value* c1 = as_fp(Builder,
          codegen(Builder, rc1, local_map, arg, value_cache), rc1->bits());
      llvm::Value* c2 = as_fp(Builder,
          codegen(Builder, rc2, local_map, arg, value_cache), rc2->bits());
      if (rc1->bits() == 32) c1 = Builder.CreateFPExt(c1, Builder.getDoubleTy());
      if (rc2->bits() == 32) c2 = Builder.CreateFPExt(c2, Builder.getDoubleTy());
      llvm::Value* c1e = Builder.CreateBitCast(c1, Builder.getInt64Ty());
      llvm::Value* c2e = Builder.CreateBitCast(c2, Builder.getInt64Ty());

      // save the (double-promoted) comparison operands to the output args
      llvm::Value* idx[1];
      idx[0] = llvm::ConstantInt::get(Builder.getInt32Ty(), 0);
      Builder.CreateStore(c1e,
                          Builder.CreateGEP(Builder.getInt64Ty(), arg, idx));
      idx[0] = llvm::ConstantInt::get(Builder.getInt32Ty(), 1);
      Builder.CreateStore(c2e,
                          Builder.CreateGEP(Builder.getInt64Ty(), arg, idx));

      ret = nullptr;
      break;
    }
    // The four FP boolean predicates produce a bit, not a measurable magnitude,
    // so gradient descent has nothing to follow.  Reject them explicitly; the
    // out-of-process chain falls back to the FP-aware z3 solver for these.
    case rgd::FpIsNan:
    case rgd::FpIsInf:
    case rgd::FpIsFinite:
    case rgd::FpSignbit: {
      throw std::invalid_argument("floating-point predicate not supported in jigsaw");
      break;
    }
    default:
      throw std::invalid_argument("unhandled expression");
      //printExpression(node);
      break;
  }

  // add to cache
  if (ret && node->label() != 0) {
    value_cache.insert({node->label(), ret});
  }

  return ret; 
}

int rgd::addFunction(const AstNode* node,
    std::map<size_t,uint32_t> const& local_map,
    uint64_t id) {

  if ((!isRelationalKind(node->kind()) &&
      !isFPRelationalKind(node->kind()) &&
      node->kind() != rgd::Memcmp &&
      node->kind() != rgd::MemcmpN)) {
    std::cerr << "non-relational expr\n";
    return -1;
  }

  // Open a new module.
  std::string moduleName = "rgdjit_m" + std::to_string(id);
  std::string funcName = "rgdjit_f" + std::to_string(id);

  auto TheCtx = std::make_unique<llvm::LLVMContext>();
  auto TheModule = std::make_unique<Module>(moduleName, *TheCtx);
  TheModule->setDataLayout(JIT->getDataLayout());
  llvm::IRBuilder<> Builder(*TheCtx);

  std::vector<llvm::Type*> input_type(1,
      llvm::PointerType::getUnqual(Builder.getInt64Ty()));
  llvm::FunctionType *funcType;
  funcType = llvm::FunctionType::get(Builder.getVoidTy(), input_type, false);
  auto *fooFunc = llvm::Function::Create(funcType, llvm::Function::ExternalLinkage,
      funcName, TheModule.get());
  auto *po = llvm::BasicBlock::Create(Builder.getContext(), "entry", fooFunc);
  Builder.SetInsertPoint(po);
  uint32_t idx = 0;

  auto args = fooFunc->arg_begin();
  llvm::Value* var = &(*args);
  std::unordered_map<uint32_t, llvm::Value*> value_cache;
  llvm::Value* body = nullptr;
  try {
    body = codegen(Builder, node, local_map, var, value_cache);
  } catch (std::invalid_argument &e) {
    std::cerr << "Invalid node: " << e.what() << std::endl;
    return -1;
  }
  if (body != nullptr) {
    std::cerr << "non-comparison expr\n";
    return -1;
  }
  Builder.CreateRet(body);

  llvm::raw_ostream *stream = &llvm::outs();
  llvm::verifyFunction(*fooFunc, stream);
#if DEBUG
  // TheModule->print(llvm::errs(), nullptr);
#endif

  JIT->addModule(std::move(TheModule), std::move(TheCtx));

  return 0;
}

test_fn_type rgd::performJit(uint64_t id) {
  std::string funcName = "rgdjit_f" + std::to_string(id);
  auto ExprSymbol = JIT->lookup(funcName).get();
  // LLVM 17 changed getAddress() to return an ExecutorAddr wrapper instead of
  // a raw uint64_t JITTargetAddress.
#if LLVM_VERSION_MAJOR >= 17
  auto func = (test_fn_type)ExprSymbol.getAddress().getValue();
#else
  auto func = (test_fn_type)ExprSymbol.getAddress();
#endif
  return func;
}
