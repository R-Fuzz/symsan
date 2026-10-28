//===- Bitfield.h - Bitfield accesses, byte by byte -------------*- C++ -*-===//
//
// Shared by UCSanPass and TaintPass, each for its own shadow. Keep this header
// small: it is included by LLVM pass plugins only.
//
// Initialization is tracked per byte, and clang accesses a bitfield through its
// whole access unit, the field's neighbours included.  As values, a field
// assigned in a struct nothing else has written is still uninitialized -- the
// load it was merged into was -- and a field read is too if any neighbour was
// never written.  tcp_check_req's `tmp_opt.saw_tstamp = 0` is load i24, and -2,
// store i24, into a struct on the stack, and its `if (tmp_opt.saw_tstamp ...)`
// is load i24, and 1: both were a UBI.  These say which bytes such an access
// writes, or reads, so each pass can judge those bytes alone.
//
//===----------------------------------------------------------------------===//

#ifndef SYMSAN_INSTRUMENTATION_BITFIELD_H
#define SYMSAN_INSTRUMENTATION_BITFIELD_H

#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/KnownBits.h"

#include <cstdint>

namespace symsan {

// A store of what was loaded from the same address with some of its bits
// replaced: a bitfield assignment, a load of the field's access unit, an and
// clearing the field, an or of the new bits, and a store of the unit back.  A
// byte the masks leave alone is stored as it was loaded, and a byte they touch
// was written.
struct RMWStore {
  llvm::LoadInst *Load = nullptr;
  // the and/or from the load up to the stored value, each with the index of
  // its operand on that chain; the other operand is a mask or the new bits
  llvm::SmallVector<std::pair<llvm::BinaryOperator *, unsigned>, 4> Chain;
  // bit i: byte i of the stored value can differ from the loaded one
  uint64_t Touched = 0;
};

namespace rmw_detail {

// the bytes (little-endian) of a Bytes-byte value that have a bit set in Bits
inline uint64_t bytesWithBits(const llvm::APInt &Bits, unsigned Bytes) {
  uint64_t T = 0;
  for (unsigned I = 0; I < Bytes; ++I)
    if (!Bits.extractBits(8, I * 8).isZero())
      T |= uint64_t(1) << I;
  return T;
}

inline bool walk(llvm::Value *V, llvm::Value *Addr, const llvm::DataLayout &DL,
                 unsigned Bytes, RMWStore &R) {
  using namespace llvm;
  if (auto *LI = dyn_cast<LoadInst>(V)) {
    if (!LI->isSimple() || LI->getPointerOperand() != Addr)
      return false;
    R.Load = LI;
    return true;
  }
  auto *BO = dyn_cast<BinaryOperator>(V);
  if (!BO)
    return false;
  unsigned Bits = Bytes * 8;
  if (BO->getOpcode() == Instruction::And) {
    for (unsigned Idx = 0; Idx < 2; ++Idx) {
      auto *Mask = dyn_cast<ConstantInt>(BO->getOperand(1 - Idx));
      if (!Mask || !walk(BO->getOperand(Idx), Addr, DL, Bytes, R))
        continue;
      // the bits the mask clears
      R.Touched |= bytesWithBits(~Mask->getValue().zextOrTrunc(Bits), Bytes);
      R.Chain.push_back({BO, Idx});
      return true;
    }
    return false;
  }
  if (BO->getOpcode() == Instruction::Or) {
    for (unsigned Idx = 0; Idx < 2; ++Idx) {
      if (!walk(BO->getOperand(Idx), Addr, DL, Bytes, R))
        continue;
      // the bits the new value can set
      KnownBits Known = computeKnownBits(BO->getOperand(1 - Idx), DL);
      R.Touched |= bytesWithBits(~Known.Zero.zextOrTrunc(Bits), Bytes);
      R.Chain.push_back({BO, Idx});
      return true;
    }
    return false;
  }
  return false;
}

} // namespace rmw_detail

// SI stores what a load of its own address in its block loaded, through ands
// with constant masks and ors of new bits, and nothing in between can write
// the program's memory -- Skip(I) says I is the instrumentation's own.
// FIXME: initialization is tracked per byte, so a store this does not match is
// judged by its whole byte.  dm_split_and_process_bio sets two bitfields of
// one byte in two blocks, the second `or` reusing the first's `and` of the
// load across stores to other fields and calls; the plain store copies the
// load's uninitialized label onto the bit the first had written (a UBI).
// Matching it needs alias reasoning, and the general fix, bitwise
// initialization state, is not planned.
inline bool matchRMWStore(llvm::StoreInst &SI,
                          llvm::function_ref<bool(llvm::Instruction &)> Skip,
                          RMWStore &R) {
  using namespace llvm;
  R = RMWStore();
  Value *V = SI.getValueOperand();
  if (!SI.isSimple() || !V->getType()->isIntegerTy())
    return false;
  const DataLayout &DL = SI.getModule()->getDataLayout();
  if (!DL.isLittleEndian())
    return false;
  uint64_t Bytes = DL.getTypeStoreSize(V->getType());
  // the access unit is a whole number of bytes, and Touched has 64 of them
  if (Bytes == 0 || Bytes > 64 ||
      V->getType()->getIntegerBitWidth() != Bytes * 8)
    return false;
  if (!rmw_detail::walk(V, SI.getPointerOperand(), DL, Bytes, R) ||
      R.Chain.empty() || R.Load->getParent() != SI.getParent())
    return false;
  for (Instruction *I = R.Load->getNextNode(); I != &SI; I = I->getNextNode())
    if (I->mayWriteToMemory() && !isa<DbgInfoIntrinsic>(I) && !Skip(*I))
      return false;
  return true;
}

// The bits of V its users read, as far as ands with constant masks, truncs and
// shifts by constants show; the instrumentation's own users (nosanitize) read
// none.  A bitfield read is a load of the access unit and a mask.
inline llvm::APInt readBits(llvm::Value *V, unsigned Depth = 0) {
  using namespace llvm;
  unsigned W = V->getType()->getIntegerBitWidth();
  APInt All = APInt::getAllOnes(W);
  if (Depth > 4)
    return All;
  APInt R(W, 0);
  for (User *U : V->users()) {
    auto *I = dyn_cast<Instruction>(U);
    if (!I)
      return All;
    if (I->getMetadata("nosanitize"))
      continue;
    switch (I->getOpcode()) {
    case Instruction::And:
      if (auto *M = dyn_cast<ConstantInt>(I->getOperand(I->getOperand(0) == V)))
        R |= M->getValue() & readBits(I, Depth + 1);
      else
        return All;
      break;
    case Instruction::Trunc:
      R |= readBits(I, Depth + 1).zext(W);
      break;
    case Instruction::LShr:
    case Instruction::AShr:
    case Instruction::Shl: {
      auto *K = dyn_cast<ConstantInt>(I->getOperand(1));
      if (I->getOperand(0) != V || !K || K->getValue().uge(W))
        return All;
      unsigned Sh = K->getZExtValue();
      APInt Out = readBits(I, Depth + 1);
      if (I->getOpcode() == Instruction::Shl) {
        R |= Out.lshr(Sh);
      } else {
        R |= Out.shl(Sh);
        // the sign bit is read wherever the shift brings it in
        if (I->getOpcode() == Instruction::AShr &&
            !Out.isSubsetOf(APInt::getLowBitsSet(W, W - Sh)))
          R.setSignBit();
      }
      break;
    }
    default:
      return All;
    }
  }
  return R;
}

// The bytes (bit i: byte i) of what LI loads that nothing it is used for reads
inline uint64_t unreadBytes(llvm::LoadInst &LI) {
  using namespace llvm;
  const DataLayout &DL = LI.getModule()->getDataLayout();
  if (!LI.getType()->isIntegerTy() || !DL.isLittleEndian())
    return 0;
  uint64_t Bytes = DL.getTypeStoreSize(LI.getType());
  if (Bytes > 64 || LI.getType()->getIntegerBitWidth() != Bytes * 8)
    return 0;
  APInt Read = readBits(&LI);
  uint64_t Unread = 0;
  for (unsigned I = 0; I < Bytes; ++I)
    if (Read.extractBits(8, I * 8).isZero())
      Unread |= uint64_t(1) << I;
  return Unread;
}

} // namespace symsan

#endif // SYMSAN_INSTRUMENTATION_BITFIELD_H
