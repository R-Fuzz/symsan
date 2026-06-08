//===- UCSanSummary.h - Shared UCSan/Taint metadata helpers -----*- C++ -*-===//
//
// Shared metadata schema for summaries emitted by UCSanPass and consumed by
// TaintPass. Keep this header small: it is included by LLVM pass plugins only.
//
//===----------------------------------------------------------------------===//

#ifndef SYMSAN_INSTRUMENTATION_UCSAN_SUMMARY_H
#define SYMSAN_INSTRUMENTATION_UCSAN_SUMMARY_H

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Metadata.h"

#include <cstdint>

namespace symsan {
namespace ucsan {

static constexpr const char *MemSummaryMetadataName = "ucsan.mem_summary";
static constexpr const char *PtrFieldAccessKind = "ptr_field_access";

struct MemoryAccessSummary {
  unsigned ArgNo = 0;
  int64_t FieldOffset = 0;
  uint64_t AccessSize = 0;
  bool IsWrite = false;
  uint32_t TypeID = 0;
  unsigned Line = 0;
  unsigned Col = 0;
};

static inline bool getMDString(llvm::MDNode *N, unsigned Idx,
                               llvm::StringRef &Out) {
  if (!N || Idx >= N->getNumOperands())
    return false;
  auto *S = llvm::dyn_cast_or_null<llvm::MDString>(N->getOperand(Idx));
  if (!S)
    return false;
  Out = S->getString();
  return true;
}

static inline bool getMDConstantInt(llvm::MDNode *N, unsigned Idx,
                                    llvm::ConstantInt *&Out) {
  if (!N || Idx >= N->getNumOperands())
    return false;
  Out = llvm::mdconst::dyn_extract<llvm::ConstantInt>(N->getOperand(Idx));
  return Out != nullptr;
}

static inline bool parseMemoryAccessSummary(llvm::MDNode *N,
                                            MemoryAccessSummary &Out) {
  llvm::StringRef Kind;
  if (!getMDString(N, 0, Kind) || Kind != PtrFieldAccessKind)
    return false;

  llvm::ConstantInt *ArgNo = nullptr;
  llvm::ConstantInt *FieldOffset = nullptr;
  llvm::ConstantInt *AccessSize = nullptr;
  llvm::ConstantInt *IsWrite = nullptr;
  llvm::ConstantInt *TypeID = nullptr;
  llvm::ConstantInt *Line = nullptr;
  llvm::ConstantInt *Col = nullptr;
  if (!getMDConstantInt(N, 1, ArgNo) ||
      !getMDConstantInt(N, 2, FieldOffset) ||
      !getMDConstantInt(N, 3, AccessSize) ||
      !getMDConstantInt(N, 4, IsWrite) ||
      !getMDConstantInt(N, 5, TypeID) ||
      !getMDConstantInt(N, 6, Line) ||
      !getMDConstantInt(N, 7, Col))
    return false;

  Out.ArgNo = ArgNo->getZExtValue();
  Out.FieldOffset = FieldOffset->getSExtValue();
  Out.AccessSize = AccessSize->getZExtValue();
  Out.IsWrite = IsWrite->isOne();
  Out.TypeID = TypeID->getZExtValue();
  Out.Line = Line->getZExtValue();
  Out.Col = Col->getZExtValue();
  return true;
}

static inline llvm::MDNode *createMemoryAccessSummaryMD(
    llvm::LLVMContext &C, const MemoryAccessSummary &Summary) {
  auto *Int1Ty = llvm::Type::getInt1Ty(C);
  auto *Int32Ty = llvm::Type::getInt32Ty(C);
  auto *Int64Ty = llvm::Type::getInt64Ty(C);
  llvm::Metadata *Ops[] = {
      llvm::MDString::get(C, PtrFieldAccessKind),
      llvm::ConstantAsMetadata::get(
          llvm::ConstantInt::get(Int32Ty, Summary.ArgNo)),
      llvm::ConstantAsMetadata::get(
          llvm::ConstantInt::get(Int64Ty, Summary.FieldOffset, true)),
      llvm::ConstantAsMetadata::get(
          llvm::ConstantInt::get(Int64Ty, Summary.AccessSize)),
      llvm::ConstantAsMetadata::get(
          llvm::ConstantInt::get(Int1Ty, Summary.IsWrite)),
      llvm::ConstantAsMetadata::get(
          llvm::ConstantInt::get(Int32Ty, Summary.TypeID)),
      llvm::ConstantAsMetadata::get(
          llvm::ConstantInt::get(Int32Ty, Summary.Line)),
      llvm::ConstantAsMetadata::get(
          llvm::ConstantInt::get(Int32Ty, Summary.Col)),
  };
  return llvm::MDNode::get(C, Ops);
}

static inline llvm::MDNode *getMemoryAccessSummaries(const llvm::Function &F) {
  return F.getMetadata(MemSummaryMetadataName);
}

static inline void setMemoryAccessSummaries(llvm::Function &F,
                                            llvm::MDNode *Summaries) {
  F.setMetadata(MemSummaryMetadataName, Summaries);
}

} // namespace ucsan
} // namespace symsan

#endif // SYMSAN_INSTRUMENTATION_UCSAN_SUMMARY_H
