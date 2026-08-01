//===- Taint.cpp - dynamic taint analysis --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
/// \file
/// This file is a part of Taint, a specialized taint analysis for symbolic
/// execution.
//
//===----------------------------------------------------------------------===//

//#include "defs.h"
#include "branch_id.h"
#include "UCSanSummary.h"

#include <optional>
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/iterator.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Transforms/Utils/GlobalStatus.h"
#include "llvm/Transforms/Utils/ScalarEvolutionExpander.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/AttributeMask.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Value.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DJB.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

// for the SYMSAN_DOCUMENT_IDS dump, which several TUs of a parallel build
// append to at once
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

using namespace llvm;

// This must be consistent with ShadowWidthBits.
static const Align ShadowTLSAlignment = Align(4);

// The size of TLS variables. These constants must be kept in sync with the ones
// in dfsan.cpp.
static const unsigned ArgTLSSize = 800;
static const unsigned RetvalTLSSize = 800;

// The -taint-preserve-alignment flag controls whether this pass assumes that
// alignment requirements provided by the input IR are correct.  For example,
// if the input IR contains a load with alignment 8, this flag will cause
// the shadow load to have alignment 16.  This flag is disabled by default as
// we have unfortunately encountered too much code (including Clang itself;
// see PR14291) which performs misaligned access.
static cl::opt<bool> ClPreserveAlignment(
    "taint-preserve-alignment",
    cl::desc("respect alignment requirements provided by input IR"), cl::Hidden,
    cl::init(false));

// The ABI list files control how shadow parameters are passed. The pass treats
// every function labelled "uninstrumented" in the ABI list file as conforming
// to the "native" (i.e. unsanitized) ABI.  Unless the ABI list contains
// additional annotations for those functions, a call to one of those functions
// will produce a warning message, as the labelling behaviour of the function is
// unknown. The other supported annotations for uninstrumented functions are
// "functional" and "discard", which are described below under
// Taint::WrapperKind.
// Functions will often be labelled with both "uninstrumented" and one of
// "functional" or "discard". This will leave the function unchanged by this
// pass, and create a wrapper function that will call the original.
//
// Instrumented functions can also be annotated as "force_zero_labels", which
// will make all shadow and return values set zero labels.
// Functions should never be labelled with both "force_zero_labels" and
// "uninstrumented" or any of the unistrumented wrapper kinds.
static cl::list<std::string> ClABIListFiles(
    "taint-abilist",
    cl::desc("File listing native ABI functions and how the pass treats them"),
    cl::Hidden);

// Controls whether the pass includes or ignores the labels of pointers in load
// instructions.
static cl::opt<bool> ClCombinePointerLabelsOnLoad(
    "taint-combine-pointer-labels-on-load",
    cl::desc("Combine the label of the pointer with the label of the data when "
             "loading from memory."),
    cl::Hidden, cl::init(false));

// Controls whether the pass includes or ignores the labels of pointers in
// stores instructions.
static cl::opt<bool> ClCombinePointerLabelsOnStore(
    "taint-combine-pointer-labels-on-store",
    cl::desc("Combine the label of the pointer with the label of the data when "
             "storing in memory."),
    cl::Hidden, cl::init(false));

static cl::opt<bool> ClDebugNonzeroLabels(
    "taint-debug-nonzero-labels",
    cl::desc("Insert calls to __dfsan_nonzero_label on observing a parameter, "
             "load or return with a nonzero label"),
    cl::Hidden);

static cl::opt<bool> ClIgnorePersonalityRoutine(
    "taint-ignore-personality-routine",
    cl::desc("If a personality routine is marked uninstrumented from the ABI "
             "list, do not create a wrapper for it."),
    cl::Hidden, cl::init(false));

// SYMSAN specific flags, invoke a callback function to trace GEP events
static cl::opt<bool> ClTraceGEPOffset(
    "taint-trace-gep",
    cl::desc("Trace GEP offset for solving."),
    cl::Hidden, cl::init(true));

// Symbolize loads from read-only global lookup tables at a symbolic index.
// Shadow memory over globals is zero, so hex[i] would otherwise produce a
// concrete value and the comparison that consumes it never reaches the solver.
// Only the i2s solver inverts the resulting tlookup op.
static cl::opt<bool> ClTraceTableLookup(
    "taint-trace-table-lookup",
    cl::desc("Symbolize loads from read-only global tables at symbolic index."),
    cl::Hidden, cl::init(true));

// Upper bound on the byte size of a table we are willing to symbolize.  The
// contents have to be shipped to the solver and packed into the constraint's
// constant args, so a large table is paid for on every solve that touches it.
static cl::opt<unsigned> ClMaxTableBytes(
    "taint-max-table-bytes",
    cl::desc("Maximum size in bytes of a symbolized lookup table."),
    cl::Hidden, cl::init(4096));

// Trace floating point operations (FP arithmetic, casts, FCmp, and common FP
// intrinsics).  Reconstructed and solved by the z3 solver via the fpa theory.
static cl::opt<bool> ClTraceFP(
    "taint-trace-float-pointer",
    cl::desc("Propagate taint for floating pointer instructions."),
    cl::Hidden, cl::init(true));

// Self-defined FP op codes.  These MUST match the __dfsan::operators enum in
// runtime/dfsan/dfsan.h (last_llvm_op = 67 on LLVM 18).  This file does not
// include dfsan.h, so — like the bswap Extract/Concat codes — they are hardcoded.
enum {
  DfsanFpNeg      = 89, // fp_neg      (last_llvm_op + 22)
  DfsanFpFabs     = 90, // fp_fabs
  DfsanFpSqrt     = 91, // fp_sqrt
  DfsanFpRound    = 92, // fp_round (rounding selector in op1)
  DfsanFpMin      = 93, // fp_min
  DfsanFpMax      = 94, // fp_max
  DfsanFpCopysign = 95, // fp_copysign
  DfsanBitReverse = 109, // bitreverse (last_llvm_op + 42)
};
// Rounding-mode selector (must match __dfsan::fp_rounding_mode in dfsan.h).
enum {
  DfsanFpRmRna = 0, // round nearest, ties to away  (llvm.round)
  DfsanFpRmRne = 1, // round nearest, ties to even  (llvm.rint/nearbyint)
  DfsanFpRmRtp = 2, // round toward +inf            (llvm.ceil)
  DfsanFpRmRtn = 3, // round toward -inf            (llvm.floor)
  DfsanFpRmRtz = 4, // round toward zero            (llvm.trunc)
};

static cl::opt<bool> ClTraceLoop(
    "taint-trace-loop",
    cl::desc("Trace loop entering and exiting."),
    cl::Hidden, cl::init(true));

// SYMSAN specific flags, enable memory safety checks (both spatial and temporal)
static cl::opt<bool> ClTraceBound(
    "taint-trace-bound",
    cl::desc("Trace buffer bound info."),
    cl::Hidden, cl::init(true));

// SYMSAN specific flags, hoist bounds checks out of loops using SCEV
static cl::opt<bool> ClHoistBoundsChecks(
    "taint-hoist-bounds-checks",
    cl::desc("Hoist bounds checks out of loops using SCEV analysis."),
    cl::Hidden, cl::init(true));

// SYMSAN specific flags, enable generating solving tasks for undefined behaviour
static cl::opt<bool> ClSolveUB(
    "taint-solve-ub",
    cl::desc("Solve undefined behaviours."),
    cl::Hidden, cl::init(false));

// SYMSAN specific flags, only send events for annotated basic blocks
static cl::opt<bool> ClTraceAnnotatedBB(
    "taint-trace-annotated-bb",
    cl::desc("Only trace annotated basic blocks."),
    cl::Hidden, cl::init(false));

// SYMSAN specific flags, if runs with UCSan
static cl::opt<bool> ClWithUCSan(
    "taint-with-ucsan",
    cl::desc("Performs under-constrained symbolic execution."),
    cl::Hidden, cl::init(false));

// SYMSAN specific flag. Upstream DFSan conservatively stores a zero shadow on
// atomic stores (and CAS/RMW) to avoid shadow data races. That loses the
// symbolic expression of the stored value. Concolic targets are typically
// single-threaded, so by default we preserve the real shadow instead. Set to
// false to restore DFSan's race-free zeroing behaviour.
static cl::opt<bool> ClPreserveAtomicShadow(
    "taint-preserve-atomic-shadow",
    cl::desc("Propagate the real shadow through atomic stores/CAS instead of "
             "zeroing it (loses symex but is race-free when disabled)."),
    cl::Hidden, cl::init(true));

static StringRef getGlobalTypeString(const GlobalValue &G) {
  // Types of GlobalVariables are always pointer types.
  Type *GType = G.getValueType();
  // For now we support excluding struct types only.
  if (StructType *SGType = dyn_cast<StructType>(GType)) {
    if (!SGType->isLiteral())
      return SGType->getName();
  }
  return "<unknown type>";
}

namespace {

// Memory map parameters used in application-to-shadow address calculation.
// Offset = (Addr & ~AndMask) ^ XorMask
// Shadow = ShadowBase + Offset * ShadowWidthBytes
struct MemoryMapParams {
  uint64_t AndMask;
  uint64_t XorMask;
  uint64_t ShadowBase;
};

} // end anonymous namespace

// x86_64 Linux
// NOLINTNEXTLINE(readability-identifier-naming)
static const MemoryMapParams Linux_X86_64_MemoryMapParams = {
    0x700000000000, // AndMask (keep old style)
    0,              // XorMask (not used)
    0,              // ShadowBase (not used)
};

namespace {

class TaintABIList {
  std::unique_ptr<SpecialCaseList> SCL;

 public:
  TaintABIList() = default;

  void set(std::unique_ptr<SpecialCaseList> List) { SCL = std::move(List); }

  /// Returns whether either this function or its source file are listed in the
  /// given category.
  bool isIn(const Function &F, StringRef Category) const {
    return isIn(*F.getParent(), Category) ||
           SCL->inSection("taint", "fun", F.getName(), Category);
  }

  /// Returns whether this global alias is listed in the given category.
  ///
  /// If GA aliases a function, the alias's name is matched as a function name
  /// would be.  Similarly, aliases of globals are matched like globals.
  bool isIn(const GlobalAlias &GA, StringRef Category) const {
    if (isIn(*GA.getParent(), Category))
      return true;

    if (isa<FunctionType>(GA.getValueType()))
      return SCL->inSection("taint", "fun", GA.getName(), Category);

    return SCL->inSection("taint", "global", GA.getName(), Category) ||
           SCL->inSection("dataflow", "type", getGlobalTypeString(GA),
                          Category);
  }

  /// Returns whether this module is listed in the given category.
  bool isIn(const Module &M, StringRef Category) const {
    return SCL->inSection("taint", "src", M.getModuleIdentifier(), Category);
  }
};

/// TransformedFunction is used to express the result of transforming one
/// function type into another.  This struct is immutable.  It holds metadata
/// useful for updating calls of the old function to the new type.
struct TransformedFunction {
  TransformedFunction(FunctionType* OriginalType,
                      FunctionType* TransformedType,
                      std::vector<unsigned> ArgumentIndexMapping)
      : OriginalType(OriginalType),
        TransformedType(TransformedType),
        ArgumentIndexMapping(ArgumentIndexMapping) {}

  // Disallow copies.
  TransformedFunction(const TransformedFunction &) = delete;
  TransformedFunction &operator=(const TransformedFunction &) = delete;

  // Allow moves.
  TransformedFunction(TransformedFunction &&) = default;
  TransformedFunction &operator=(TransformedFunction &&) = default;

  /// Type of the function before the transformation.
  FunctionType *OriginalType;

  /// Type of the function after the transformation.
  FunctionType *TransformedType;

  /// Transforming a function may change the position of arguments.  This
  /// member records the mapping from each argument's old position to its new
  /// position.  Argument positions are zero-indexed.  If the transformation
  /// from F to F' made the first argument of F into the third argument of F',
  /// then ArgumentIndexMapping[0] will equal 2.
  std::vector<unsigned> ArgumentIndexMapping;
};

/// Given function attributes from a call site for the original function,
/// return function attributes appropriate for a call to the transformed
/// function.
AttributeList
TransformFunctionAttributes(const TransformedFunction& TransformedFunction,
                            LLVMContext& Ctx, AttributeList CallSiteAttrs) {

  // Construct a vector of AttributeSet for each function argument.
  std::vector<llvm::AttributeSet> ArgumentAttributes(
      TransformedFunction.TransformedType->getNumParams());

  // Copy attributes from the parameter of the original function to the
  // transformed version.  'ArgumentIndexMapping' holds the mapping from
  // old argument position to new.
  for (unsigned I = 0, IE = TransformedFunction.ArgumentIndexMapping.size();
       I < IE; ++I) {
    unsigned TransformedIndex = TransformedFunction.ArgumentIndexMapping[I];
    ArgumentAttributes[TransformedIndex] = CallSiteAttrs.getParamAttrs(I);
  }

  // Copy annotations on varargs arguments.
  for (unsigned I = TransformedFunction.OriginalType->getNumParams(),
                IE = CallSiteAttrs.getNumAttrSets();
       I < IE; ++I) {
    ArgumentAttributes.push_back(CallSiteAttrs.getParamAttrs(I));
  }

  return AttributeList::get(Ctx, CallSiteAttrs.getFnAttrs(),
                            CallSiteAttrs.getRetAttrs(),
                            ArrayRef(ArgumentAttributes));
}

class Taint {
  friend struct TaintFunction;
  friend class TaintVisitor;

  enum { ShadowWidthBits  = 32, ShadowWidthBytes = ShadowWidthBits / 8 };

  /// How should calls to uninstrumented functions be handled?
  enum WrapperKind {
    /// This function is present in an uninstrumented form but we don't know
    /// how it should be handled.  Print a warning and call the function anyway.
    /// Don't label the return value.
    WK_Warning,

    /// This function does not write to (user-accessible) memory, and its return
    /// value is unlabelled.
    WK_Discard,

    /// This function does not write to (user-accessible) memory, and the label
    /// of its return value is the union of the label of its arguments.
    WK_Functional,

    /// Instead of calling the function, a custom wrapper __dfsw_F is called,
    /// where F is the name of the function.  This function may wrap the
    /// original function or provide its own implementation.  This is similar to
    /// the IA_Args ABI, except that IA_Args uses a struct return type to
    /// pass the return value shadow in a register, while WK_Custom uses an
    /// extra pointer argument to return the shadow.  This allows the wrapped
    /// form of the function type to be expressed in C.
    WK_Custom,

    /// Special cases for memcmp, strcmp, strncmp like functions
    WK_Memcmp,
    WK_Strcmp,
    WK_Strncmp,
    WK_Strchr,    // strchr/memchr - find first char occurrence
    WK_Strrchr,   // strrchr/memrchr - find last char occurrence
    WK_Strstr,    // strstr/memmem - find substring
    WK_Prefixof,  // prefix check (e.g., g_str_has_prefix)
    WK_Suffixof,  // suffix check (e.g., g_str_has_suffix)
    WK_Strcat,    // strcat/strncat - string concatenation
    WK_Strsub,    // substr(s, start, len) - substring from start with len
  };

  Module *Mod;
  LLVMContext *Ctx;
  IntegerType *Int8Ty;
  IntegerType *Int16Ty;
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  /// The shadow type for all primitive types and vector types.
  IntegerType *PrimitiveShadowTy;
  PointerType *PrimitiveShadowPtrTy;
  IntegerType *IntptrTy;
  PointerType *VoidPtrTy;
  ConstantInt *ZeroPrimitiveShadow;
  ConstantInt *UninitializedPrimitiveShadow;
  ConstantInt *ShadowPtrAndMask;
  ConstantInt *ShadowPtrXorMask;
  ConstantInt *ShadowPtrBase;
  ConstantInt *ShadowPtrMul;
  Constant *ArgTLS;
  Constant *RetvalTLS;
  FunctionType *TaintUnionFnTy;
  FunctionType *TaintGetWideFnTy;
  FunctionType *TaintUnionLoadFnTy;
  FunctionType *TaintUnionStoreFnTy;
  FunctionType *TaintGEPOffsetFnTy;
  FunctionType *TaintUnimplementedFnTy;
  FunctionType *TaintWrapperExternWeakNullFnTy;
  FunctionType *TaintSetLabelFnTy;
  FunctionType *TaintNonzeroLabelFnTy;
  FunctionType *TaintVarargWrapperFnTy;
  FunctionType *TaintTraceCmpFnTy;
  FunctionType *TaintTraceCondFnTy;
  FunctionType *TaintTraceLoopFnTy;
  FunctionType *TaintTraceSwitchEndFnTy;
  FunctionType *TaintTraceSelectFnTy;
  FunctionType *TaintTraceIndirectCallFnTy;
  FunctionType *TaintTraceGEPFnTy;
  FunctionType *TaintTableLookupFnTy;
  FunctionType *TaintPushStackFrameFnTy;
  FunctionType *TaintPopStackFrameFnTy;
  FunctionType *TaintTraceAllocaFnTy;
  FunctionType *TaintCheckBoundsFnTy;
  FunctionType *TaintSolveBoundsFnTy;
  FunctionType *TaintSolveSizeFnTy;
  FunctionType *TaintSolveStrBoundsFnTy;
  FunctionType *TaintTraceGlobalFnTy;
  FunctionType *TaintDebugFnTy;
  FunctionType *TaintMinimizeLabelFnTy;
  FunctionCallee TaintUnionFn;
  FunctionCallee TaintGetWideFn;
  FunctionCallee TaintUnionLoadFn;
  FunctionCallee TaintUnionStoreFn;
  FunctionCallee TaintGEPOffsetFn;
  FunctionCallee TaintUnimplementedFn;
  FunctionCallee TaintWrapperExternWeakNullFn;
  FunctionCallee TaintSetLabelFn;
  FunctionCallee TaintNonzeroLabelFn;
  FunctionCallee TaintVarargWrapperFn;
  FunctionCallee TaintTraceCmpFn;
  FunctionCallee TaintTraceCondFn;
  FunctionCallee TaintTraceLoopFn;
  FunctionCallee TaintTraceSwitchEndFn;
  FunctionCallee TaintTraceSelectFn;
  FunctionCallee TaintTraceIndirectCallFn;
  FunctionCallee TaintTraceGEPFn;
  FunctionCallee TaintTableLookupFn;
  FunctionCallee TaintPushStackFrameFn;
  FunctionCallee TaintPopStackFrameFn;
  FunctionCallee TaintTraceAllocaFn;
  FunctionCallee TaintCheckBoundsFn;
  FunctionCallee TaintSolveBoundsFn;
  FunctionCallee TaintSolveSizeFn;
  FunctionCallee TaintSolveStrBoundsFn;
  FunctionCallee TaintTraceGlobalFn;
  FunctionCallee TaintDebugFn;
  FunctionCallee TaintMinimizeLabelFn;
  SmallPtrSet<Value *, 16> TaintRuntimeFunctions;
  /// Read-only global arrays eligible to be treated as lookup tables, mapped to
  /// {num_elements, element_size}.  Computed once, before anything is
  /// instrumented, because the instrumentation itself passes globals to runtime
  /// calls (see getShadowForGlobal) and GlobalStatus then reports them as
  /// unanalyzable.  Populated by findReadOnlyTables().
  DenseMap<const GlobalVariable *, std::pair<uint64_t, uint64_t>> ReadOnlyTables;
  Constant *CallStack;
  MDNode *ColdCallWeights;
  TaintABIList ABIList;
  DenseMap<Value *, Function *> UnwrappedFnMap;
  AttributeMask ReadOnlyNoneAttrs;

  /// Memory map parameters used in calculation mapping application addresses
  /// to shadow addresses and origin addresses.
  const MemoryMapParams *MapParams;

  Value *getShadowOffset(Value *Addr, IRBuilder<> &IRB);
  Value *getShadowAddress(Value *Addr, IRBuilder<> &IRB);
  bool isInstrumented(const Function *F);
  bool isInstrumented(const GlobalAlias *GA);
  FunctionType *getArgsFunctionType(FunctionType *T);
  bool isForceZeroLabels(const Function *F);
  TransformedFunction getCustomFunctionType(FunctionType *T);
  WrapperKind getWrapperKind(Function *F);
  void addGlobalNameSuffix(GlobalValue *GV);
  void buildExternWeakCheckIfNeeded(IRBuilder<> &IRB, Function *F);
  Function *buildWrapperFunction(Function *F, StringRef NewFName,
                                 GlobalValue::LinkageTypes NewFLink,
                                 FunctionType *NewFT);

  void findReadOnlyTables(Module &M);
  void addContextRecording(Function &F);
  void addFrameTracing(Function &F);
  uint32_t getInstructionId(Instruction *Inst);
  const uint32_t InvalidInstructionId = -1;

  /// Record that @p Inst was instrumented with branch id @p cid, for
  /// SYMSAN_DOCUMENT_IDS.  @p Kind is "br", "select", "switch" or
  /// "switch-case"; see documentBranchId() for why the caller has to say, and
  /// for what @p Extra is.
  void documentBranchId(uint32_t cid, Instruction *Inst, const char *Kind,
                        const std::string &Extra = std::string());
  void flushDocumentedIds();
  /// Value of SYMSAN_DOCUMENT_IDS, or empty when the dump is off.
  std::string DocumentIdsPath;
  /// Lines accumulated by documentBranchId(), written out once per module so
  /// that a parallel build takes the file lock once per TU rather than once
  /// per branch.
  std::vector<std::string> DocumentedIds;

  void initializeRuntimeFunctions(Module &M);
  void initializeCallbackFunctions(Module &M);
  bool initializeModule(Module &M);

  /// Returns a zero constant with the shadow type of OrigTy.
  ///
  /// getZeroShadow({T1,T2,...}) = {getZeroShadow(T1),getZeroShadow(T2,...}
  /// getZeroShadow([n x T]) = [n x getZeroShadow(T)]
  /// getZeroShadow(other type) = i16(0)
  ///
  /// Note that a zero shadow is always i16(0) when shouldTrackFieldsAndIndices
  /// returns false.
  Constant *getZeroShadow(Type *OrigTy);
  /// Returns a zero constant with the shadow type of V's type.
  Constant *getZeroShadow(Value *V);

  /// Checks if V is a zero shadow.
  bool isZeroShadow(Value *V);

  /// Returns the shadow type of OrigTy.
  ///
  /// getShadowTy({T1,T2,...}) = {getShadowTy(T1),getShadowTy(T2),...}
  /// getShadowTy([n x T]) = [n x getShadowTy(T)]
  /// getShadowTy(other type) = i16
  ///
  /// Note that a shadow type is always i16 when shouldTrackFieldsAndIndices
  /// returns false.
  Type *getShadowTy(Type *OrigTy);
  /// Returns the shadow type of of V's type.
  Type *getShadowTy(Value *V);

  /// Returns an uninitialized shadow value with the shadow type of OrigTy.
  Constant *getUninitializedShadow(Type *OrigTy);

public:
  Taint(const std::vector<std::string> &ABIListFiles);

  bool runImpl(Module &M);
};

struct TaintFunction {
  Taint &TT;
  Function *F;
  DominatorTree DT;
  LoopInfo *LI;
  bool IsNativeABI;
  bool IsForceZeroLabels;
  Value *ArgTLSPtr = nullptr;
  Value *RetvalTLSPtr = nullptr;
  AllocaInst *LabelReturnAlloca = nullptr;
  DenseMap<Value *, Value *> ValShadowMap;
  DenseMap<AllocaInst *, AllocaInst *> AllocaShadowMap;

  struct PHIFixupElement {
    PHINode *Phi;
    PHINode *ShadowPhi;
  };
  std::vector<PHIFixupElement> PHIFixups;

  DenseSet<Instruction *> SkipInsts;
  std::vector<Value *> NonZeroChecks;
  bool AvoidNewBlocks;
  std::hash<std::string> HashFn;

  struct CachedShadow {
    BasicBlock *Block; // The block where Shadow is defined.
    Value *Shadow;
  };
  /// Maps a value to its latest shadow value in terms of domination tree.
  DenseMap<std::pair<Value *, Value *>, CachedShadow> CachedShadows;
  /// Maps a value to its latest collapsed shadow value it was converted to in
  /// terms of domination tree. When ClDebugNonzeroLabels is on, this cache is
  /// used at a post process where CFG blocks are split. So it does not cache
  /// BasicBlock like CachedShadows, but uses domination between values.
  DenseMap<Value *, Value *> CachedCollapsedShadows;
  DenseMap<Value *, std::set<Value *>> ShadowElements;

  /// A GEP that indexes a read-only global table with a symbolic index.  Keyed
  /// on the GEP itself so the load that consumes it can be given a real shadow
  /// (see visitLoadInst); instructions are visited in order, so the GEP is
  /// always recorded before its load.
  struct TableGEPInfo {
    Value *IndexShadow; // shadow of the symbolic index
    Value *Index;       // the index, zext/trunc'd to i64
    Value *TablePtr;    // base address of the global, as i64
    uint64_t NumElements;
    uint64_t ElemSize;
  };
  DenseMap<Value *, TableGEPInfo> TableGEPs;

  TaintFunction(Taint &TT, Function *F, bool IsNativeABI,
                bool IsForceZeroLabels)
      : TT(TT), F(F), IsNativeABI(IsNativeABI),
        IsForceZeroLabels(IsForceZeroLabels) {
    DT.recalculate(*F);
    LI = new LoopInfo(DT);
    // initialize the pseudo-random number generator with the function name
    srandom(std::hash<std::string>{}(F->getName().str()));
  }

  ~TaintFunction() { delete LI; }

  /// Computes the shadow address for a given function argument.
  ///
  /// Shadow = ArgTLS+ArgOffset.
  Value *getArgTLS(Type *T, unsigned ArgOffset, IRBuilder<> &IRB);

  /// Computes the shadow address for a retval.
  Value *getRetvalTLS(Type *T, IRBuilder<> &IRB);

  Value *getShadow(Value *V);
  void setShadow(Instruction *I, Value *Shadow);

  /// Handle nosanitize __dfsw_* calls from UCSan:
  /// emit minimize hints for alloc size args and load retval TLS for non-void.
  /// Returns true if handled.
  bool handleUCSanCall(CallInst *CI, Instruction *Next);

  /// Returns the shadow value of a global variable GV.
  Value *getShadowForGlobal(GlobalVariable *GV, IRBuilder<> &IRB);

  // Op Shadow
  Value *combineShadows(Value *V1, Value *V2,
                        uint16_t op, Instruction *Pos);
  Value *combineBinaryOperatorShadows(BinaryOperator *BO, uint8_t op);
  Value *combineCastInstShadows(CastInst *CI, uint8_t op);
  Value *combineCmpInstShadows(CmpInst *CI, uint8_t op);
  void visitCmpInst(CmpInst *I);
  void visitCondition(Value *Cond, Instruction *I);
  void visitSwitchInst(SwitchInst *I);
  Value *visitSelectInst(Value *Cond, Value *TS, Value *FS, SelectInst *I);
  void visitGEPInst(GetElementPtrInst *I);
  Value *visitAllocaInst(AllocaInst *I, Value *ArraySize, Type *ElTy);
  void checkBounds(Value *Ptr, Value *Size, Instruction *Pos);
  void solveBounds(Value *Ptr, Value *Size, Instruction *Pos);
  void hoistBoundsChecks();

  /// XXX: because we never collapse taint labels for aggregate types,
  ///      we also do not expand taint labels from an aggreated primitive
  ///      shadow value. Instead, we always load the label for each
  ///      primitive field.
  ///
  /// Load all primitive subtypes of T, returning the aggrate shadow value.
  ///
  /// LS({T1,T2, ...}, Addr) = {LS(T1, SubAdrr),LS(T2, SubAddr),...}
  /// LS([n x T], Addr) = [n x LS(T, SubAddr)]
  /// LS(other types, Addr) = LS(PS, Addr)
  Value *loadShadow(Type *T, Value *Addr, uint64_t Size, Align Alignment,
                    Instruction *Pos);

  /// XXX: we do not union taint labels for aggregate types before store;
  ///      instead, we store each privimitive field individually.
  ///
  /// Store all primitive subtypes of T, using the aggrate shadow value.
  ///
  /// SS(Addr, {T1,T2, ...}) = SS(SubAddr, T1), SS(SubAddr, T2), ...
  /// SS(Addr, [T1,T2,...]) = SS(SubAddr, T1), SS(SubAddr, T2), ...
  /// SS(Addr, PS) = SS(Addr, PS)
  void storeShadow(Value *Addr, Type *T, uint64_t Size, Align Alignment,
                   Value *Shadow, Instruction *Pos);

  Align getShadowAlign(Align InstAlignment);

private:
  /// Loads a primitive shadow label
  Value *loadPrimitiveShadow(Value *Addr, uint64_t Size, uint64_t SizeInBits,
                             uint64_t Align, IRBuilder<> &IRB);
  /// Loads shadow recursively for aggregate types
  Value *loadShadowRecursive(Value *Shadow, SmallVector<unsigned, 4> &Indices,
                             Type *SubTy, Value *Addr, uint64_t Size,
                             uint64_t Align, IRBuilder<> &IRB);
  /// Stores an aggregate shadow label
  void storeShadowRecursive(Value *Shadow, SmallVector<unsigned, 4> &Indices,
                            Type *SubShadowTy, Value *ShadowAddr, uint64_t Size,
                            uint64_t Align, IRBuilder<> &IRB);
  /// Returns the shadow value of an argument A.
  Value *getShadowForTLSArgument(Argument *A);

  static const uint8_t TrueBranchLoopLatch = 0x8;
  static const uint8_t FalseBranchLoopLatch = 0x4;
  static const uint8_t TrueBranchLoopExit = 0x2;
  static const uint8_t FalseBranchLoopExit = 0x1;
  static const uint8_t LoopExitBranch = TrueBranchLoopExit | FalseBranchLoopExit;
};

class TaintVisitor : public InstVisitor<TaintVisitor> {
public:
  TaintFunction &TF;

  TaintVisitor(TaintFunction &TF) : TF(TF) {}

  const DataLayout &getDataLayout() const {
    return TF.F->getParent()->getDataLayout();
  }

  void visitUnaryOperator(UnaryOperator &UO);
  void visitBinaryOperator(BinaryOperator &BO);
  void visitCastInst(CastInst &CI);
  void visitCmpInst(CmpInst &CI);
  void visitLandingPadInst(LandingPadInst &LPI);
  void visitGetElementPtrInst(GetElementPtrInst &GEPI);
  void visitLoadInst(LoadInst &LI);
  void visitStoreInst(StoreInst &SI);
  void visitAtomicRMWInst(AtomicRMWInst &I);
  void visitAtomicCmpXchgInst(AtomicCmpXchgInst &I);
  void visitReturnInst(ReturnInst &RI);
  void visitCallBase(CallBase &CB);
  void visitPHINode(PHINode &PN);
  void visitExtractElementInst(ExtractElementInst &I);
  void visitInsertElementInst(InsertElementInst &I);
  void visitShuffleVectorInst(ShuffleVectorInst &I);
  void visitExtractValueInst(ExtractValueInst &I);
  void visitInsertValueInst(InsertValueInst &I);
  void visitAllocaInst(AllocaInst &I);
  void visitSelectInst(SelectInst &I);
  void visitMemSetInst(MemSetInst &I);
  void visitMemTransferInst(MemTransferInst &I);
  void visitBranchInst(BranchInst &BR);
  void visitSwitchInst(SwitchInst &SW);

private:
  //void visitCASOrRMW(Align InstAlignment, Instruction &I);

  // Returns false when this is an invoke of a custom function.
  bool visitWrappedCallBase(Function *F, CallBase &CB);

  void addShadowArguments(Function *F, CallBase &CB, std::vector<Value *> &Args,
                          IRBuilder<> &IRB);

  void visitIntrinsicCallBase(Function *F, CallBase &CB);
};

} // end anonymous namespace

Taint::Taint(
    const std::vector<std::string> &ABIListFiles) {
  std::vector<std::string> AllABIListFiles(std::move(ABIListFiles));
  llvm::append_range(AllABIListFiles, ClABIListFiles);
  // FIXME: should we propagate vfs::FileSystem to this constructor?
  ABIList.set(
      SpecialCaseList::createOrDie(AllABIListFiles, *vfs::getRealFileSystem()));
}

FunctionType *Taint::getArgsFunctionType(FunctionType *T) {
  SmallVector<Type *, 4> ArgTypes(T->param_begin(), T->param_end());
  // we keep the shadow type consistent with the arg type so we don't
  // need to collapse or expand the shadow
  for (unsigned i = 0, ie = T->getNumParams(); i != ie; ++i) {
    Type* param_type = T->getParamType(i);
    ArgTypes.push_back(getShadowTy(param_type));
  }
  // ArgTypes.append(T->getNumParams(), PrimitiveShadowTy);
  if (T->isVarArg()) // FIXME: vararg
    ArgTypes.push_back(PrimitiveShadowPtrTy);
  Type *RetType = T->getReturnType();
  if (!RetType->isVoidTy())
    RetType = StructType::get(RetType, getShadowTy(RetType));
  return FunctionType::get(RetType, ArgTypes, T->isVarArg());
}


TransformedFunction Taint::getCustomFunctionType(FunctionType *T) {
  SmallVector<Type *, 4> ArgTypes;

  // Some parameters of the custom function being constructed are
  // parameters of T.  Record the mapping from parameters of T to
  // parameters of the custom function, so that parameter attributes
  // at call sites can be updated.
  std::vector<unsigned> ArgumentIndexMapping;
  for (unsigned I = 0, E = T->getNumParams(); I != E; ++I) {
    Type* ParamType = T->getParamType(I);
    // Opaque pointers hide the pointee type, so custom-wrapper trampolines for
    // function-pointer arguments cannot be detected; pass the parameter through.
    ArgumentIndexMapping.push_back(ArgTypes.size());
    ArgTypes.push_back(ParamType);
  }
  for (unsigned i = 0, e = T->getNumParams(); i != e; ++i) {
    // we keep the shadow type consistent with the arg type so we don't
    // need to collapse or expand the shadow
    Type* param_type = T->getParamType(i);
    ArgTypes.push_back(getShadowTy(param_type));
    // ArgTypes.push_back(PrimitiveShadowTy);
  }
  if (T->isVarArg()) // FIXME: vararg
    ArgTypes.push_back(PrimitiveShadowPtrTy);
  Type *RetType = T->getReturnType();
  if (!RetType->isVoidTy())
    ArgTypes.push_back(PointerType::getUnqual(getShadowTy(RetType)));
    // ArgTypes.push_back(PrimitiveShadowPtrTy);
  return TransformedFunction(
      T, FunctionType::get(T->getReturnType(), ArgTypes, T->isVarArg()),
      ArgumentIndexMapping);
}

bool Taint::isZeroShadow(Value *V) {
  Type *T = V->getType();
  if (!isa<ArrayType>(T) && !isa<StructType>(T)) {
    if (const ConstantInt *CI = dyn_cast<ConstantInt>(V))
      return CI->isZero();
    return false;
  }

  return isa<ConstantAggregateZero>(V);
}

Constant *Taint::getUninitializedShadow(Type *OrigTy) {
  if (!isa<ArrayType>(OrigTy) && !isa<StructType>(OrigTy))
    return UninitializedPrimitiveShadow;
  Type *ShadowTy = getShadowTy(OrigTy);
  if (ArrayType *AT = dyn_cast<ArrayType>(ShadowTy)) {
    SmallVector<Constant *, 4> Elements(AT->getNumElements(),
                                        getUninitializedShadow(AT->getElementType()));
    return ConstantArray::get(AT, Elements);
  } else if (StructType *ST = dyn_cast<StructType>(ShadowTy)) {
    SmallVector<Constant *, 4> Elements(ST->getNumElements());
    for (unsigned I = 0, N = ST->getNumElements(); I < N; ++I)
      Elements[I] = getUninitializedShadow(ST->getElementType(I));
    return ConstantStruct::get(ST, Elements);
  }
  llvm_unreachable("Unexpected type for uninitialized shadow");
}

Constant *Taint::getZeroShadow(Type *OrigTy) {
  if (!isa<ArrayType>(OrigTy) && !isa<StructType>(OrigTy))
    return ZeroPrimitiveShadow;
  Type *ShadowTy = getShadowTy(OrigTy);
  return ConstantAggregateZero::get(ShadowTy);
}

Constant *Taint::getZeroShadow(Value *V) {
  return getZeroShadow(V->getType());
}

Type *Taint::getShadowTy(Type *OrigTy) {
  if (!OrigTy->isSized())
    return PrimitiveShadowTy;
  if (isa<IntegerType>(OrigTy))
    return PrimitiveShadowTy;
  if (isa<VectorType>(OrigTy))
    return PrimitiveShadowTy;
  if (ArrayType *AT = dyn_cast<ArrayType>(OrigTy))
    return ArrayType::get(getShadowTy(AT->getElementType()),
                          AT->getNumElements());
  if (StructType *ST = dyn_cast<StructType>(OrigTy)) {
    SmallVector<Type *, 4> Elements;
    for (unsigned I = 0, N = ST->getNumElements(); I < N; ++I)
      Elements.push_back(getShadowTy(ST->getElementType(I)));
    return StructType::get(*Ctx, Elements);
  }
  return PrimitiveShadowTy;
}

Type *Taint::getShadowTy(Value *V) {
  return getShadowTy(V->getType());
}

uint32_t Taint::getInstructionId(Instruction *Inst) {
  // check if there is a bbid annotation from UCSan ("dfsan.bb")
  MDNode *BBID = Inst->getMetadata("dfsan.bb");
  // For non-terminator instructions, try getting bbid from the block's terminator
  if (!BBID && !Inst->isTerminator()) {
    Instruction *Term = Inst->getParent()->getTerminator();
    BBID = Term->getMetadata("dfsan.bb");
  }
  if (BBID) {
    auto C = dyn_cast<ConstantAsMetadata>(BBID->getOperand(0));
    if (ConstantInt *CI = dyn_cast<ConstantInt>(C->getValue())) {
      uint64_t BBIDValue = CI->getZExtValue();
      assert(BBIDValue < UINT32_MAX &&
             "bbid value is too large for 32-bit hash");
      return static_cast<uint32_t>(BBIDValue);
    }
  }
  if (ClTraceAnnotatedBB && Inst->isTerminator())
    return InvalidInstructionId;

  // otherwise, fallback to hash
  static uint32_t unamed = 0;
  DILocation *Loc = Inst->getDebugLoc();
  if (Loc) {
    auto Line = Loc->getLine();
    auto Col = Loc->getColumn();
    // Hash the *debug location's* file, not Mod->getSourceFileName(): the two
    // differ for anything the inliner moved, and only the former is a key
    // AFL++'s link-time instrumentation can compute for the same branch.
    // symsan::branch_cid is the single definition of that key; see
    // include/branch_id.h.
    return symsan::branch_cid(Loc->getFilename().str(), Line, Col);
  }

  auto SourceInfo = Mod->getSourceFileName();
  SourceInfo += "unamed:" + std::to_string(unamed++);
  return djbHash(SourceInfo);
}

// The counterpart of AFL++'s AFL_LLVM_DOCUMENT_IDS.  That one says which source
// location each *edge id* came from; this one says which source location each
// *branch id* came from.  Diffing the two tables answers "do the two builds
// name the same branch the same way?" without running anything, and separates
// the two ways the join can be thin: a location both sides emit but with
// different columns means the two clangs disagree and the join is dead, while a
// location only this side emits is AFL++ having pruned the block, which is
// expected and merely costs opportunities.
//
// The line deliberately echoes AFL++'s: same ModuleID=/Function= lead-in, and
// src= last because a path may contain spaces and colons, so it is parsed from
// the right.
//
// Kind is passed in rather than sniffed from Inst because the interesting
// distinction is not the LLVM opcode but whether the line can join at all.  A
// "switch" line never can -- the switch as a whole is not an edge on the AFL++
// side, only its individual cases are, and those come out as "switch-case"
// lines with their own cid.  A "select" line cannot join either, though only
// for want of a patch: AFL++ does allocate two edge ids per scalar select, it
// just never writes them to its ids file.  Saying which is which here keeps a
// line with no counterpart from being read as evidence of a broken build.
//
// Extra is anything belonging between kind= and src=; a switch case uses it to
// carry the case value that, with the switch's location, makes up its id.
void Taint::documentBranchId(uint32_t cid, Instruction *Inst,
                             const char *Kind, const std::string &Extra) {
  if (DocumentIdsPath.empty())
    return;

  std::string Line = "ModuleID=" + Mod->getSourceFileName();
  if (const Function *F = Inst->getFunction())
    Line += " Function=" + F->getName().str();
  Line += " cid=" + std::to_string(cid);
  Line += " kind=";
  Line += Kind;
  if (!Extra.empty())
    Line += " " + Extra;
  // No debug location means the id came from the "unamed:" counter, which is
  // per-module state and not a key anything else can compute.  Emit the line
  // anyway: a build accidentally missing -g shows up as every line lacking a
  // src=, which is a much clearer diagnosis than an empty intersection.
  if (const DILocation *Loc = Inst->getDebugLoc()) {
    Line += " src=" + Loc->getFilename().str() + ":" +
            std::to_string(Loc->getLine()) + ":" +
            std::to_string(Loc->getColumn());
  }
  DocumentedIds.push_back(std::move(Line));
}

void Taint::flushDocumentedIds() {
  if (DocumentIdsPath.empty() || DocumentedIds.empty())
    return;

  std::string Buf;
  for (const auto &Line : DocumentedIds) {
    Buf += Line;
    Buf += '\n';
  }
  DocumentedIds.clear();

  // Every TU of a parallel build appends to the same file, so take the lock
  // rather than trusting one write() to be indivisible.  A failure here is
  // reported and otherwise ignored: this is a diagnostic, and refusing to
  // compile because it could not be written would be the wrong trade.
  int Fd = open(DocumentIdsPath.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (Fd < 0) {
    errs() << "SymSan: cannot open SYMSAN_DOCUMENT_IDS file "
           << DocumentIdsPath << ": " << strerror(errno) << "\n";
    return;
  }
  if (flock(Fd, LOCK_EX) == 0) {
    if (write(Fd, Buf.data(), Buf.size()) != (ssize_t)Buf.size())
      errs() << "SymSan: short write to " << DocumentIdsPath << "\n";
    flock(Fd, LOCK_UN);
  }
  close(Fd);
}

void Taint::addContextRecording(Function &F) {
  // Most code from Angora
  BasicBlock *BB = &F.getEntryBlock();
  assert(pred_begin(BB) == pred_end(BB) &&
         "Assume that entry block has no predecessors");

  // Add ctx ^ hash(fun_name) at the beginning of a function
  IRBuilder<> IRB(&*(BB->getFirstInsertionPt()));

  // Strip dfs$ prefix
  auto FName = F.getName();
  if ((FName).starts_with("dfs")) {
    size_t pos = FName.find_first_of('$');
    FName = FName.drop_front(pos + 1);
  }
  // add source file name for static function
  if (!F.hasExternalLinkage()) {
    FName = StringRef(Mod->getSourceFileName() + "::" + FName.str());
  }
  uint32_t hash = djbHash(FName);

  ConstantInt *CID = ConstantInt::get(Int32Ty, hash);
  LoadInst *LCS = IRB.CreateLoad(Int32Ty, CallStack);
  LCS->setMetadata(Mod->getMDKindID("nosanitize"), MDNode::get(*Ctx, std::nullopt));
  Value *NCS = IRB.CreateXor(LCS, CID);
  StoreInst *SCS = IRB.CreateStore(NCS, CallStack);
  SCS->setMetadata(Mod->getMDKindID("nosanitize"), MDNode::get(*Ctx, std::nullopt));

  // Recover ctx at the end of a function
  for (auto FI = F.begin(), FE = F.end(); FI != FE; FI++) {
    BasicBlock *BB = &*FI;
    Instruction *Inst = BB->getTerminator();
    if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {
      IRB.SetInsertPoint(Inst);
      SCS = IRB.CreateStore(LCS, CallStack);
      SCS->setMetadata(Mod->getMDKindID("nosanitize"), MDNode::get(*Ctx, std::nullopt));
    }
  }
}

void Taint::addFrameTracing(Function &F) {
  BasicBlock *BB = &F.getEntryBlock();
  assert(pred_begin(BB) == pred_end(BB) &&
         "Assume that entry block has no predecessors");

  IRBuilder<> IRB(&*(BB->getFirstInsertionPt()));
  IRB.CreateCall(TaintPushStackFrameFn);

  // Recover ctx at the end of a function
  for (auto FI = F.begin(), FE = F.end(); FI != FE; FI++) {
    BasicBlock *BB = &*FI;
    Instruction *Inst = BB->getTerminator();
    if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {
      IRB.SetInsertPoint(Inst);
      IRB.CreateCall(TaintPopStackFrameFn);
    }
  }
}

bool Taint::initializeModule(Module &M) {
  Triple TargetTriple(M.getTargetTriple());
  const DataLayout &DL = M.getDataLayout();

  if (TargetTriple.getOS() != Triple::Linux)
    report_fatal_error("unsupported operating system");
  switch (TargetTriple.getArch()) {
  case Triple::x86_64:
    MapParams = &Linux_X86_64_MemoryMapParams;
    break;
  default:
    report_fatal_error("unsupported architecture");
  }

  Mod = &M;
  Ctx = &M.getContext();
  // An environment variable rather than a -mllvm flag, to match how AFL++
  // spells the same thing and so that a whole build can be documented by
  // exporting one variable.
  if (const char *P = getenv("SYMSAN_DOCUMENT_IDS"))
    DocumentIdsPath = P;
  Int8Ty = IntegerType::get(*Ctx, 8);
  Int16Ty = IntegerType::get(*Ctx, 16);
  Int32Ty = IntegerType::get(*Ctx, 32);
  Int64Ty = IntegerType::get(*Ctx, 64);
  PrimitiveShadowTy = IntegerType::get(*Ctx, ShadowWidthBits);
  PrimitiveShadowPtrTy = PointerType::getUnqual(PrimitiveShadowTy);
  IntptrTy = DL.getIntPtrType(*Ctx);
  VoidPtrTy = PointerType::getUnqual(Int8Ty);
  ZeroPrimitiveShadow = ConstantInt::getSigned(PrimitiveShadowTy, 0);
  UninitializedPrimitiveShadow = ConstantInt::getSigned(PrimitiveShadowTy, -1);
  ShadowPtrMul = ConstantInt::get(IntptrTy, ShadowWidthBytes);
  ShadowPtrAndMask = ShadowPtrXorMask = ShadowPtrBase = nullptr;
  if (MapParams->AndMask != 0)
    ShadowPtrAndMask = ConstantInt::get(IntptrTy, ~MapParams->AndMask);
  if (MapParams->XorMask != 0)
    ShadowPtrXorMask = ConstantInt::get(IntptrTy, MapParams->XorMask);
  if (MapParams->ShadowBase != 0)
    ShadowPtrBase = ConstantInt::get(IntptrTy, MapParams->ShadowBase);

  Type *TaintUnionArgs[6] = { PrimitiveShadowTy, PrimitiveShadowTy,
      Int16Ty, Int16Ty, Int64Ty, Int64Ty};
  TaintUnionFnTy = FunctionType::get(
      PrimitiveShadowTy, TaintUnionArgs, /*isVarArg=*/ false);
  // Normalizes ONE operand of an operation wider than 64 bits to a real label,
  // to be called before __taint_union rather than instead of it: a symbolic
  // operand keeps its label, a concrete one becomes a WideConst leaf built from
  // the full value.  Hence lo and hi -- op1/op2 in dfsan_label_info are 64 bits
  // each, so a >64-bit concrete operand does not fit in one.
  // args: label, lo, hi, size
  Type *TaintGetWideArgs[4] = { PrimitiveShadowTy, Int64Ty, Int64Ty, Int16Ty };
  TaintGetWideFnTy = FunctionType::get(
      PrimitiveShadowTy, TaintGetWideArgs, /*isVarArg=*/ false);
  Type *TaintUnionLoadArgs[4] = { PrimitiveShadowPtrTy, IntptrTy, Int64Ty, Int64Ty };
  TaintUnionLoadFnTy = FunctionType::get(
      PrimitiveShadowTy, TaintUnionLoadArgs, /*isVarArg=*/ false);
  // args: shadow_ptr, n (bytes), size_in_bits, align
  Type *TaintUnionStoreArgs[4] = { PrimitiveShadowTy, PrimitiveShadowPtrTy,
      IntptrTy, Int64Ty };
  TaintUnionStoreFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), TaintUnionStoreArgs, /*isVarArg=*/ false);
  TaintGEPOffsetFnTy = FunctionType::get(
      PrimitiveShadowTy,
      { PrimitiveShadowTy, VoidPtrTy, VoidPtrTy }, /*isVarArg=*/ false);
  TaintUnimplementedFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), PointerType::getUnqual(*Ctx), /*isVarArg=*/false);
  Type *TaintWrapperExternWeakNullArgs[2] = { PointerType::getUnqual(*Ctx),
      PointerType::getUnqual(*Ctx) };
  TaintWrapperExternWeakNullFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), TaintWrapperExternWeakNullArgs, /*isVarArg=*/false);
  Type *TaintSetLabelArgs[3] = { PrimitiveShadowTy, PointerType::getUnqual(*Ctx),
      IntptrTy };
  TaintSetLabelFnTy = FunctionType::get(Type::getVoidTy(*Ctx),
                                        TaintSetLabelArgs, /*isVarArg=*/false);
  TaintNonzeroLabelFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), std::nullopt, /*isVarArg=*/false);
  TaintVarargWrapperFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), PointerType::getUnqual(*Ctx), /*isVarArg=*/false);
  Type *TaintTraceCmpArgs[7] = { PrimitiveShadowTy, PrimitiveShadowTy,
      Int32Ty, Int32Ty, Int64Ty, Int64Ty, Int32Ty };
  TaintTraceCmpFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), TaintTraceCmpArgs, false);
  Type *TaintTraceCondArgs[4] = { PrimitiveShadowTy, IntegerType::get(*Ctx, 1),
      Int8Ty, Int32Ty };
  TaintTraceCondFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), TaintTraceCondArgs, false);
  TaintTraceLoopFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), { Int32Ty, Int32Ty }, false);
  TaintTraceSwitchEndFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), { Int32Ty }, false);
  Type *TaintTraceSelectArgs[] = { PrimitiveShadowTy, PrimitiveShadowTy,
      PrimitiveShadowTy, Int8Ty, Int8Ty, Int8Ty, Int32Ty };
  TaintTraceSelectFnTy = FunctionType::get(
      PrimitiveShadowTy, TaintTraceSelectArgs, false);
  TaintTraceIndirectCallFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), { PrimitiveShadowTy }, false);
  Type *TaintTraceGEPArgs[8] = { PrimitiveShadowTy, Int64Ty, PrimitiveShadowTy,
      Int64Ty, Int64Ty, Int64Ty, Int64Ty, Int32Ty };
  TaintTraceGEPFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), TaintTraceGEPArgs, false);
  // __taint_table_lookup(index_label, index, table_ptr, num_elems, elem_size)
  // -> label for the loaded element
  Type *TaintTableLookupArgs[5] =
      { PrimitiveShadowTy, Int64Ty, Int64Ty, Int64Ty, Int64Ty };
  TaintTableLookupFnTy = FunctionType::get(
      PrimitiveShadowTy, TaintTableLookupArgs, false);
  TaintPushStackFrameFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), {}, false);
  TaintPopStackFrameFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), {}, false);
  Type *TaintTraceAllocaArgs[4] =
      { PrimitiveShadowTy, Int64Ty, Int64Ty, Int64Ty };
  TaintTraceAllocaFnTy = FunctionType::get(
      PrimitiveShadowTy, TaintTraceAllocaArgs, false);
  TaintCheckBoundsFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx),
      { PrimitiveShadowTy, Int64Ty, PrimitiveShadowTy, Int64Ty }, false);
  TaintSolveBoundsFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), TaintTraceGEPArgs, false); // use the same args as GEP
  TaintSolveSizeFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx),
      { PrimitiveShadowTy, Int64Ty, PrimitiveShadowTy, Int64Ty, Int32Ty }, false);
  // __taint_solve_str_bounds(str_ptr, buf_label, buf_ptr, step)
  TaintSolveStrBoundsFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx),
      { PointerType::getUnqual(*Ctx), PrimitiveShadowTy, Int64Ty, Int64Ty }, false);
  TaintTraceGlobalFnTy = FunctionType::get(
      PrimitiveShadowTy, { Int64Ty, Int64Ty }, false);

  TaintDebugFnTy = FunctionType::get(Type::getVoidTy(*Ctx),
      {PrimitiveShadowTy, PrimitiveShadowTy, PrimitiveShadowTy,
       PrimitiveShadowTy, PrimitiveShadowTy}, false);

  TaintMinimizeLabelFnTy = FunctionType::get(Type::getVoidTy(*Ctx),
      { PrimitiveShadowTy, Int64Ty, PrimitiveShadowTy }, false);

  ColdCallWeights = MDBuilder(*Ctx).createBranchWeights(1, 1000);
  return true;
}

bool Taint::isInstrumented(const Function *F) {
  return !ABIList.isIn(*F, "uninstrumented");
}

bool Taint::isInstrumented(const GlobalAlias *GA) {
  return !ABIList.isIn(*GA, "uninstrumented");
}

bool Taint::isForceZeroLabels(const Function *F) {
  return ABIList.isIn(*F, "force_zero_labels");
}

Taint::WrapperKind Taint::getWrapperKind(Function *F) {
  // priority custom
  if (ABIList.isIn(*F, "custom"))
    return WK_Custom;
  if (ABIList.isIn(*F, "memcmp"))
    return WK_Memcmp;
  if (ABIList.isIn(*F, "strcmp"))
    return WK_Strcmp;
  if (ABIList.isIn(*F, "strncmp"))
    return WK_Strncmp;
  if (ABIList.isIn(*F, "strchr"))
    return WK_Strchr;
  if (ABIList.isIn(*F, "strrchr"))
    return WK_Strrchr;
  if (ABIList.isIn(*F, "strstr"))
    return WK_Strstr;
  if (ABIList.isIn(*F, "prefixof"))
    return WK_Prefixof;
  if (ABIList.isIn(*F, "suffixof"))
    return WK_Suffixof;
  if (ABIList.isIn(*F, "strcat"))
    return WK_Strcat;
  if (ABIList.isIn(*F, "strsub"))
    return WK_Strsub;
  if (ABIList.isIn(*F, "functional"))
    return WK_Functional;
  if (ABIList.isIn(*F, "discard"))
    return WK_Discard;

  return WK_Warning;
}

void Taint::addGlobalNameSuffix(GlobalValue *GV) {
  std::string GVName = std::string(GV->getName()), Suffix = ".taint";
  GV->setName(GVName + Suffix);

  // Try to change the name of the function in module inline asm.  We only do
  // this for specific asm directives, currently only ".symver", to try to avoid
  // corrupting asm which happens to contain the symbol name as a substring.
  // Note that the substitution for .symver assumes that the versioned symbol
  // also has an instrumented name.
  std::string Asm = GV->getParent()->getModuleInlineAsm();
  std::string SearchStr = ".symver " + GVName + ",";
  size_t Pos = Asm.find(SearchStr);
  if (Pos != std::string::npos) {
    Asm.replace(Pos, SearchStr.size(), ".symver " + GVName + Suffix + ",");
    Pos = Asm.find("@");

    if (Pos == std::string::npos)
      report_fatal_error(Twine("unsupported .symver: ", Asm));

    Asm.replace(Pos, 1, Suffix + "@");
    GV->getParent()->setModuleInlineAsm(Asm);
  }
}

void Taint::buildExternWeakCheckIfNeeded(IRBuilder<> &IRB, Function *F) {
  // If the function we are wrapping was ExternWeak, it may be null.
  // The original code before calling this wrapper may have checked for null,
  // but replacing with a known-to-not-be-null wrapper can break this check.
  // When replacing uses of the extern weak function with the wrapper we try
  // to avoid replacing uses in conditionals, but this is not perfect.
  // In the case where we fail, and accidentially optimize out a null check
  // for a extern weak function, add a check here to help identify the issue.
  if (GlobalValue::isExternalWeakLinkage(F->getLinkage())) {
    std::vector<Value *> Args;
    Args.push_back(IRB.CreatePointerCast(F, PointerType::getUnqual(*Ctx)));
    Args.push_back(IRB.CreateGlobalStringPtr(F->getName()));
    IRB.CreateCall(TaintWrapperExternWeakNullFn, Args);
  }
}

Function *
Taint::buildWrapperFunction(Function *F, StringRef NewFName,
                            GlobalValue::LinkageTypes NewFLink,
                            FunctionType *NewFT) {
  FunctionType *FT = F->getFunctionType();
  Function *NewF = Function::Create(NewFT, NewFLink, F->getAddressSpace(),
                                    NewFName, F->getParent());
  NewF->copyAttributesFrom(F);
  NewF->removeRetAttrs(
      AttributeFuncs::typeIncompatible(NewFT->getReturnType()));

  BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", NewF);
  if (F->isVarArg() && getWrapperKind(F) != WK_Custom) {
    // keep the invocation if custom (e.g., open)
    NewF->removeFnAttr("split-stack");
    CallInst::Create(TaintVarargWrapperFn,
                     IRBuilder<>(BB).CreateGlobalStringPtr(F->getName()), "",
                     BB);
    new UnreachableInst(*Ctx, BB);
  } else {
    auto ArgIt = pointer_iterator<Argument *>(NewF->arg_begin());
    std::vector<Value *> Args(ArgIt, ArgIt + FT->getNumParams());

    CallInst *CI = CallInst::Create(F, Args, "", BB);
    if (FT->getReturnType()->isVoidTy())
      ReturnInst::Create(*Ctx, BB);
    else
      ReturnInst::Create(*Ctx, CI, BB);
  }

  return NewF;
}

// Initialize DataFlowSanitizer runtime functions and declare them in the module
void Taint::initializeRuntimeFunctions(Module &M) {
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addRetAttribute(M.getContext(), Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
    TaintUnionFn =
        Mod->getOrInsertFunction("__taint_union", TaintUnionFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addRetAttribute(M.getContext(), Attribute::ZExt);
    // only param 0 is a label; 1 and 2 are full i64 value halves
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintGetWideFn =
        Mod->getOrInsertFunction("__taint_get_wide", TaintGetWideFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addRetAttribute(M.getContext(), Attribute::ZExt);
    TaintUnionLoadFn =
        Mod->getOrInsertFunction("__taint_union_load", TaintUnionLoadFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintUnionStoreFn =
        Mod->getOrInsertFunction("__taint_union_store", TaintUnionStoreFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addRetAttribute(M.getContext(), Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintGEPOffsetFn =
        Mod->getOrInsertFunction("__taint_gep_offset", TaintGEPOffsetFnTy, AL);
  }
  {
    TaintUnimplementedFn =
        Mod->getOrInsertFunction("__dfsan_unimplemented", TaintUnimplementedFnTy);
  }
  {
    TaintWrapperExternWeakNullFn = Mod->getOrInsertFunction(
        "__dfsan_wrapper_extern_weak_null", TaintWrapperExternWeakNullFnTy);
  }
  {
    AttributeList AL;
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintSetLabelFn =
        Mod->getOrInsertFunction("__dfsan_set_label", TaintSetLabelFnTy, AL);
  }
  {
    TaintNonzeroLabelFn =
        Mod->getOrInsertFunction("__dfsan_nonzero_label", TaintNonzeroLabelFnTy);
  }
  {
    TaintVarargWrapperFn = Mod->getOrInsertFunction("__dfsan_vararg_wrapper",
                                                    TaintVarargWrapperFnTy);
  }
  {
    TaintDebugFn =
        Mod->getOrInsertFunction("__taint_debug", TaintDebugFnTy);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintMinimizeLabelFn =
        Mod->getOrInsertFunction("__taint_minimize_label", TaintMinimizeLabelFnTy, AL);
  }

  TaintRuntimeFunctions.insert(
      TaintUnionFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintGetWideFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintUnionLoadFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintUnionStoreFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintGEPOffsetFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintUnimplementedFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintWrapperExternWeakNullFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintSetLabelFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintNonzeroLabelFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintVarargWrapperFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintDebugFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintMinimizeLabelFn.getCallee()->stripPointerCasts());
}

// Initializes event callback functions and declare them in the module
void Taint::initializeCallbackFunctions(Module &M) {
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
    TaintTraceCmpFn =
        Mod->getOrInsertFunction("__taint_trace_cmp", TaintTraceCmpFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
    TaintTraceCondFn =
        Mod->getOrInsertFunction("__taint_trace_cond", TaintTraceCondFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    TaintTraceLoopFn =
        Mod->getOrInsertFunction("__taint_trace_loop", TaintTraceLoopFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    TaintTraceSwitchEndFn =
        Mod->getOrInsertFunction("__taint_trace_switch_end", TaintTraceSwitchEndFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 2, Attribute::ZExt);
    TaintTraceSelectFn =
        Mod->getOrInsertFunction("__taint_trace_select", TaintTraceSelectFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintTraceIndirectCallFn =
        Mod->getOrInsertFunction("__taint_trace_indcall", TaintTraceIndirectCallFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 2, Attribute::ZExt);
    TaintTraceGEPFn =
        Mod->getOrInsertFunction("__taint_trace_gep", TaintTraceGEPFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addRetAttribute(M.getContext(), Attribute::ZExt);
    TaintTableLookupFn =
        Mod->getOrInsertFunction("__taint_table_lookup", TaintTableLookupFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    TaintPushStackFrameFn =
        Mod->getOrInsertFunction("__taint_push_stack_frame", TaintPushStackFrameFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    TaintPopStackFrameFn =
        Mod->getOrInsertFunction("__taint_pop_stack_frame", TaintPopStackFrameFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addRetAttribute(M.getContext(), Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintTraceAllocaFn =
        Mod->getOrInsertFunction("__taint_trace_alloca", TaintTraceAllocaFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addRetAttribute(M.getContext(), Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
    TaintTraceGlobalFn =
        Mod->getOrInsertFunction("__taint_trace_global", TaintTraceGlobalFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintCheckBoundsFn =
        Mod->getOrInsertFunction("__taint_check_bounds", TaintCheckBoundsFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 2, Attribute::ZExt);
    TaintSolveBoundsFn =
        Mod->getOrInsertFunction("__taint_solve_bounds", TaintSolveBoundsFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 2, Attribute::ZExt);
    TaintSolveSizeFn =
        Mod->getOrInsertFunction("__taint_solve_size", TaintSolveSizeFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
    AL = AL.addFnAttribute(M.getContext(), Attribute::NoMerge);
    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
    TaintSolveStrBoundsFn =
        Mod->getOrInsertFunction("__taint_solve_str_bounds", TaintSolveStrBoundsFnTy, AL);
  }

  TaintRuntimeFunctions.insert(
      TaintTraceCmpFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintTraceCondFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintTraceLoopFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintTraceSwitchEndFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintTraceSelectFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintTraceIndirectCallFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintTraceGEPFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintTableLookupFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintPushStackFrameFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintPopStackFrameFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintTraceAllocaFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintTraceGlobalFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintCheckBoundsFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintSolveBoundsFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintSolveSizeFn.getCallee()->stripPointerCasts());
  TaintRuntimeFunctions.insert(
      TaintSolveStrBoundsFn.getCallee()->stripPointerCasts());
}

bool Taint::runImpl(Module &M) {
  initializeModule(M);

  if (ABIList.isIn(M, "skip"))
    return false;

  const unsigned InitialGlobalSize = M.global_size();
  const unsigned InitialModuleSize = M.size();

  bool Changed = false;

  auto GetOrInsertGlobal = [this, &Changed](StringRef Name,
                                            Type *Ty) -> Constant * {
    Constant *C = Mod->getOrInsertGlobal(Name, Ty);
    if (GlobalVariable *G = dyn_cast<GlobalVariable>(C)) {
      Changed |= G->getThreadLocalMode() != GlobalVariable::InitialExecTLSModel;
      G->setThreadLocalMode(GlobalVariable::InitialExecTLSModel);
    }
    return C;
  };

  // These globals must be kept in sync with the ones in dfsan.cpp.
  ArgTLS =
      GetOrInsertGlobal("__dfsan_arg_tls",
                        ArrayType::get(Int64Ty, ArgTLSSize / 8));
  RetvalTLS =
      GetOrInsertGlobal("__dfsan_retval_tls",
                        ArrayType::get(Int64Ty, RetvalTLSSize / 8));
  CallStack = GetOrInsertGlobal("__taint_trace_callstack", Int32Ty);

  initializeCallbackFunctions(M);
  initializeRuntimeFunctions(M);

  // Before touching any IR: see findReadOnlyTables().
  findReadOnlyTables(M);

  std::vector<Function *> FnsToInstrument;
  SmallPtrSet<Function *, 8> IFuncs;
  SmallPtrSet<Function *, 2> FnsWithNativeABI;
  SmallPtrSet<Function *, 2> FnsWithForceZeroLabel;
  SmallPtrSet<Constant *, 1> PersonalityFns;

  // find ifunc resolvers and their dependencies, we can't instrument them
  // as dfsan initialization is not done yet
  for (auto &ifunc : M.ifuncs()) {
    auto *resolver = ifunc.getResolverFunction();
    IFuncs.insert(resolver);
    for (auto &I : instructions(resolver)) {
      if (CallBase *CB = dyn_cast<CallBase>(&I)) {
        if (Function *Callee = CB->getCalledFunction()) {
          IFuncs.insert(Callee);
        }
      }
    }
  }

  for (Function &F : M) {
    if (!F.isIntrinsic() && !TaintRuntimeFunctions.count(&F) &&
        !IFuncs.count(&F) &&
        !F.hasFnAttribute(Attribute::DisableSanitizerInstrumentation)) {
      FnsToInstrument.push_back(&F);
      if (F.hasPersonalityFn())
        PersonalityFns.insert(F.getPersonalityFn());
    }
  }

  if (ClIgnorePersonalityRoutine) {
    for (auto *C : PersonalityFns) {
      assert(isa<Function>(C) && "Personality routine is not a function!");
      Function *F = cast<Function>(C);
      if (!isInstrumented(F))
        FnsToInstrument.erase(
            std::remove(FnsToInstrument.begin(), FnsToInstrument.end(), F),
            FnsToInstrument.end());
    }
  }

  // Give function aliases suffixes when necessary, and build wrappers where the
  // instrumentedness is inconsistent.
  for (GlobalAlias &GA : llvm::make_early_inc_range(M.aliases())) {
    // Don't stop on weak.  We assume people aren't playing games with the
    // instrumentedness of overridden weak aliases.
    auto F = dyn_cast<Function>(GA.getAliaseeObject());
    if (!F)
      continue;

    // Skip functions with nosanitize metadata
    if (F->hasFnAttribute(Attribute::DisableSanitizerInstrumentation))
      continue;

    bool GAInst = isInstrumented(&GA), FInst = isInstrumented(F);
    if (GAInst && FInst) {
      addGlobalNameSuffix(&GA);
    } else if (GAInst != FInst) {
      // Non-instrumented alias of an instrumented function, or vice versa.
      // Replace the alias with a native-ABI wrapper of the aliasee.  The pass
      // below will take care of instrumenting it.
      Function *NewF =
          buildWrapperFunction(F, "", GA.getLinkage(), F->getFunctionType());
      GA.replaceAllUsesWith(ConstantExpr::getBitCast(NewF, GA.getType()));
      NewF->takeName(&GA);
      GA.eraseFromParent();
      FnsToInstrument.push_back(NewF);
    }
  }

  ReadOnlyNoneAttrs.addAttribute(Attribute::ReadOnly)
      .addAttribute(Attribute::ReadNone);

  // First, change the ABI of every function in the module.  ABI-listed
  // functions keep their original ABI and get a wrapper function.
  for (std::vector<Function *>::iterator FI = FnsToInstrument.begin(),
                                         FE = FnsToInstrument.end();
       FI != FE; ++FI) {
    Function &F = **FI;
    FunctionType *FT = F.getFunctionType();

    bool IsZeroArgsVoidRet = (FT->getNumParams() == 0 && !FT->isVarArg() &&
                              FT->getReturnType()->isVoidTy());

    if (isInstrumented(&F)) {
      if (isForceZeroLabels(&F))
        FnsWithForceZeroLabel.insert(&F);

      // Instrumented functions get a '.taint' sufffix.  This allows us to more
      // easily identify cases of mismatching ABIs. This naming scheme is
      // mangling-compatible (see Itanium ABI), using a vendor-specific suffix.
      addGlobalNameSuffix(&F);
    } else if (!IsZeroArgsVoidRet || getWrapperKind(&F) == WK_Custom) {
      if (FT->isVarArg() && F.isDeclaration() && F.hasAddressTaken() &&
          !isInstrumented(&F)) {
        // FIXME: vararg functions do used as indirect call targets
        *FI = nullptr;
        continue;
      }

      // Build a wrapper function for F.  The wrapper simply calls F, and is
      // added to FnsToInstrument so that any instrumentation according to its
      // WrapperKind is done in the second pass below.

      // If the function being wrapped has local linkage, then preserve the
      // function's linkage in the wrapper function.
      GlobalValue::LinkageTypes wrapperLinkage =
          F.hasLocalLinkage() ? F.getLinkage()
                              : GlobalValue::LinkOnceODRLinkage;

      Function *NewF = buildWrapperFunction(
          &F,
          std::string("dfsw$") + std::string(F.getName()),
          wrapperLinkage, FT);
      NewF->removeFnAttrs(ReadOnlyNoneAttrs);

      Value *WrappedFnCst =
          ConstantExpr::getBitCast(NewF, PointerType::getUnqual(FT));

      // Extern weak functions can sometimes be null at execution time.
      // Code will sometimes check if an extern weak function is null.
      // This could look something like:
      //   declare extern_weak i8 @my_func(i8)
      //   br i1 icmp ne (i8 (i8)* @my_func, i8 (i8)* null), label %use_my_func,
      //   label %avoid_my_func
      // The @"dfsw$my_func" wrapper is never null, so if we replace this use
      // in the comparision, the icmp will simplify to false and we have
      // accidentially optimized away a null check that is necessary.
      // This can lead to a crash when the null extern_weak my_func is called.
      //
      // To prevent (the most common pattern of) this problem,
      // do not replace uses in comparisons with the wrapper.
      // We definitely want to replace uses in call instructions.
      // Other uses (e.g. store the function address somewhere) might be
      // called or compared or both - this case may not be handled correctly.
      // We will default to replacing with wrapper in cases we are unsure.
      auto IsNotCmpUse = [](Use &U) -> bool {
        User *Usr = U.getUser();
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(Usr)) {
          // This is the most common case for icmp ne null
          if (CE->getOpcode() == Instruction::ICmp) {
            return false;
          }
        }
        if (Instruction *I = dyn_cast<Instruction>(Usr)) {
          if (I->getOpcode() == Instruction::ICmp) {
            return false;
          }
        }
        return true;
      };
      F.replaceUsesWithIf(WrappedFnCst, IsNotCmpUse);

      UnwrappedFnMap[WrappedFnCst] = &F;
      *FI = NewF;

      if (!F.isDeclaration()) {
        // This function is probably defining an interposition of an
        // uninstrumented function and hence needs to keep the original ABI.
        // But any functions it may call need to use the instrumented ABI, so
        // we instrument it in a mode which preserves the original ABI.
        FnsWithNativeABI.insert(&F);

        // This code needs to rebuild the iterators, as they may be invalidated
        // by the push_back, taking care that the new range does not include
        // any functions added by this code.
        size_t N = FI - FnsToInstrument.begin(),
               Count = FE - FnsToInstrument.begin();
        FnsToInstrument.push_back(&F);
        FI = FnsToInstrument.begin() + N;
        FE = FnsToInstrument.begin() + Count;
      }
      // Hopefully, nobody will try to indirectly call a vararg
      // function... yet.
    } else if (FT->isVarArg()) {
      UnwrappedFnMap[&F] = &F;
      *FI = nullptr;
    }
  }

  for (Function *F : FnsToInstrument) {
    if (!F || F->isDeclaration())
      continue;

    addContextRecording(*F);
    if (!(F->getName()).starts_with("dfsw$"))
      addFrameTracing(*F);
    removeUnreachableBlocks(*F);

    TaintFunction TF(*this, F, FnsWithNativeABI.count(F),
                     FnsWithForceZeroLabel.count(F));

    // TaintVisitor may create new basic blocks, which confuses df_iterator.
    // Build a copy of the list before iterating over it.
    SmallVector<BasicBlock *, 4> BBList(depth_first(&F->getEntryBlock()));
    std::unordered_map<uint32_t, SmallPtrSet<BasicBlock *, 4>> LoopExits;

    for (BasicBlock *BB : BBList) {
      // check for loop header
      if (ClTraceLoop && TF.LI) {
        Loop *L = TF.LI->getLoopFor(BB);
        if (L) {
          auto *Header = L->getHeader();
          uint32_t LoopIdVal = getInstructionId(Header->getTerminator());
          ConstantInt *LoopID = ConstantInt::get(Int32Ty, LoopIdVal);
          if (Header == BB) {
            // This is a loop header
            Instruction *FI = &*(BB->getFirstInsertionPt());
            ConstantInt *LoopDepth = ConstantInt::get(Int32Ty, TF.LI->getLoopDepth(BB));
            IRBuilder<> IRB(FI);
            IRB.CreateCall(TaintTraceLoopFn, {LoopID, LoopDepth});
          }
          // try to find exits, we do this because predecessors could be incomplete
          for (BasicBlock *Succ : successors(BB)) {
            if (!L->contains(Succ)) {
              auto &Exits = LoopExits[LoopIdVal];
              if (Exits.insert(Succ).second) {
                // only instrument once
                Instruction *FI = &*(Succ->getFirstInsertionPt());
                IRBuilder<> IRB(FI);
                Loop *SuccL = TF.LI->getLoopFor(Succ);
                int succ_depth = SuccL ? SuccL->getLoopDepth() : 0;
                int depth = L->getLoopDepth();
                ConstantInt *LoopDepth = ConstantInt::get(Int32Ty, succ_depth - depth);
                IRB.CreateCall(TaintTraceLoopFn, {LoopID, LoopDepth});
              }
            }
          }
        }
      }

      Instruction *Inst = &BB->front();
      while (true) {
        // TaintVisitor may split the current basic block, changing the current
        // instruction's next pointer and moving the next instruction to the
        // tail block from which we should continue.
        Instruction *Next = Inst->getNextNode();
        // TaintVisitor may delete Inst, so keep track of whether it was a
        // terminator.
        bool IsTerminator = Inst->isTerminator();
        // Handle nosanitize __dfsw_* calls from UCSan
        if (ClWithUCSan && Inst->getMetadata("nosanitize")) {
          if (auto *CI = dyn_cast<CallInst>(Inst)) {
            TF.handleUCSanCall(CI, Next);
          }
        }
        if (!TF.SkipInsts.count(Inst) && !Inst->getMetadata("nosanitize"))
          TaintVisitor(TF).visit(Inst);
        if (IsTerminator)
          break;
        Inst = Next;
      }
    }

    // We will not necessarily be able to compute the shadow for every phi node
    // until we have visited every block.  Therefore, the code that handles phi
    // nodes adds them to the PHIFixups list so that they can be properly
    // handled here.
    for (auto &P : TF.PHIFixups) {
      for (unsigned Val = 0, N = P.Phi->getNumIncomingValues(); Val != N;
           ++Val) {
        P.ShadowPhi->setIncomingValue(
            Val, TF.getShadow(P.Phi->getIncomingValue(Val)));
      }
    }

    // Hoist bounds checks out of loops
    if (ClTraceBound && ClHoistBoundsChecks)
      TF.hoistBoundsChecks();
  }

  flushDocumentedIds();

  return Changed || !FnsToInstrument.empty() ||
         M.global_size() != InitialGlobalSize || M.size() != InitialModuleSize;
}

Value *TaintFunction::getArgTLS(Type *T, unsigned ArgOffset, IRBuilder<> &IRB) {
  Value *Base = IRB.CreatePointerCast(TT.ArgTLS, TT.IntptrTy);
  if (ArgOffset)
    Base = IRB.CreateAdd(Base, ConstantInt::get(TT.IntptrTy, ArgOffset));
  return IRB.CreateIntToPtr(Base, PointerType::get(TT.getShadowTy(T), 0),
                            "_dfsarg"); 
}

Value *TaintFunction::getRetvalTLS(Type *T, IRBuilder<> &IRB) {
  return IRB.CreatePointerCast(
      TT.RetvalTLS, PointerType::get(TT.getShadowTy(T), 0), "_dfsret");
}

Value *TaintFunction::getShadowForTLSArgument(Argument *A) {
  unsigned ArgOffset = 0;
  const DataLayout &DL = F->getParent()->getDataLayout();
  for (auto &FArg : F->args()) {
    if (!FArg.getType()->isSized()) {
      if (A == &FArg)
        break;
      continue;
    }

    unsigned Size = DL.getTypeAllocSize(TT.getShadowTy(&FArg));
    if (A != &FArg) {
      ArgOffset += alignTo(Size, ShadowTLSAlignment);
      if (ArgOffset > ArgTLSSize)
        break; // ArgTLS overflows, uses a zero shadow.
      continue;
    }

    if (ArgOffset + Size > ArgTLSSize)
      break; // ArgTLS overflows, uses a zero shadow.

    Instruction *ArgTLSPos = &*F->getEntryBlock().begin();
    IRBuilder<> IRB(ArgTLSPos);
    Value *ArgShadowPtr = getArgTLS(FArg.getType(), ArgOffset, IRB);
    return IRB.CreateAlignedLoad(TT.getShadowTy(&FArg), ArgShadowPtr,
                                 ShadowTLSAlignment);
  }

  return TT.getZeroShadow(A);
}

Value *TaintFunction::getShadowForGlobal(GlobalVariable *GV, IRBuilder<> &IRB) {
  Type *T = GV->getValueType();
  if (!T && GV->hasInitializer()) {
    T = GV->getInitializer()->getType();
  }
  if (T && (T->isArrayTy() || T->isStructTy())) {
    Module *M = F->getParent();
    auto &DL = M->getDataLayout();
    uint64_t size = T->isSized() ? DL.getTypeAllocSize(T) : 1; // FIXME: default size?
    Value *Size = ConstantInt::get(TT.Int64Ty, size);
    Value *Addr = IRB.CreatePtrToInt(GV, TT.Int64Ty);
    return IRB.CreateCall(TT.TaintTraceGlobalFn, {Addr, Size});
  }
  return TT.ZeroPrimitiveShadow; // GV is always a ptr
}

Value *TaintFunction::getShadow(Value *V) {
  if (!isa<Argument>(V) && !isa<Instruction>(V))
    return TT.getZeroShadow(V);
  if (IsForceZeroLabels)
    return TT.getZeroShadow(V);
  Value *&Shadow = ValShadowMap[V];
  if (!Shadow) {
    if (Argument *A = dyn_cast<Argument>(V)) {
      if (IsNativeABI)
        return TT.getZeroShadow(V);
      Shadow = getShadowForTLSArgument(A);
      NonZeroChecks.push_back(Shadow);
    } else {
      Shadow = TT.getZeroShadow(V);
    }
  }
  return Shadow;
}

void TaintFunction::setShadow(Instruction *I, Value *Shadow) {
  assert(!ValShadowMap.count(I));
  ValShadowMap[I] = Shadow;
}

bool TaintFunction::handleUCSanCall(CallInst *CI, Instruction *Next) {
  Function *Callee = CI->getCalledFunction();
  if (!Callee)
    return false;
  StringRef FName = Callee->getName();
  if (!(FName).starts_with("__dfsw_"))
    return false;

  StringRef BaseName = FName.drop_front(7); // skip "__dfsw_"

  auto GetFakeIORetShadow = [&]() -> Value * {
    // ucsan_custom.cpp simulates reads without forwarding to libc. For these
    // fake full-read paths the return value is derived from the requested
    // count, so keep the return label tied to that argument instead of the
    // wrapper's concrete retval TLS.
    if (BaseName == "read" || BaseName == "pread" ||
        BaseName == "pread64") {
      if (CI->arg_size() > 2)
        return getShadow(CI->getArgOperand(2));
    } else if (BaseName == "fread" || BaseName == "fread_unlocked") {
      if (CI->arg_size() > 2)
        return getShadow(CI->getArgOperand(2));
    }
    return nullptr;
  };

  // Emit minimize hints for allocation size arguments
  SmallVector<unsigned, 2> SizeArgIndices;
  if (BaseName == "malloc" || BaseName == "__libc_malloc" ||
      BaseName == "valloc" || BaseName == "__libc_valloc" ||
      BaseName == "pvalloc" || BaseName == "__libc_pvalloc" ||
      BaseName == "kmalloc_large") {
    SizeArgIndices.push_back(0);
  } else if (BaseName == "calloc" || BaseName == "__libc_calloc") {
    SizeArgIndices.push_back(0);
    SizeArgIndices.push_back(1);
  } else if (BaseName == "realloc" || BaseName == "__libc_realloc" ||
             BaseName == "aligned_alloc" ||
             BaseName == "memalign" || BaseName == "__libc_memalign" ||
             BaseName == "kmalloc" || BaseName == "__kmalloc") {
    SizeArgIndices.push_back(1);
  } else if (BaseName == "reallocarray" || BaseName == "__libc_reallocarray") {
    SizeArgIndices.push_back(1);
    SizeArgIndices.push_back(2);
  } else if (BaseName == "posix_memalign") {
    SizeArgIndices.push_back(2);
  }

  // Load return shadow from retval TLS for non-void __dfsw_* calls
  LoadInst *LI = nullptr;
  if (!CI->getType()->isVoidTy()) {
    IRBuilder<> NextIRB(Next);
    if (Value *RetShadow = GetFakeIORetShadow()) {
      setShadow(CI, RetShadow);
    } else {
      LI = NextIRB.CreateAlignedLoad(
          TT.getShadowTy(CI), getRetvalTLS(CI->getType(), NextIRB),
          ShadowTLSAlignment, "_dfsret");
      SkipInsts.insert(LI);
      setShadow(CI, LI);
    }
  }

  if (!SizeArgIndices.empty()) {
    IRBuilder<> IRB(LI ? LI->getNextNode() : Next);
    for (unsigned Idx : SizeArgIndices) {
      Value *Size = CI->getArgOperand(Idx);
      Value *Shadow = getShadow(Size);
      Value *Bounds = LI;
      if (!Bounds) Bounds = ConstantInt::get(TT.getShadowTy(CI), 0);
      if (!TT.isZeroShadow(Shadow)) {
        IRB.CreateCall(TT.TaintMinimizeLabelFn, {Shadow, Size, Bounds});
      }
    }
  }

  return true;
}

/// Compute the integer shadow offset that corresponds to a given
/// application address.
///
/// Offset = (Addr & ~AndMask) ^ XorMask
Value *Taint::getShadowOffset(Value *Addr, IRBuilder<> &IRB) {
  assert(Addr != RetvalTLS && "Reinstrumenting?");
  Value *OffsetLong = IRB.CreatePointerCast(Addr, IntptrTy);
  if (ShadowPtrAndMask)
    OffsetLong = IRB.CreateAnd(OffsetLong, ShadowPtrAndMask);
  if (ShadowPtrXorMask)
    OffsetLong = IRB.CreateXor(OffsetLong, ShadowPtrXorMask);
  return OffsetLong;
}

Value *Taint::getShadowAddress(Value *Addr, IRBuilder<> &IRB) {
  Value *ShadowLong = getShadowOffset(Addr, IRB);
  if (ShadowPtrBase)
    ShadowLong = IRB.CreateAdd(ShadowLong, ShadowPtrBase);
  if (ShadowPtrMul)
    ShadowLong = IRB.CreateMul(ShadowLong, ShadowPtrMul);
  return IRB.CreateIntToPtr(ShadowLong, PrimitiveShadowPtrTy);
}

static inline bool isConstantOne(const Value *V) {
  if (const ConstantInt *CI = dyn_cast<ConstantInt>(V))
    return CI->isOne();
  return false;
}

Value *TaintFunction::combineBinaryOperatorShadows(BinaryOperator *BO,
                                                   uint8_t op) {
  if (BO->getType()->isIntegerTy(1) &&
      BO->getOpcode() == Instruction::Xor &&
      (isConstantOne(BO->getOperand(1)) ||
       isConstantOne(BO->getOperand(0)))) {
    op = 1; // __dfsan::Not
  }
  // else if (BinaryOperator::isNeg(BO))
  //   op = 2;
  Value *Shadow1 = getShadow(BO->getOperand(0));
  Value *Shadow2 = getShadow(BO->getOperand(1));
  Value *Shadow = combineShadows(Shadow1, Shadow2, op, BO);
  return Shadow;
}

// Widest operand the label format can describe.  op1 and op2 are 64 bits each,
// which is exactly what a concrete 128-bit operand needs; anything above this
// would require a side channel, and nothing observed needs one.
static const uint64_t kMaxOperandBits = 128;

Value *TaintFunction::combineShadows(Value *V1, Value *V2,
                                     uint16_t op,
                                     Instruction *Pos) {
  if (TT.isZeroShadow(V1) && TT.isZeroShadow(V2)) return V1;

  // filter types
  Type *Ty = Pos->getOperand(0)->getType();
  if (Ty->isFloatingPointTy()) {
    // check for FP
    if (!ClTraceFP)
      return TT.getZeroShadow(Pos);
    // only half/float/double have a bitcast to an integer that fits the 64-bit
    // union below.  Anything wider (x86_fp80, fp128, ppc_fp128) would fall
    // through to the CreateZExtOrTrunc and emit `trunc x86_fp80 to i64`, which
    // the backend cannot select ("Cannot select: i64 = truncate (f80 load)").
    // Drop the shadow instead: imprecise, but it compiles and stays sound.
    //
    // x86_fp80 is now allowed for COMPARISONS, and the selection problem above
    // is avoided rather than hit: the operand is bitcast to i80 FIRST, and
    // `trunc i80 to i64` (plus the lshr for the high half) selects fine.  What
    // could not be selected was the FP-to-integer truncate, not the width.
    //
    // Only comparisons, deliberately.  A compare is self-contained -- both
    // operands are fp80, the result is an i1, and the whole thing is described
    // by the two op slots.  A conversion is not: `fpext double to x86_fp80`
    // already slips past this filter (it looks at operand 0, which is the
    // double) and `fptrunc x86_fp80 to double` would produce a 64-bit node
    // whose recorded operand value is an fp80 significand.  Both are declines
    // below rather than nodes with a plausible wrong value in them.
    //
    // fp80 stays declined for z3 and jigsaw, which is a format problem and not
    // a width one: fp80 has an EXPLICIT integer significand bit, so z3's
    // (_ FloatingPoint 15 64) is a different, 79-bit sort and reinterpreting
    // the bits into it would be wrong, while jigsaw carries every FP value as a
    // double in a uint64 arg slot.  i2s is the exception because it evaluates
    // in C++ on x86, where `long double` IS x86_fp80: it can decode, compare,
    // step and re-encode on the hardware that produced the value, with no model
    // in between.  See solve_fcmp80 in solvers/i2s-solver.cpp.
    //
    // fp128 and ppc_fp128 remain declined outright: no host type evaluates them
    // natively the way `long double` does fp80, so there is no backend that
    // could take them even if they were transported.
    if (!Ty->isHalfTy() && !Ty->isFloatTy() && !Ty->isDoubleTy() &&
        !(Ty->isX86_FP80Ty() && isa<CmpInst>(Pos)))
      return TT.getZeroShadow(Pos);
  } else if (Ty->isVectorTy()) {
    // FIXME: vector type
    return TT.getZeroShadow(Pos);
  } else if (!Ty->isIntegerTy() && !Ty->isPointerTy()) {
    // not FP and not vector and not int and not ptr?
    errs() << "Unknown type: " << *Pos << "\n";
    return TT.getZeroShadow(Pos);
  }

  // filter size
  auto &DL = Pos->getModule()->getDataLayout();
  uint64_t size = DL.getTypeSizeInBits(Pos->getType());
  // a comparison records the width of its operands, not of its i1 result, so
  // the size filter below has to look at the operands too -- otherwise a
  // 128-bit icmp sails through (result is i1) and its operands get truncated
  // to 64 bits while the label still claims size = 128, which is a wrong
  // formula the solver will happily model
  if (CmpInst *CI = dyn_cast<CmpInst>(Pos))
    size = DL.getTypeSizeInBits(CI->getOperand(0)->getType());
  // FIXME: do not handle type larger than 64-bit
  //
  // Relaxed to 128 so __int128 arithmetic is tracked -- the shape at the core of
  // every modern 64-bit hash (`(unsigned __int128)a * b >> 64`) and of
  // __builtin_mul_overflow on uint64_t.  128 is a hard ceiling rather than an
  // arbitrary one: a concrete operand has to travel in the label's op1 and op2
  // slots, which are exactly 64 bits each (see WideConst in dfsan.h), so
  // _BitInt(256) and friends still decline here.  Floating point never reaches
  // this point above 64 bits -- the half/float/double filter above already
  // rejects x86_fp80/fp128/ppc_fp128, which need a format conversion rather than
  // a wider integer, not least because x86_fp80 has an explicit significand bit
  // that z3's (_ FloatingPoint 15 64) does not.
  if (size > kMaxOperandBits) return TT.getZeroShadow(Pos);

  IRBuilder<> IRB(Pos);
  // x86_fp80's integer twin.  Note this is i80 and not i128: the type is 80
  // bits wide even though it occupies 16 bytes of storage, and bitcast demands
  // the exact primitive size.
  Type *Int80Ty = IntegerType::get(Pos->getContext(), 80);
  if (CmpInst *CI = dyn_cast<CmpInst>(Pos)) { // for both icmp and fcmp
    // op should be predicate
    op |= (CI->getPredicate() << 8);
  }
  Value *Op = ConstantInt::get(TT.Int16Ty, op);
  Value *Size = ConstantInt::get(TT.Int16Ty, size);
  Value *Op1 = Pos->getOperand(0);
  Ty = Op1->getType();
  // bitcast to integer before extending
  if (Ty->isHalfTy())
    Op1 = IRB.CreateBitCast(Op1, TT.Int16Ty);
  else if (Ty->isFloatTy())
    Op1 = IRB.CreateBitCast(Op1, TT.Int32Ty);
  else if (Ty->isDoubleTy())
    Op1 = IRB.CreateBitCast(Op1, TT.Int64Ty);
  else if (Ty->isX86_FP80Ty())
    // the trunc to 64 below keeps the low half, which for an fp80 is the whole
    // significand -- the high 16 bits are sign and exponent, and they travel in
    // the WideConst produced by the size > 64 path
    Op1 = IRB.CreateBitCast(Op1, Int80Ty);
  else if (Ty->isPointerTy())
    Op1 = IRB.CreatePtrToInt(Op1, TT.Int64Ty);
  Op1 = IRB.CreateZExtOrTrunc(Op1, TT.Int64Ty);
  Value *Op2 = ConstantInt::get(TT.Int64Ty, 0);
  if (Pos->getNumOperands() > 1) {
    Op2 = Pos->getOperand(1);
    Ty = Op2->getType();
    // bitcast to integer before extending
    if (Ty->isHalfTy())
      Op2 = IRB.CreateBitCast(Op2, TT.Int16Ty);
    else if (Ty->isFloatTy())
      Op2 = IRB.CreateBitCast(Op2, TT.Int32Ty);
    else if (Ty->isDoubleTy())
      Op2 = IRB.CreateBitCast(Op2, TT.Int64Ty);
    else if (Ty->isX86_FP80Ty())
      Op2 = IRB.CreateBitCast(Op2, Int80Ty);
    else if (Ty->isPointerTy())
      Op2 = IRB.CreatePtrToInt(Op2, TT.Int64Ty);
    Op2 = IRB.CreateZExtOrTrunc(Op2, TT.Int64Ty);
  }
  // A concrete operand of a wide operation cannot ride in the Op1/Op2 slots
  // above -- they are 64 bits and the extends just truncated into them, so the
  // runtime would embed a wrong constant in the AST without any way to tell.
  // Such an operand needs a real label instead (see WideConst in dfsan.h), and
  // that applies to small values too: `(unsigned __int128)x >> 64` has to go
  // through it, because what a zero shadow cannot express is not "large" but
  // "exact".
  //
  // Which operands are concrete is a *runtime* question, not one that can be
  // settled here.  It is tempting to look for a ConstantInt and give up on
  // anything else, but at -O0 clang keeps even a literal `__int128` in an
  // alloca, so `a == 0x0123...` reaches the icmp as `load i128` with no
  // constant in sight -- the shape would have worked only in optimized builds,
  // which is exactly backwards.  So hand each operand's full value to
  // __taint_get_wide, which can see the label: symbolic keeps its label,
  // concrete becomes a WideConst leaf.  Normalizing the operands rather than
  // replacing the union call is what keeps this to one extra entry point -- the
  // union below is the same one every other width uses, and only the operands
  // it is given have changed.  Both sides tainted costs two calls that return
  // their argument, and no union-table entry.
  if (size > 64) {
    // Only integers and fp80 comparison operands should get this far -- the FP
    // filter above rejects every other float format wider than double, and a
    // pointer is 64 bits -- but `fpext double to x86_fp80` slips past it,
    // because that filter looks at operand 0 and operand 0 is the double.  It
    // arrives here at size 80 with no fp80 operand to bitcast, so decline it the
    // way the old constant-only path did (by finding no ConstantInt) rather than
    // asserting in CreateZExtOrTrunc.
    //
    // An fp80 operand is admitted because it does have a high half to extract,
    // once bitcast to i80: the top 16 bits are its sign and exponent, and they
    // are exactly what would be lost if only the 64-bit significand travelled.
    for (unsigned i = 0, n = Pos->getNumOperands(); i < n && i < 2; ++i) {
      Type *OpTy = Pos->getOperand(i)->getType();
      if (!OpTy->isIntegerTy() && !OpTy->isX86_FP80Ty())
        return TT.getZeroShadow(Pos);
    }
    Type *Int128Ty = IntegerType::get(Pos->getContext(), 128);
    // the high half of an operand narrower than the operation (`zext i64 to
    // i128`) is zero, which the zext produces without a special case
    auto getWide = [&](Value *Label, Value *Lo, Value *Operand) -> Value * {
      if (Operand->getType()->isX86_FP80Ty())
        Operand = IRB.CreateBitCast(Operand, Int80Ty);
      Value *W = IRB.CreateZExtOrTrunc(Operand, Int128Ty);
      Value *Hi = IRB.CreateTrunc(IRB.CreateLShr(W, 64), TT.Int64Ty);
      CallInst *C = IRB.CreateCall(TT.TaintGetWideFn, {Label, Lo, Hi, Size});
      C->addRetAttr(Attribute::ZExt);
      C->addParamAttr(0, Attribute::ZExt);
      return C;
    };
    V1 = getWide(V1, Op1, Pos->getOperand(0));
    // Only promote a slot that actually holds an operand value.  This is why
    // the getter is per-operand: the caller knows, whereas a wide union would
    // have to re-derive it from the opcode (a Load keeps a byte count in op2,
    // an Extract a bit offset, a unary op nothing at all).
    if (Pos->getNumOperands() > 1)
      V2 = getWide(V2, Op2, Pos->getOperand(1));
  }
  CallInst *Call = IRB.CreateCall(TT.TaintUnionFn, {V1, V2, Op, Size, Op1, Op2});
  Call->addRetAttr(Attribute::ZExt);
  Call->addParamAttr(0, Attribute::ZExt);
  Call->addParamAttr(1, Attribute::ZExt);
  return Call;
}

Value *TaintFunction::combineCastInstShadows(CastInst *CI,
                                             uint8_t op) {
  Value *Shadow1 = getShadow(CI->getOperand(0));
  Value *Shadow2 = TT.getZeroShadow(CI);
  if (op == Instruction::BitCast) {
    // BitCast is a no-op, so we can just return the shadow of the operand.
    return Shadow1;
  } else if (op == Instruction::AddrSpaceCast) {
    // AddrSpaceCast is also a no-op for taint, so we can just return the shadow
    // of the operand.
    return TT.ZeroPrimitiveShadow;
  } else {
    return combineShadows(Shadow1, Shadow2, op, CI);
  }
}

Value *TaintFunction::combineCmpInstShadows(CmpInst *CI,
                                            uint8_t op) {
  Value *Shadow1 = getShadow(CI->getOperand(0));
  Value *Shadow2 = getShadow(CI->getOperand(1));
  Value *Shadow = combineShadows(Shadow1, Shadow2, op, CI);
  return Shadow;
}

Align TaintFunction::getShadowAlign(Align InstAlignment) {
  const Align Alignment = ClPreserveAlignment ? InstAlignment : Align(1);
  return Align(Alignment.value() * TT.ShadowWidthBytes);
}

void TaintFunction::checkBounds(Value *Ptr, Value* Size, Instruction *Pos) {
  IRBuilder<> IRB(Pos);
  // another place to check for global variable as the ptr
  Value *PtrShadow = nullptr;
  Value *PtrBase = getUnderlyingObject(Ptr);
  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Ptr->stripPointerCasts())) {
    PtrShadow = getShadowForGlobal(GV, IRB);
  } else if (GlobalVariable *GV = dyn_cast<GlobalVariable>(PtrBase)) {
    PtrShadow = getShadowForGlobal(GV, IRB);
  } else {
    PtrShadow = getShadow(Ptr);
  }
  Value *SizeShadow = getShadow(Size);
  // ptr shadow only exists for array and heap object
  if (!TT.isZeroShadow(PtrShadow)) {
    Value *Addr = IRB.CreatePtrToInt(Ptr, TT.Int64Ty);
    Value *Size64 = IRB.CreateZExtOrTrunc(Size, TT.Int64Ty);
    IRB.CreateCall(TT.TaintCheckBoundsFn, {PtrShadow, Addr, SizeShadow, Size64});
  }
}

void TaintFunction::solveBounds(Value *Ptr, Value* Size, Instruction *Pos) {
  Value *SizeShadow = getShadow(Size);
  if (TT.isZeroShadow(SizeShadow)) {
    // If the size is not symbolic, we cannot check if it can go out of bounds.
    return;
  }
  IRBuilder<> IRB(Pos);
  // another place to check for global variable as the ptr
  Value *PtrShadow = nullptr;
  Value *PtrBase = getUnderlyingObject(Ptr);
  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Ptr->stripPointerCasts())) {
    PtrShadow = getShadowForGlobal(GV, IRB);
  } else if (GlobalVariable *GV = dyn_cast<GlobalVariable>(PtrBase)) {
    PtrShadow = getShadowForGlobal(GV, IRB);
  } else {
    PtrShadow = getShadow(Ptr);
  }
  Value *Addr = IRB.CreatePtrToInt(Ptr, TT.Int64Ty);
  Value *Size64 = IRB.CreateZExtOrTrunc(Size, TT.Int64Ty);
  ConstantInt *CID = ConstantInt::get(TT.Int32Ty, TT.getInstructionId(Pos));
  IRB.CreateCall(TT.TaintSolveSizeFn,
      {PtrShadow, Addr, SizeShadow, Size64, CID});
}

// Collect all SCEVUnknown values from a SCEV expression.
static void collectSCEVUnknowns(const SCEV *S,
                                SmallVectorImpl<Value *> &Unknowns) {
  if (auto *U = dyn_cast<SCEVUnknown>(S)) {
    Unknowns.push_back(U->getValue());
  } else if (auto *NAry = dyn_cast<SCEVNAryExpr>(S)) {
    for (const SCEV *Op : NAry->operands())
      collectSCEVUnknowns(Op, Unknowns);
  } else if (auto *Cast = dyn_cast<SCEVCastExpr>(S)) {
    collectSCEVUnknowns(Cast->getOperand(), Unknowns);
  } else if (auto *UDiv = dyn_cast<SCEVUDivExpr>(S)) {
    collectSCEVUnknowns(UDiv->getLHS(), Unknowns);
    collectSCEVUnknowns(UDiv->getRHS(), Unknowns);
  }
  // SCEVConstant has no unknowns
}

// Hoist __taint_check_bounds / __taint_solve_bounds calls out of loops using
// SCEV analysis.
// For each loop with a computable backedge-taken count, find bounds checks
// where the pointer shadow (bounds label) is loop-invariant and the address
// follows an affine recurrence {start, +, stride}. Replace N per-iteration
// checks with a single summary check in the preheader covering the full
// access range [start, start + BTC * stride + elem_size).
// When the summarized range is symbolic, also emit a __taint_solve_size call
// so the solver can find loop bounds that cause OOB.
void TaintFunction::hoistBoundsChecks() {
  // Recalculate analyses after TaintVisitor may have split blocks
  DT.recalculate(*F);
  delete LI;
  LI = new LoopInfo(DT);

  if (LI->empty()) return;

  Module *M = F->getParent();
  TargetLibraryInfoImpl TLII(Triple(M->getTargetTriple()));
  TargetLibraryInfo TLI(TLII, F);
  AssumptionCache AC(*F);
  ScalarEvolution SE(*F, TLI, AC, DT, *LI);

  // Process innermost loops first so hoisted checks can be further
  // hoisted when processing outer loops
  SmallVector<Loop *, 8> Loops(LI->getLoopsInPreorder());

  for (Loop *L : reverse(Loops)) {
    BasicBlock *Preheader = L->getLoopPreheader();
    if (!Preheader) {
      // No canonical preheader (predecessor has multiple successors).
      // Split the edge to create one.
      BasicBlock *Pred = L->getLoopPredecessor();
      if (!Pred) continue;
      Preheader = SplitEdge(Pred, L->getHeader(), &DT, LI);
      if (!Preheader) continue;
    }

    const SCEV *BTC = SE.getBackedgeTakenCount(L);
    if (isa<SCEVCouldNotCompute>(BTC)) {
      struct UCSanCallSummary {
        CallInst *CI;
        symsan::ucsan::MemoryAccessSummary Summary;
      };
      SmallVector<UCSanCallSummary, 8> UCSanCallSummaries;
      if (ClWithUCSan) {
        for (BasicBlock *BB : L->blocks()) {
          if (LI->getLoopFor(BB) != L) continue;
          for (Instruction &I : *BB) {
            auto *CI = dyn_cast<CallInst>(&I);
            if (!CI) continue;
            Function *Callee = CI->getCalledFunction();
            if (!Callee) continue;
            MDNode *Summaries = symsan::ucsan::getMemoryAccessSummaries(*Callee);
            if (!Summaries) continue;
            for (const MDOperand &Op : Summaries->operands()) {
              auto *SummaryNode = dyn_cast_or_null<MDNode>(Op.get());
              symsan::ucsan::MemoryAccessSummary Summary;
              if (!symsan::ucsan::parseMemoryAccessSummary(SummaryNode,
                                                           Summary))
                continue;
              if (!Summary.IsWrite || Summary.AccessSize == 0 ||
                  Summary.ArgNo >= CI->arg_size())
                continue;
              UCSanCallSummaries.push_back({CI, Summary});
            }
          }
        }
      }

      auto GetSinglePredGuardCount = [&](CallInst *CI) -> Value * {
        BasicBlock *BB = CI->getParent();
        if (std::distance(pred_begin(BB), pred_end(BB)) != 1)
          return nullptr;
        BasicBlock *Pred = *pred_begin(BB);
        auto *BI = dyn_cast<BranchInst>(Pred->getTerminator());
        if (!BI || !BI->isConditional())
          return nullptr;
        if (BI->getSuccessor(0) != BB && BI->getSuccessor(1) != BB)
          return nullptr;
        auto *Cmp = dyn_cast<ICmpInst>(BI->getCondition());
        if (!Cmp)
          return nullptr;

        Value *LHS = Cmp->getOperand(0);
        Value *RHS = Cmp->getOperand(1);
        if (auto *C = dyn_cast<ConstantInt>(RHS)) {
          if (C->isZero())
            return LHS;
        }
        if (auto *C = dyn_cast<ConstantInt>(LHS)) {
          if (C->isZero())
            return RHS;
        }
        return nullptr;
      };

      bool EmittedUnknownTripSummary = false;
      for (const UCSanCallSummary &CallSummary : UCSanCallSummaries) {
        CallInst *CI = CallSummary.CI;
        const auto &Summary = CallSummary.Summary;
        Value *Arg = CI->getArgOperand(Summary.ArgNo)->stripPointerCasts();
        if (!L->isLoopInvariant(Arg) || !isa<AllocaInst>(Arg))
          continue;

        Value *Count = GetSinglePredGuardCount(CI);
        if (!Count)
          continue;

        IRBuilder<> IRB(CI);
        Type *I8PtrTy = PointerType::getUnqual(F->getContext());
        Type *I8PtrPtrTy = PointerType::getUnqual(I8PtrTy);
        Value *ArgI8 = IRB.CreateBitCast(Arg, I8PtrTy);
        Value *FieldAddr = ArgI8;
        if (Summary.FieldOffset != 0) {
          FieldAddr = IRB.CreateGEP(
              IRB.getInt8Ty(), ArgI8,
              ConstantInt::get(TT.Int64Ty, Summary.FieldOffset, true));
        }
        Value *FieldAddrPtr = IRB.CreateBitCast(FieldAddr, I8PtrPtrTy);
        Value *AddrLabel = loadShadow(I8PtrTy, FieldAddrPtr,
                                      M->getDataLayout().getTypeStoreSize(I8PtrTy),
                                      Align(1), CI);
        Value *LoadedPtr = IRB.CreateLoad(I8PtrTy, FieldAddrPtr);
        Value *StartVal = IRB.CreatePtrToInt(LoadedPtr, TT.Int64Ty);
        Value *Count64 = IRB.CreateZExtOrTrunc(Count, TT.Int64Ty);
        Value *TotalVal = Count64;
        if (Summary.AccessSize != 1)
          TotalVal = IRB.CreateMul(
              Count64, ConstantInt::get(TT.Int64Ty, Summary.AccessSize));
        Value *SizeShadow = getShadow(Count);

        // Soft solve_size hint only: the guard value is a heuristic for the
        // write count, not a proven bound, so a hard check_bounds here would
        // risk spurious OOB aborts.
        ConstantInt *CID = ConstantInt::get(TT.Int32Ty,
            TT.getInstructionId(CI));
        IRB.CreateCall(TT.TaintSolveSizeFn,
                       {AddrLabel, StartVal, SizeShadow, TotalVal, CID});
        EmittedUnknownTripSummary = true;
      }

      if (EmittedUnknownTripSummary)
        continue;

      // SCEV can't compute trip count — check for strlen-bounded loop:
      //   while (ptr[i] != 0) { ... __taint_check_bounds(...) ... }
      // Detect: loop exit is (icmp ne (load i8 (gep i8* base, iv)), 0)
      BasicBlock *Header = L->getHeader();
      BranchInst *HeaderBr = dyn_cast<BranchInst>(Header->getTerminator());
      if (!HeaderBr || !HeaderBr->isConditional()) continue;

      ICmpInst *Cmp = dyn_cast<ICmpInst>(HeaderBr->getCondition());
      if (!Cmp) continue;

      // Match: icmp ne i8 %val, 0  or  icmp eq i8 %val, 0
      Value *LoadedVal = nullptr;
      if (Cmp->getPredicate() == ICmpInst::ICMP_NE &&
          isa<ConstantInt>(Cmp->getOperand(1)) &&
          cast<ConstantInt>(Cmp->getOperand(1))->isZero())
        LoadedVal = Cmp->getOperand(0);
      else if (Cmp->getPredicate() == ICmpInst::ICMP_EQ &&
               isa<ConstantInt>(Cmp->getOperand(1)) &&
               cast<ConstantInt>(Cmp->getOperand(1))->isZero())
        LoadedVal = Cmp->getOperand(0);
      else
        continue;

      // Strip zext/trunc to find the load
      if (auto *ZE = dyn_cast<ZExtInst>(LoadedVal))
        LoadedVal = ZE->getOperand(0);
      if (auto *TR = dyn_cast<TruncInst>(LoadedVal))
        LoadedVal = TR->getOperand(0);

      // Find the base string pointer from the loop header.
      Value *StrBase = nullptr;

      CallInst *StrUCChk = nullptr;
      if (ClWithUCSan) {
        // TaintPass runs after UCSanPass, so the load goes through
        // ucsan_check_pointer. Scan the header
        // for a GEP matching: gep i8, base, iv
        for (Instruction &I : *Header) {
          auto *GEP = dyn_cast<GetElementPtrInst>(&I);
          if (!GEP || GEP->getNumIndices() != 1) continue;
          if (!GEP->getSourceElementType()->isIntegerTy(8)) continue;
          if (!L->isLoopInvariant(GEP->getPointerOperand())) continue;
          Value *Idx = GEP->getOperand(1);
          if (auto *PN = dyn_cast<PHINode>(Idx)) {
            if (L->contains(PN->getParent())) {
              StrBase = GEP->getPointerOperand();
              break;
            }
          }
        }
        // Find the ucsan_check_pointer call on StrBase's GEP in the loop
        if (StrBase) {
          for (BasicBlock *BB : L->blocks()) {
            if (StrUCChk) break;
            for (Instruction &I : *BB) {
              auto *CI = dyn_cast<CallInst>(&I);
              if (!CI) continue;
              Function *Fn = CI->getCalledFunction();
              if (Fn && Fn->getName() == "ucsan_check_pointer") {
                Value *Ptr = CI->getArgOperand(0);
                if (auto *GEP = dyn_cast<GetElementPtrInst>(Ptr)) {
                  if (GEP->getPointerOperand() == StrBase) {
                    StrUCChk = CI;
                    break;
                  }
                }
              }
            }
          }
        }
      } else {
        // Without UCSan, the load directly uses the GEP
        if (auto *ZE = dyn_cast<ZExtInst>(LoadedVal))
          LoadedVal = ZE->getOperand(0);
        if (auto *TR = dyn_cast<TruncInst>(LoadedVal))
          LoadedVal = TR->getOperand(0);
        auto *LI_load = dyn_cast<LoadInst>(LoadedVal);
        if (!LI_load || !LI_load->getType()->isIntegerTy(8))
          continue;
        auto *GEP = dyn_cast<GetElementPtrInst>(LI_load->getPointerOperand());
        if (!GEP || GEP->getNumIndices() != 1) continue;
        if (!L->isLoopInvariant(GEP->getPointerOperand())) continue;
        StrBase = GEP->getPointerOperand();
      }
      if (!StrBase) continue;

      // Collect __taint_check_bounds calls in this loop
      SmallVector<CallInst *, 8> BoundsChecks;
      for (BasicBlock *BB : L->blocks()) {
        if (LI->getLoopFor(BB) != L) continue;
        for (Instruction &I : *BB) {
          auto *CI = dyn_cast<CallInst>(&I);
          if (!CI) continue;
          Function *Callee = CI->getCalledFunction();
          if (Callee && Callee->getName() == "__taint_check_bounds")
            BoundsChecks.push_back(CI);
        }
      }
      if (BoundsChecks.empty()) continue;

      // For each bounds check, extract the buffer pointer and emit
      // __taint_solve_str_bounds(str_ptr, buf_label, buf_ptr, step)
      Instruction *InsertPt = Preheader->getTerminator();
      IRBuilder<> IRB(InsertPt);
      Value *StrPtr = IRB.CreateBitCast(StrBase, PointerType::getUnqual(*TT.Ctx));
      if (StrUCChk) {
        // Hoist ucsan_check_pointer with deref=1 so the string object
        // is materialized before __taint_solve_str_bounds dereferences it
        Value *UCLabel = StrUCChk->getArgOperand(1);
        if (!L->isLoopInvariant(UCLabel))
          UCLabel = ConstantInt::get(UCLabel->getType(), 0);
        StrPtr = IRB.CreateCall(StrUCChk->getCalledFunction(),
            {StrPtr, UCLabel, StrUCChk->getArgOperand(2),
             ConstantInt::getTrue(*TT.Ctx), StrUCChk->getArgOperand(4)});
      }

      DenseSet<Value *> EmittedBufs;
      for (CallInst *CI : BoundsChecks) {
        Value *AddrLabel = CI->getArgOperand(0);  // buf shadow (bounds info)
        Value *Addr = CI->getArgOperand(1);       // buf concrete address
        Value *Size = CI->getArgOperand(3);       // access size (step)

        // Resolve loop-variant AddrLabel to loop-invariant base
        if (!L->isLoopInvariant(AddrLabel)) {
          Value *Resolved = AddrLabel;
          bool Found = false;
          for (int Depth = 0; Depth < 4 && !Found; ++Depth) {
            if (L->isLoopInvariant(Resolved)) {
              Found = true;
            } else if (auto *PN = dyn_cast<PHINode>(Resolved)) {
              for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i) {
                if (!L->contains(PN->getIncomingBlock(i))) {
                  Resolved = PN->getIncomingValue(i);
                  break;
                }
              }
            } else if (auto *GepCall = dyn_cast<CallInst>(Resolved)) {
              Function *GepFn = GepCall->getCalledFunction();
              if (GepFn && GepFn->getName() == "__taint_gep_offset")
                Resolved = GepCall->getArgOperand(0);
              else
                break;
            } else {
              break;
            }
          }
          if (!Found && L->isLoopInvariant(Resolved))
            Found = true;
          if (!Found) continue;
          AddrLabel = Resolved;
        }

        // One call per unique buffer
        if (!EmittedBufs.insert(AddrLabel).second) continue;

        // Resolve buf_ptr to loop-invariant start address
        Value *BufPtr = Addr;
        if (!L->isLoopInvariant(BufPtr)) {
          // Try to find the base address from SCEV or PHI
          if (auto *PTI = dyn_cast<PtrToIntOperator>(BufPtr)) {
            Value *PtrOp = PTI->getOperand(0);
            if (ClWithUCSan) {
              if (auto *ChkCall = dyn_cast<CallInst>(PtrOp)) {
                Function *ChkFn = ChkCall->getCalledFunction();
                if (ChkFn && ChkFn->getName() == "ucsan_check_pointer")
                  PtrOp = ChkCall->getArgOperand(0);
              }
            }
            if (auto *BufGEP = dyn_cast<GetElementPtrInst>(PtrOp)) {
              BufPtr = IRB.CreatePtrToInt(BufGEP->getPointerOperand(), TT.Int64Ty);
            }
          }
          if (!L->isLoopInvariant(BufPtr)) continue;
        }

        auto *SizeC = dyn_cast<ConstantInt>(Size);
        uint64_t Step = SizeC ? SizeC->getZExtValue() : 1;

        IRB.CreateCall(TT.TaintSolveStrBoundsFn,
                       {StrPtr, AddrLabel,
                        BufPtr, ConstantInt::get(TT.Int64Ty, Step)});
      }

      // Remove per-iteration bounds checks
      for (CallInst *CI : BoundsChecks)
        CI->eraseFromParent();

      continue;
    }

    // Collect bounds calls at this loop level (skip subloops).
    SmallVector<CallInst *, 8> BoundsChecks;
    SmallVector<CallInst *, 8> SolveBoundsCalls;
    SmallVector<CallInst *, 8> UCSanPointerChecks;
    struct UCSanCallSummary {
      CallInst *CI;
      symsan::ucsan::MemoryAccessSummary Summary;
    };
    SmallVector<UCSanCallSummary, 8> UCSanCallSummaries;
    for (BasicBlock *BB : L->blocks()) {
      if (LI->getLoopFor(BB) != L) continue;
      for (Instruction &I : *BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI) continue;
        Function *Callee = CI->getCalledFunction();
        if (!Callee) continue;
        if (Callee->getName() == "__taint_check_bounds")
          BoundsChecks.push_back(CI);
        else if (Callee->getName() == "__taint_solve_bounds")
          SolveBoundsCalls.push_back(CI);
        else if (ClWithUCSan && Callee->getName() == "ucsan_check_pointer")
          UCSanPointerChecks.push_back(CI);
        if (ClWithUCSan) {
          if (MDNode *Summaries =
                  symsan::ucsan::getMemoryAccessSummaries(*Callee)) {
            for (const MDOperand &Op : Summaries->operands()) {
              auto *SummaryNode = dyn_cast_or_null<MDNode>(Op.get());
              symsan::ucsan::MemoryAccessSummary Summary;
              if (!symsan::ucsan::parseMemoryAccessSummary(SummaryNode,
                                                           Summary))
                continue;
              if (!Summary.IsWrite || Summary.AccessSize == 0 ||
                  Summary.ArgNo >= CI->arg_size())
                continue;
              UCSanCallSummaries.push_back({CI, Summary});
            }
          }
        }
      }
    }
    if (BoundsChecks.empty() && SolveBoundsCalls.empty() &&
        UCSanPointerChecks.empty() && UCSanCallSummaries.empty())
      continue;

    auto ResolveLoopInvariantLabel = [&](Value *Label) -> Value * {
      if (L->isLoopInvariant(Label))
        return Label;

      Value *Resolved = Label;
      bool Found = false;
      for (int Depth = 0; Depth < 4 && !Found; ++Depth) {
        if (L->isLoopInvariant(Resolved)) {
          Found = true;
        } else if (auto *PN = dyn_cast<PHINode>(Resolved)) {
          for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i) {
            if (!L->contains(PN->getIncomingBlock(i))) {
              Resolved = PN->getIncomingValue(i);
              break;
            }
          }
        } else if (auto *GepCall = dyn_cast<CallInst>(Resolved)) {
          Function *GepFn = GepCall->getCalledFunction();
          if (GepFn && GepFn->getName() == "__taint_gep_offset")
            Resolved = GepCall->getArgOperand(0);
          else
            break;
        } else {
          break;
        }
      }
      if (!Found && L->isLoopInvariant(Resolved))
        Found = true;
      return Found ? Resolved : nullptr;
    };

    // Group hoistable checks by AddrLabel (ptr bounds shadow).
    // For each group, compute the merged range covering all accesses,
    // emit one summary check + one solve_size call.
    struct HoistCandidate {
      const SCEVAddRecExpr *AR;
      uint64_t ElemSize;
      CallInst *CI;
    };
    // ptrtoint instructions materialized only to query SCEV; erased at the end
    // of this loop if they end up unused.
    SmallVector<Instruction *, 8> SCEVTemps;

    DenseMap<Value *, SmallVector<HoistCandidate, 4>> Groups;
    for (CallInst *CI : BoundsChecks) {
      Value *AddrLabel = CI->getArgOperand(0);  // ptr bounds shadow
      Value *Addr = CI->getArgOperand(1);       // concrete address
      Value *Size = CI->getArgOperand(3);       // access size

      // AddrLabel may be loop-variant due to:
      // 1. __taint_gep_offset(base_shadow, gep, base) called per-iteration
      // 2. PHI nodes for pointer-incrementing loops (buf++)
      // Walk through these to find the loop-invariant base allocation shadow.
      if (!L->isLoopInvariant(AddrLabel)) {
        Value *Resolved = ResolveLoopInvariantLabel(AddrLabel);
        if (!Resolved) continue;
        AddrLabel = Resolved;
      }

      auto *SizeC = dyn_cast<ConstantInt>(Size);
      if (!SizeC) continue;

      // With UCSan, Addr is ptrtoint(ucsan_check_pointer(orig_ptr, ...)).
      // ucsan_check_pointer is opaque to SCEV; use the original pointer.
      Value *AddrForSCEV = Addr;
      if (ClWithUCSan) {
        if (auto *PTI = dyn_cast<PtrToIntOperator>(Addr)) {
          if (auto *ChkCall = dyn_cast<CallInst>(PTI->getPointerOperand())) {
            Function *ChkFn = ChkCall->getCalledFunction();
            if (ChkFn && ChkFn->getName() == "ucsan_check_pointer") {
              IRBuilder<> IRB(CI);
              AddrForSCEV = IRB.CreatePtrToInt(ChkCall->getArgOperand(0), TT.Int64Ty);
              SCEVTemps.push_back(cast<Instruction>(AddrForSCEV));
            }
          }
        }
      }

      const SCEV *AddrSCEV = SE.getSCEV(AddrForSCEV);
      auto *AR = dyn_cast<SCEVAddRecExpr>(AddrSCEV);
      if (!AR || AR->getLoop() != L) continue;

      const SCEV *Step = AR->getStepRecurrence(SE);
      auto *StepC = dyn_cast<SCEVConstant>(Step);
      if (!StepC) continue;
      int64_t StepVal = StepC->getAPInt().getSExtValue();
      if (StepVal <= 0) continue;

      Groups[AddrLabel].push_back({AR, SizeC->getZExtValue(), CI});
    }

    // UCSan may guard the concrete access directly with ucsan_check_pointer
    // without a matching __taint_check_bounds on the checked pointer. Treat
    // affine checked pointers as solve-hint candidates, but keep the original
    // runtime checks in place.
    for (CallInst *CI : UCSanPointerChecks) {
      if (CI->arg_size() < 5)
        continue;

      auto *SizeC = dyn_cast<ConstantInt>(CI->getArgOperand(2));
      auto *DerefC = dyn_cast<ConstantInt>(CI->getArgOperand(3));
      if (!SizeC || !DerefC || !DerefC->isOne())
        continue;

      Value *AddrLabel = getShadow(CI);
      if (TT.isZeroShadow(AddrLabel))
        AddrLabel = getShadow(CI->getArgOperand(0));
      if (TT.isZeroShadow(AddrLabel))
        continue;

      AddrLabel = ResolveLoopInvariantLabel(AddrLabel);
      if (!AddrLabel)
        continue;

      IRBuilder<> LocalIRB(CI);
      Value *PtrAsInt =
          LocalIRB.CreatePtrToInt(CI->getArgOperand(0), TT.Int64Ty);
      SCEVTemps.push_back(cast<Instruction>(PtrAsInt));
      const SCEV *AddrSCEV = SE.getSCEV(PtrAsInt);
      auto *AR = dyn_cast<SCEVAddRecExpr>(AddrSCEV);
      if (!AR || AR->getLoop() != L)
        continue;

      const SCEV *Step = AR->getStepRecurrence(SE);
      auto *StepC = dyn_cast<SCEVConstant>(Step);
      if (!StepC || StepC->getAPInt().getSExtValue() <= 0)
        continue;

      Groups[AddrLabel].push_back({AR, SizeC->getZExtValue(), CI});
    }

    // The backedge-taken count is typed by the loop's induction variable,
    // which need not be as wide as the address recurrence: an i32 IV walking
    // an i64 address is common once inlining exposes the loop (it shows up at
    // -O2, and after LTO even in code that was fine per-TU). SCEV requires
    // both operands of getMulExpr/getAddExpr to have the same width, but that
    // check is an assert -- in a release LLVM it is compiled out, the
    // mixed-width SCEV is built anyway, and SCEVExpander later materializes
    // it as `shl i32 %btc, i64 2`, which fails the module verifier. Coerce
    // the count to the width we are about to combine it with.
    auto CountAs = [&](Type *Ty) {
      return SE.getTruncateOrZeroExtend(BTC, Ty);
    };

    SCEVExpander Expander(SE, M->getDataLayout(), "bounds.hoist");
    Instruction *InsertPt = Preheader->getTerminator();
    DenseSet<CallInst *> HoistedSolveBounds;

    for (auto &KV : Groups) {
      Value *AddrLabel = KV.first;
      auto &Candidates = KV.second;

      // Find the minimum start and maximum end across all accesses
      // to emit a single check covering the entire range.
      const SCEV *MinStart = Candidates[0].AR->getStart();
      const SCEV *MaxEnd = nullptr; // end = BTC * stride + elem_size
      CallInst *FirstCI = Candidates[0].CI;

      for (auto &C : Candidates) {
        const SCEV *Start = C.AR->getStart();
        const SCEV *Step = C.AR->getStepRecurrence(SE);
        // end of this access: start + BTC * stride + elem_size
        // Step is always integer-typed (only an add-rec's start may be a
        // pointer), so it is the right width to compute the extent in.
        const SCEV *End = SE.getAddExpr(
          Start,
          SE.getAddExpr(
            SE.getMulExpr(CountAs(Step->getType()), Step),
            SE.getConstant(Step->getType(), C.ElemSize)
          )
        );
        if (SE.isKnownPredicate(ICmpInst::ICMP_ULT, Start, MinStart))
          MinStart = Start;
        if (!MaxEnd || SE.isKnownPredicate(ICmpInst::ICMP_UGT, End, MaxEnd))
          MaxEnd = End;
      }

      // total = MaxEnd - MinStart
      const SCEV *TotalSCEV = SE.getMinusSCEV(MaxEnd, MinStart);

      Value *StartVal = Expander.expandCodeFor(MinStart, TT.Int64Ty, InsertPt);
      Value *TotalVal = Expander.expandCodeFor(TotalSCEV, TT.Int64Ty, InsertPt);

      // Emit one summary bounds check for the group
      IRBuilder<> IRB(InsertPt);
      IRB.CreateCall(TT.TaintCheckBoundsFn,
                     {AddrLabel, StartVal, TT.ZeroPrimitiveShadow, TotalVal});

      // If the summarized range is symbolic, emit one solve_size outside the
      // loop. Looking at TotalSCEV catches both symbolic trip counts and
      // symbolic extents folded into the address/range expression.
      SmallVector<Value *, 4> Unknowns;
      collectSCEVUnknowns(TotalSCEV, Unknowns);
      Value *SizeShadow = TT.ZeroPrimitiveShadow;
      for (Value *V : Unknowns) {
        Value *S = getShadow(V);
        if (!TT.isZeroShadow(S))
          SizeShadow = S;
      }
      if (!TT.isZeroShadow(SizeShadow)) {
        ConstantInt *CID = ConstantInt::get(TT.Int32Ty,
            TT.getInstructionId(FirstCI));
        IRB.CreateCall(TT.TaintSolveSizeFn,
                       {AddrLabel, StartVal, SizeShadow, TotalVal, CID});
      }

      // Remove original __taint_check_bounds checks, but do not remove
      // ucsan_check_pointer calls because they perform the runtime access
      // validation and may materialize under-constrained objects.
      for (auto &C : Candidates) {
        Function *Callee = C.CI->getCalledFunction();
        if (Callee && Callee->getName() == "__taint_check_bounds")
          C.CI->eraseFromParent();
      }
    }

    // UCSan callee summaries let us see stores hidden behind a call inside the
    // loop. For a summary "callee loads a pointer from arg+field_offset and
    // writes access_size bytes through it", emit a caller-side upper-bound
    // check from the loop preheader. This is intentionally conservative: it
    // only uses loop-invariant alloca-backed arguments so the inserted field
    // load is safe without adding new UCSan instrumentation.
    for (const UCSanCallSummary &CallSummary : UCSanCallSummaries) {
      CallInst *CI = CallSummary.CI;
      const auto &Summary = CallSummary.Summary;
      Value *Arg = CI->getArgOperand(Summary.ArgNo)->stripPointerCasts();
      if (!L->isLoopInvariant(Arg))
        continue;
      if (!isa<AllocaInst>(Arg))
        continue;

      // Widen before the +1 and the multiply, not after: the extent is about
      // to be expanded at i64, and a narrow induction variable would otherwise
      // have trip_count * access_size wrap before it is zero-extended.
      const SCEV *TripCount = SE.getAddExpr(
          CountAs(TT.Int64Ty), SE.getConstant(TT.Int64Ty, 1));
      const SCEV *TotalSCEV = SE.getMulExpr(
          TripCount, SE.getConstant(TT.Int64Ty, Summary.AccessSize));

      IRBuilder<> IRB(InsertPt);
      Type *I8PtrTy = PointerType::getUnqual(F->getContext());
      Type *I8PtrPtrTy = PointerType::getUnqual(I8PtrTy);
      Value *ArgI8 = IRB.CreateBitCast(Arg, I8PtrTy);
      Value *FieldAddr = ArgI8;
      if (Summary.FieldOffset != 0) {
        FieldAddr = IRB.CreateGEP(
            IRB.getInt8Ty(), ArgI8,
            ConstantInt::get(TT.Int64Ty, Summary.FieldOffset, true));
      }
      Value *FieldAddrPtr = IRB.CreateBitCast(FieldAddr, I8PtrPtrTy);
      Value *AddrLabel = loadShadow(I8PtrTy, FieldAddrPtr,
                                    M->getDataLayout().getTypeStoreSize(I8PtrTy),
                                    Align(1), InsertPt);
      Value *LoadedPtr = IRB.CreateLoad(I8PtrTy, FieldAddrPtr);
      Value *StartVal = IRB.CreatePtrToInt(LoadedPtr, TT.Int64Ty);
      Value *TotalVal = Expander.expandCodeFor(TotalSCEV, TT.Int64Ty, InsertPt);

      // Soft solve_size hint only. The summary records a fixed field offset and
      // access size with no per-iteration stride, so trip_count * access_size is
      // not a proven extent; a hard check_bounds here could abort spuriously.
      SmallVector<Value *, 4> Unknowns;
      collectSCEVUnknowns(TotalSCEV, Unknowns);
      Value *SizeShadow = TT.ZeroPrimitiveShadow;
      for (Value *V : Unknowns) {
        Value *S = getShadow(V);
        if (!TT.isZeroShadow(S))
          SizeShadow = S;
      }
      ConstantInt *CID = ConstantInt::get(TT.Int32Ty,
          TT.getInstructionId(CI));
      IRB.CreateCall(TT.TaintSolveSizeFn,
                     {AddrLabel, StartVal, SizeShadow, TotalVal, CID});
    }

    // Some accesses do not have a matching check_bounds call with an affine
    // address. With UCSan this can happen when the load pointer is the
    // ucsan_check_pointer result. Summarize solve_bounds directly from its
    // base pointer and GEP index.
    struct SolveCandidate {
      const SCEVAddRecExpr *AR;
      uint64_t ElemSize;
      CallInst *CI;
    };
    struct NonAffineSolveCandidate {
      Value *AddrLabel;
      Value *BasePtr;
      Value *Index;
      uint64_t ElemSize;
      uint64_t Offset;
      CallInst *CI;
    };
    DenseMap<Value *, SmallVector<SolveCandidate, 4>> SolveGroups;
    DenseMap<Value *, SmallVector<NonAffineSolveCandidate, 4>>
        NonAffineSolveGroups;
    for (CallInst *CI : SolveBoundsCalls) {
      Value *AddrLabel = CI->getArgOperand(0);
      if (TT.isZeroShadow(AddrLabel))
        continue;
      AddrLabel = ResolveLoopInvariantLabel(AddrLabel);
      if (!AddrLabel)
        continue;

      Value *BasePtr = CI->getArgOperand(1);
      Value *BasePtrForSCEV = BasePtr;
      if (auto *PTI = dyn_cast<PtrToIntOperator>(BasePtrForSCEV)) {
        Value *PtrOp = PTI->getPointerOperand();
        if (ClWithUCSan) {
          if (auto *ChkCall = dyn_cast<CallInst>(PtrOp)) {
            Function *ChkFn = ChkCall->getCalledFunction();
            if (ChkFn && ChkFn->getName() == "ucsan_check_pointer")
              PtrOp = ChkCall->getArgOperand(0);
          }
        }
        if (L->isLoopInvariant(PtrOp)) {
          IRBuilder<> IRB(InsertPt);
          BasePtrForSCEV = IRB.CreatePtrToInt(PtrOp, TT.Int64Ty);
        }
      }
      if (!L->isLoopInvariant(BasePtrForSCEV))
        continue;

      auto *ElemSizeC = dyn_cast<ConstantInt>(CI->getArgOperand(5));
      auto *OffsetC = dyn_cast<ConstantInt>(CI->getArgOperand(6));
      if (!ElemSizeC || !OffsetC)
        continue;
      uint64_t ElemSize = ElemSizeC->getZExtValue();
      if (ElemSize == 0)
        continue;

      NonAffineSolveGroups[AddrLabel].push_back(
          {AddrLabel, BasePtrForSCEV, CI->getArgOperand(3), ElemSize,
           OffsetC->getZExtValue(), CI});

      const SCEV *IndexSCEV = SE.getSCEV(CI->getArgOperand(3));
      const SCEV *AddrSCEV = SE.getAddExpr(
          SE.getSCEV(BasePtrForSCEV),
          SE.getAddExpr(
              SE.getMulExpr(IndexSCEV,
                            SE.getConstant(IndexSCEV->getType(), ElemSize)),
              SE.getConstant(IndexSCEV->getType(), OffsetC->getZExtValue())));
      auto *AR = dyn_cast<SCEVAddRecExpr>(AddrSCEV);
      if (!AR || AR->getLoop() != L) {
        continue;
      }

      const SCEV *Step = AR->getStepRecurrence(SE);
      auto *StepC = dyn_cast<SCEVConstant>(Step);
      if (!StepC) {
        continue;
      }
      if (StepC->getAPInt().getSExtValue() <= 0) {
        continue;
      }

      SolveGroups[AddrLabel].push_back({AR, ElemSize, CI});
    }

    for (auto &KV : SolveGroups) {
      Value *AddrLabel = KV.first;
      auto &Candidates = KV.second;
      const SCEV *MinStart = Candidates[0].AR->getStart();
      const SCEV *MaxEnd = nullptr;
      CallInst *FirstCI = Candidates[0].CI;

      for (auto &C : Candidates) {
        const SCEV *Start = C.AR->getStart();
        const SCEV *Step = C.AR->getStepRecurrence(SE);
        const SCEV *End = SE.getAddExpr(
            Start,
            SE.getAddExpr(SE.getMulExpr(CountAs(Step->getType()), Step),
                          SE.getConstant(Step->getType(), C.ElemSize)));
        if (SE.isKnownPredicate(ICmpInst::ICMP_ULT, Start, MinStart))
          MinStart = Start;
        if (!MaxEnd || SE.isKnownPredicate(ICmpInst::ICMP_UGT, End, MaxEnd))
          MaxEnd = End;
      }

      const SCEV *TotalSCEV = SE.getMinusSCEV(MaxEnd, MinStart);
      Value *StartVal = Expander.expandCodeFor(MinStart, TT.Int64Ty, InsertPt);
      Value *TotalVal = Expander.expandCodeFor(TotalSCEV, TT.Int64Ty, InsertPt);

      IRBuilder<> IRB(InsertPt);
      IRB.CreateCall(TT.TaintCheckBoundsFn,
                     {AddrLabel, StartVal, TT.ZeroPrimitiveShadow, TotalVal});

      SmallVector<Value *, 4> Unknowns;
      collectSCEVUnknowns(TotalSCEV, Unknowns);
      Value *SizeShadow = TT.ZeroPrimitiveShadow;
      for (Value *V : Unknowns) {
        Value *S = getShadow(V);
        if (!TT.isZeroShadow(S))
          SizeShadow = S;
      }
      if (!TT.isZeroShadow(SizeShadow)) {
        ConstantInt *CID = ConstantInt::get(TT.Int32Ty,
            TT.getInstructionId(FirstCI));
        IRB.CreateCall(TT.TaintSolveSizeFn,
                       {AddrLabel, StartVal, SizeShadow, TotalVal, CID});
      }

      for (auto &C : Candidates)
        HoistedSolveBounds.insert(C.CI);
    }

    auto FindHeaderPhi = [&](Value *V) -> PHINode * {
      SmallVector<Value *, 8> Worklist;
      SmallPtrSet<Value *, 8> Seen;
      Worklist.push_back(V);
      while (!Worklist.empty()) {
        Value *Cur = Worklist.pop_back_val();
        if (!Seen.insert(Cur).second)
          continue;
        if (auto *PN = dyn_cast<PHINode>(Cur)) {
          if (PN->getParent() == L->getHeader())
            return PN;
          continue;
        }
        if (auto *Cast = dyn_cast<CastInst>(Cur)) {
          Worklist.push_back(Cast->getOperand(0));
          continue;
        }
        if (auto *BO = dyn_cast<BinaryOperator>(Cur)) {
          Worklist.push_back(BO->getOperand(0));
          Worklist.push_back(BO->getOperand(1));
        }
      }
      return nullptr;
    };

    auto GetLoopStartValue = [&](PHINode *PN) -> Value * {
      for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i) {
        if (!L->contains(PN->getIncomingBlock(i)))
          return PN->getIncomingValue(i);
      }
      return nullptr;
    };

    auto CountCandidatesOnPath =
        [&](ArrayRef<NonAffineSolveCandidate> Candidates,
            BasicBlock *Succ) -> unsigned {
      unsigned Count = 0;
      for (auto &C : Candidates) {
        if (DT.dominates(Succ, C.CI->getParent()))
          ++Count;
      }
      return Count;
    };

    uint64_t ConstantIterations = 0;
    if (auto *BTCConst = dyn_cast<SCEVConstant>(BTC)) {
      ConstantIterations = BTCConst->getAPInt().getZExtValue() + 1;
    } else if (BasicBlock *Latch = L->getLoopLatch()) {
      if (auto *LatchBr = dyn_cast<BranchInst>(Latch->getTerminator())) {
        if (LatchBr->isConditional()) {
          if (auto *Cmp = dyn_cast<ICmpInst>(LatchBr->getCondition())) {
            if (auto *C = dyn_cast<ConstantInt>(Cmp->getOperand(1))) {
              if (Cmp->getPredicate() == ICmpInst::ICMP_EQ ||
                  Cmp->getPredicate() == ICmpInst::ICMP_UGE ||
                  Cmp->getPredicate() == ICmpInst::ICMP_ULT)
                ConstantIterations = C->getZExtValue();
            } else if (auto *C = dyn_cast<ConstantInt>(Cmp->getOperand(0))) {
              if (Cmp->getPredicate() == ICmpInst::ICMP_EQ ||
                  Cmp->getPredicate() == ICmpInst::ICMP_ULE ||
                  Cmp->getPredicate() == ICmpInst::ICMP_UGT)
                ConstantIterations = C->getZExtValue();
            }
          }
        }
      }
    }
    BranchInst *HeaderBr = dyn_cast<BranchInst>(L->getHeader()->getTerminator());
    if (ConstantIterations != 0 && HeaderBr && HeaderBr->isConditional() &&
        L->isLoopInvariant(HeaderBr->getCondition())) {
      for (auto &KV : NonAffineSolveGroups) {
        auto &Candidates = KV.second;
        if (Candidates.empty())
          continue;

        PHINode *IndexPN = FindHeaderPhi(Candidates[0].Index);
        if (!IndexPN)
          continue;
        Value *StartIndex = GetLoopStartValue(IndexPN);
        if (!StartIndex)
          continue;

        uint64_t ElemSize = Candidates[0].ElemSize;
        uint64_t Offset = Candidates[0].Offset;
        Value *BasePtr = Candidates[0].BasePtr;
        bool SameShape = true;
        for (auto &C : Candidates) {
          if (C.ElemSize != ElemSize || C.Offset != Offset) {
            SameShape = false;
            break;
          }
        }
        if (!SameShape)
          continue;

        unsigned TrueCount =
            CountCandidatesOnPath(Candidates, HeaderBr->getSuccessor(0));
        unsigned FalseCount =
            CountCandidatesOnPath(Candidates, HeaderBr->getSuccessor(1));
        if (TrueCount == 0 && FalseCount == 0)
          continue;

        IRBuilder<> IRB(InsertPt);
        Value *StartIndex64 = IRB.CreateZExtOrTrunc(StartIndex, TT.Int64Ty);
        Value *StartOffset = StartIndex64;
        if (ElemSize != 1)
          StartOffset = IRB.CreateMul(
              StartOffset, ConstantInt::get(TT.Int64Ty, ElemSize));
        if (Offset != 0)
          StartOffset = IRB.CreateAdd(
              StartOffset, ConstantInt::get(TT.Int64Ty, Offset));
        Value *StartVal = IRB.CreateAdd(BasePtr, StartOffset);

        Value *TrueSize = ConstantInt::get(TT.Int64Ty,
                                           ConstantIterations * TrueCount * ElemSize);
        Value *FalseSize = ConstantInt::get(TT.Int64Ty,
                                            ConstantIterations * FalseCount * ElemSize);
        Value *TotalVal = IRB.CreateSelect(HeaderBr->getCondition(),
                                           TrueSize, FalseSize);

        // Soft solve_size hint only: ConstantIterations and the per-path counts
        // are heuristics, not a proven extent, so no hard check_bounds here.
        ConstantInt *CID = ConstantInt::get(TT.Int32Ty,
            TT.getInstructionId(Candidates[0].CI));
        IRB.CreateCall(TT.TaintSolveSizeFn,
                       {KV.first, StartVal, TT.ZeroPrimitiveShadow, TotalVal,
                        CID});

        for (auto &C : Candidates)
          HoistedSolveBounds.insert(C.CI);
      }
    }

    for (CallInst *CI : HoistedSolveBounds)
      CI->eraseFromParent();

    // Drop ptrtoint temporaries that were only needed for SCEV queries.
    for (Instruction *T : SCEVTemps)
      if (T->use_empty())
        T->eraseFromParent();
  }
}

// Generates IR to load shadow corresponding to bytes [Addr, Addr+Size), where
// Addr has alignment Align, and take the union of each of those shadows.
Value *TaintFunction::loadPrimitiveShadow(Value *Addr, uint64_t Size,
                                          uint64_t SizeInBits, uint64_t Align,
                                          IRBuilder<> &IRB) {
  if (Size == 0)
    return TT.ZeroPrimitiveShadow;

  Value *ShadowAddr = TT.getShadowAddress(Addr, IRB);
  CallInst *FallbackCall = IRB.CreateCall(
      TT.TaintUnionLoadFn, {ShadowAddr, ConstantInt::get(TT.IntptrTy, Size),
                            ConstantInt::get(TT.Int64Ty, SizeInBits),
                            ConstantInt::get(TT.IntptrTy, Align)});
  FallbackCall->addRetAttr(Attribute::ZExt);
  return FallbackCall;
}

Value *TaintFunction::loadShadowRecursive(
    Value *Shadow, SmallVector<unsigned, 4> &Indices, Type *SubTy,
    Value *Addr, uint64_t Size, uint64_t Align, IRBuilder<> &IRB) {
  auto &DL = F->getParent()->getDataLayout();

  if (!isa<ArrayType>(SubTy) && !isa<StructType>(SubTy)) {
    uint64_t SubSize = DL.getTypeStoreSize(SubTy);
    assert(Size >= SubSize);
    uint64_t SubSizeInBits = DL.getTypeSizeInBits(SubTy);
    Align = std::min(Align, (uint64_t)(DL).getABITypeAlign(SubTy).value());
    // load a primitive shadow from address
    Value *PrimitiveShadow = loadPrimitiveShadow(Addr, SubSize, SubSizeInBits, Align, IRB);
    // then insert the primitive shadow into the sub-field
    return IRB.CreateInsertValue(Shadow, PrimitiveShadow, Indices);
  }

  if (ArrayType *AT = dyn_cast<ArrayType>(SubTy)) {
    for (unsigned Idx = 0; Idx < AT->getNumElements(); Idx++) {
      Indices.push_back(Idx);
      // double check the remaining size
      Type *ElemTy = AT->getElementType();
      uint64_t ElemSize = DL.getTypeStoreSize(ElemTy);
      uint64_t Offset = ElemSize * Idx;
      assert(Offset <= Size);
      // get the address of the array element
      Value *SubAddr = IRB.CreateConstGEP2_32(AT, Addr, 0, Idx);
      Shadow = loadShadowRecursive(Shadow, Indices, ElemTy,
                                   SubAddr, Size - Offset, Align, IRB);
      Indices.pop_back();
    }
    return Shadow;
  }

  if (StructType *ST = dyn_cast<StructType>(SubTy)) {
    const StructLayout *SL = DL.getStructLayout(ST);
    for (unsigned Idx = 0; Idx < ST->getNumElements(); Idx++) {
      Indices.push_back(Idx);
      // double check the remaining size
      uint64_t Offset = SL->getElementOffset(Idx);
      assert(Offset <= Size);
      Type *ElemTy = ST->getElementType(Idx);
      // get the address of the struct field
      Value *SubAddr = IRB.CreateConstGEP2_32(ST, Addr, 0, Idx);
      Shadow = loadShadowRecursive(Shadow, Indices, ElemTy,
                                   SubAddr, Size - Offset, Align, IRB);
      Indices.pop_back();
    }
    return Shadow;
  }
  llvm_unreachable("Unexpected shadow type");
}

Value *TaintFunction::loadShadow(Type *T, Value *Addr, uint64_t Size,
                                 Align Alignment, Instruction *Pos) {
  IRBuilder<> IRB(Pos);
  // if loading from a local variable, load label from its shadow
  if (AllocaInst *AI = dyn_cast<AllocaInst>(Addr)) {
    const auto i = AllocaShadowMap.find(AI);
    if (i != AllocaShadowMap.end()) {
      return IRB.CreateLoad(TT.getShadowTy(T), i->second);
    }
  }

  // check if the target object is a constant
  SmallVector<const Value *, 2> Objs;
  getUnderlyingObjects(Addr, Objs);
  bool AllConstants = true;
  for (const Value *Obj : Objs) {
    if (isa<Function>(Obj) || isa<BlockAddress>(Obj))
      continue;
    if (isa<GlobalVariable>(Obj) && cast<GlobalVariable>(Obj)->isConstant())
      continue;

    AllConstants = false;
    break;
  }
  if (AllConstants)
    return TT.getZeroShadow(T);

  if (Size == 0)
    return TT.ZeroPrimitiveShadow;

  const uint64_t ShadowAlign = getShadowAlign(Alignment).value();
  auto &DL = F->getParent()->getDataLayout();

  // now check if we're loading an aggragate object
  if (!isa<ArrayType>(T) && !isa<StructType>(T)) {
    uint64_t SizeInBits = DL.getTypeSizeInBits(T);
    return loadPrimitiveShadow(Addr, Size, SizeInBits, ShadowAlign, IRB);
  }

  // if loading an aggregate object, load its shadow recursively
  SmallVector<unsigned, 4> Indices;
  Type *ShadowTy = TT.getShadowTy(T);
  Value *Shadow = UndefValue::get(ShadowTy);
  Shadow = loadShadowRecursive(Shadow, Indices, T, Addr, Size, ShadowAlign, IRB);
  return Shadow;
}

static AtomicOrdering addAcquireOrdering(AtomicOrdering AO) {
  switch (AO) {
  case AtomicOrdering::NotAtomic:
    return AtomicOrdering::NotAtomic;
  case AtomicOrdering::Unordered:
  case AtomicOrdering::Monotonic:
  case AtomicOrdering::Acquire:
    return AtomicOrdering::Acquire;
  case AtomicOrdering::Release:
  case AtomicOrdering::AcquireRelease:
    return AtomicOrdering::AcquireRelease;
  case AtomicOrdering::SequentiallyConsistent:
    return AtomicOrdering::SequentiallyConsistent;
  }
  llvm_unreachable("Unknown ordering");
}

static AtomicOrdering addReleaseOrdering(AtomicOrdering AO) {
  switch (AO) {
  case AtomicOrdering::NotAtomic:
    return AtomicOrdering::NotAtomic;
  case AtomicOrdering::Unordered:
  case AtomicOrdering::Monotonic:
  case AtomicOrdering::Release:
    return AtomicOrdering::Release;
  case AtomicOrdering::Acquire:
  case AtomicOrdering::AcquireRelease:
    return AtomicOrdering::AcquireRelease;
  case AtomicOrdering::SequentiallyConsistent:
    return AtomicOrdering::SequentiallyConsistent;
  }
  llvm_unreachable("Unknown ordering");
}

void TaintVisitor::visitAtomicRMWInst(AtomicRMWInst &I) {
  auto &DL = I.getModule()->getDataLayout();
  Value *Ptr = I.getPointerOperand();
  Value *Val = I.getValOperand();
  Type *Ty = I.getType();
  uint64_t Size = DL.getTypeStoreSize(Ty);

  Value *Shadow1 = TF.loadShadow(Ty, Ptr, Size, I.getAlign(), &I);
  Value *Shadow2 = TF.getShadow(Val);
  Value *Shadow  = nullptr;
  Value *Op1 = nullptr, *Cond = nullptr;
  IRBuilder<> IRB(&I);

  switch (I.getOperation()) {
    case AtomicRMWInst::Xchg:
      Shadow = Shadow2;
      break;
    case AtomicRMWInst::Add:
      Shadow = TF.combineShadows(Shadow1, Shadow2, BinaryOperator::Add, &I);
      break;
    case AtomicRMWInst::Sub:
      Shadow = TF.combineShadows(Shadow1, Shadow2, BinaryOperator::Sub, &I);
      break;
    case AtomicRMWInst::And:
      Shadow = TF.combineShadows(Shadow1, Shadow2, BinaryOperator::And, &I);
      break;
    case AtomicRMWInst::Nand:
      Shadow = TF.combineShadows(Shadow1, Shadow2, BinaryOperator::And, &I);
      Shadow = TF.combineShadows(TF.TT.getZeroShadow(Ty), Shadow, 2, &I); // __dfsan::Neg
      break;
    case AtomicRMWInst::Or:
      Shadow = TF.combineShadows(Shadow1, Shadow2, BinaryOperator::Or, &I);
      break;
    case AtomicRMWInst::Xor:
      Shadow = TF.combineShadows(Shadow1, Shadow2, BinaryOperator::Xor, &I);
      break;
    case AtomicRMWInst::Max:
      Op1 = IRB.CreateLoad(Ty, Ptr, true);
      Cond = IRB.CreateICmpSGT(Op1, Val);
      Shadow = IRB.CreateSelect(Cond, Shadow1, Shadow2);
      break;
    case AtomicRMWInst::Min:
      Op1 = IRB.CreateLoad(Ty, Ptr, true);
      Cond = IRB.CreateICmpSLT(Op1, Val);
      Shadow = IRB.CreateSelect(Cond, Shadow1, Shadow2);
      break;
    case AtomicRMWInst::UMax:
      Op1 = IRB.CreateLoad(Ty, Ptr, true);
      Cond = IRB.CreateICmpUGT(Op1, Val);
      Shadow = IRB.CreateSelect(Cond, Shadow1, Shadow2);
      break;
    case AtomicRMWInst::UMin:
      Op1 = IRB.CreateLoad(Ty, Ptr, true);
      Cond = IRB.CreateICmpULT(Op1, Val);
      Shadow = IRB.CreateSelect(Cond, Shadow1, Shadow2);
      break;
    // TODO: support extra operations
    default:
      assert(false && "unimplemented atomicrmw operation");
      break;
  }

  TF.storeShadow(Ptr, Ty, Size, I.getAlign(), Shadow, &I);
  TF.setShadow(&I, Shadow1);

  // TODO: The ordering change follows MSan. It is possible not to change
  // ordering because we always set and use 0 shadows.
  I.setOrdering(addReleaseOrdering(I.getOrdering()));
}

void TaintVisitor::visitAtomicCmpXchgInst(AtomicCmpXchgInst &I) {
  auto &DL = I.getModule()->getDataLayout();
  Value *Ptr = I.getPointerOperand();
  Value *NewVal = I.getNewValOperand();
  Type *ValTy = NewVal->getType();
  uint64_t Size = DL.getTypeStoreSize(ValTy);

  // The result is { ValTy old_value, i1 success }. Field 0 carries the value
  // read from memory; the success flag is a concrete comparison result and is
  // treated as clean.
  Type *ResShadowTy = TF.TT.getShadowTy(I.getType());

  if (Size == 0) {
    TF.setShadow(&I, TF.TT.getZeroShadow(&I));
    // Upstream DFSan follows MSan's ordering change; do the same.
    I.setSuccessOrdering(addReleaseOrdering(I.getSuccessOrdering()));
    return;
  }

  if (!ClPreserveAtomicShadow) {
    // Conservative, race-free behaviour matching upstream DFSan: zero the
    // shadow at the stored address and return a zero result shadow.
    Value *Zero = TF.TT.getZeroShadow(ValTy);
    TF.storeShadow(Ptr, ValTy, Size, I.getAlign(), Zero, &I);
    TF.setShadow(&I, TF.TT.getZeroShadow(&I));
    I.setSuccessOrdering(addReleaseOrdering(I.getSuccessOrdering()));
    return;
  }

  // Shadow of the value currently in memory (returned in field 0).
  Value *OldShadow = TF.loadShadow(ValTy, Ptr, Size, I.getAlign(), &I);
  Value *NewShadow = TF.getShadow(NewVal);

  // The exchange only writes NewVal on success, so the shadow in memory
  // becomes NewShadow when the comparison succeeded and stays OldShadow
  // otherwise. The success flag is only available after the instruction.
  Instruction *Pos = I.getNextNode();
  IRBuilder<> IRB(Pos);
  Value *Success = IRB.CreateExtractValue(&I, 1);
  Value *StoredShadow = IRB.CreateSelect(Success, NewShadow, OldShadow);
  TF.storeShadow(Ptr, ValTy, Size, I.getAlign(), StoredShadow, Pos);

  Value *ResShadow = UndefValue::get(ResShadowTy);
  ResShadow = IRB.CreateInsertValue(ResShadow, OldShadow, 0);
  ResShadow = IRB.CreateInsertValue(
      ResShadow, TF.TT.getZeroShadow(I.getType()->getStructElementType(1)), 1);
  TF.setShadow(&I, ResShadow);

  // TODO: The ordering change follows MSan. It is possible not to change
  // ordering because we always set and use 0 shadows.
  I.setSuccessOrdering(addReleaseOrdering(I.getSuccessOrdering()));
}

void TaintVisitor::visitLoadInst(LoadInst &LI) {
  auto &DL = LI.getModule()->getDataLayout();
  uint64_t Size = DL.getTypeStoreSize(LI.getType());
  if (Size == 0) {
    TF.setShadow(&LI, TF.TT.getZeroShadow(&LI));
    return;
  }

  // When an application load is atomic, increase atomic ordering between
  // atomic application loads and stores to ensure happen-before order; load
  // shadow data after application data; store zero shadow data before
  // application data. This ensure shadow loads return either labels of the
  // initial application data or zeros.
  if (LI.isAtomic())
    LI.setOrdering(addAcquireOrdering(LI.getOrdering()));

  Instruction *Pos = LI.isAtomic() ? LI.getNextNode() : &LI;

  // check bounds first
  if (ClTraceBound)
    TF.checkBounds(LI.getPointerOperand(),
                   ConstantInt::get(TF.TT.Int64Ty, Size), Pos);

  // A load from a read-only global table at a symbolic index: shadow memory
  // over globals is zero, so the value we just loaded is concrete and any
  // comparison consuming it never reaches the solver.  Give it a real shadow
  // describing the lookup instead.  Done at the load, not the GEP, so the
  // loaded value itself carries the label and propagates normally from here.
  //
  // This replaces the shadow load rather than combining with it: the table is a
  // read-only global, so its shadow is zero by construction and loading it
  // would only cost an access.  (Testing isZeroShadow() on the loaded shadow
  // would never fire -- loadShadow returns an instruction, not a constant.)
  Value *Shadow = nullptr;
  if (ClTraceTableLookup) {
    auto It = TF.TableGEPs.find(LI.getPointerOperand());
    if (It != TF.TableGEPs.end()) {
      const auto &TGI = It->second;
      // Only the element type we recorded; a differently-sized load through the
      // same GEP (type punning) is not the lookup we analyzed.
      if (DL.getTypeStoreSize(LI.getType()) == TGI.ElemSize &&
          LI.getType()->isIntegerTy()) {
        IRBuilder<> IRB(Pos);
        Shadow = IRB.CreateCall(
            TF.TT.TaintTableLookupFn,
            {TGI.IndexShadow, TGI.Index, TGI.TablePtr,
             ConstantInt::get(TF.TT.Int64Ty, TGI.NumElements),
             ConstantInt::get(TF.TT.Int64Ty, TGI.ElemSize)});
      }
    }
  }

  if (!Shadow)
    Shadow = TF.loadShadow(LI.getType(), LI.getPointerOperand(), Size,
                           LI.getAlign(), Pos);
#if 0
  //FIXME: tainted pointer
  if (ClCombinePointerLabelsOnLoad) {
    Value *PtrShadow = TF.getShadow(LI.getPointerOperand());
    Shadow = TF.combineShadows(Shadow, PtrShadow, Pos);
  }
#endif

  if (!TF.TT.isZeroShadow(Shadow))
    TF.NonZeroChecks.push_back(Shadow);

  TF.setShadow(&LI, Shadow);
}

void TaintFunction::storeShadowRecursive(
    Value *Shadow, SmallVector<unsigned, 4> &Indices, Type *SubShadowTy,
    Value *Addr, uint64_t Size, uint64_t Align, IRBuilder<> &IRB) {
  auto &DL = F->getParent()->getDataLayout();

  if (!isa<ArrayType>(SubShadowTy) && !isa<StructType>(SubShadowTy)) {
    uint64_t SubSize = DL.getTypeStoreSize(SubShadowTy);
    assert(Size >= SubSize);
    Align = std::min(Align, (uint64_t)(DL).getABITypeAlign(SubShadowTy).value());
    // load a primitive shadow from the sub-field
    Value *PrimitiveShadow = IRB.CreateExtractValue(Shadow, Indices);
    // then store the primitive shadow into the shadow address
    Value *ShadowAddr = TT.getShadowAddress(Addr, IRB);
    IRB.CreateCall(TT.TaintUnionStoreFn,
                   {PrimitiveShadow, ShadowAddr,
                    ConstantInt::get(TT.IntptrTy, SubSize),
                    ConstantInt::get(TT.IntptrTy, Align)});
    return;
  }

  if (ArrayType *AT = dyn_cast<ArrayType>(SubShadowTy)) {
    for (unsigned Idx = 0; Idx < AT->getNumElements(); Idx++) {
      Indices.push_back(Idx);
      // double check the remaining size
      Type *ElemTy = AT->getElementType();
      uint64_t ElemSize = DL.getTypeStoreSize(ElemTy);
      uint64_t Offset = ElemSize * Idx;
      assert(Offset <= Size);
      // get the address of the array element
      Value *SubAddr = IRB.CreateConstGEP2_32(AT, Addr, 0, Idx);
      storeShadowRecursive(Shadow, Indices, ElemTy,
                           SubAddr, Size - Offset, Align, IRB);
      Indices.pop_back();
    }
    return;
  }

  if (StructType *ST = dyn_cast<StructType>(SubShadowTy)) {
    const StructLayout *SL = DL.getStructLayout(ST);
    for (unsigned Idx = 0; Idx < ST->getNumElements(); Idx++) {
      Indices.push_back(Idx);
      // double check the remaining size
      uint64_t Offset = SL->getElementOffset(Idx);
      assert(Offset <= Size);
      Type *ElemTy = ST->getElementType(Idx);
      // get the address of the struct field
      Value *SubAddr = IRB.CreateConstGEP2_32(ST, Addr, 0, Idx);
      storeShadowRecursive(Shadow, Indices, ElemTy,
                           SubAddr, Size - Offset, Align, IRB);
      Indices.pop_back();
    }
    return;
  }
  llvm_unreachable("Unexpected shadow type");
}

void TaintFunction::storeShadow(Value *Addr, Type *T, uint64_t Size,
                                Align Alignment, Value *Shadow,
                                Instruction *Pos) {
  IRBuilder<> IRB(Pos);
  if (AllocaInst *AI = dyn_cast<AllocaInst>(Addr)) {
    const auto i = AllocaShadowMap.find(AI);
    if (i != AllocaShadowMap.end()) {
      auto *SI = IRB.CreateStore(Shadow, i->second);
      SkipInsts.insert(SI);
      return;
    }
  }

  Value *ShadowAddr = TT.getShadowAddress(Addr, IRB);
  const Align ShadowAlign = getShadowAlign(Alignment);
  // check if the shadow is zero, if so, clear the shadow memory regardless
  // of the shadow type
  if (TT.isZeroShadow(Shadow)) {
    IntegerType *ShadowTy =
        IntegerType::get(*TT.Ctx, Size * TT.ShadowWidthBits);
    Value *ExtZeroShadow = ConstantInt::get(ShadowTy, 0);
    Value *ExtShadowAddr =
        IRB.CreateBitCast(ShadowAddr, PointerType::getUnqual(ShadowTy));
    IRB.CreateAlignedStore(ExtZeroShadow, ExtShadowAddr, ShadowAlign);
    return;
  }

  // now check if we're storing an aggragate shadow object
  if (!isa<ArrayType>(T) && !isa<StructType>(T)) {
    IRB.CreateCall(TT.TaintUnionStoreFn,
                   {Shadow, ShadowAddr, ConstantInt::get(TT.IntptrTy, Size),
                    ConstantInt::get(TT.IntptrTy, ShadowAlign.value())});
    return;
  }

  // if storing an aggregate shadow object, store its shadow recursively
  // we want to do this so union_store may have a chance to simplify some
  // constraints
  SmallVector<unsigned, 4> Indices;
  storeShadowRecursive(Shadow, Indices, T, Addr, Size,
                       ShadowAlign.value(), IRB);
}

void TaintVisitor::visitStoreInst(StoreInst &SI) {
  auto &DL = SI.getModule()->getDataLayout();
  Value *Val = SI.getValueOperand();
  Type* VT = SI.getValueOperand()->getType();
  uint64_t Size = DL.getTypeStoreSize(VT);
  if (Size == 0)
    return;

  // When an application store is atomic, increase atomic ordering between
  // atomic application loads and stores to ensure happen-before order; load
  // shadow data after application data; store zero shadow data before
  // application data. This ensure shadow loads return either labels of the
  // initial application data or zeros.
  if (SI.isAtomic())
    SI.setOrdering(addReleaseOrdering(SI.getOrdering()));

  Value* Shadow = (SI.isAtomic() && !ClPreserveAtomicShadow)
                      ? TF.TT.getZeroShadow(VT)
                      : TF.getShadow(Val);

  // check bounds first
  if (ClTraceBound)
    TF.checkBounds(SI.getPointerOperand(),
                   ConstantInt::get(TF.TT.Int64Ty, Size), &SI);

#if 0
  //FIXME: tainted pointer
  if (ClCombinePointerLabelsOnStore) {
    Value *PtrShadow = TF.getShadow(SI.getPointerOperand());
    Shadow = TF.combineShadows(Shadow, PtrShadow, &SI);
  }
#endif
  TF.storeShadow(SI.getPointerOperand(), VT, Size, SI.getAlign(), Shadow, &SI);
}

void TaintVisitor::visitUnaryOperator(UnaryOperator &UO) {
  // The only unary operator in LLVM IR is FNeg.  LLVM's FNeg opcode is a unary
  // instruction which is not part of the __dfsan::operators enum (only binary,
  // memory, cast and other insts are expanded from Instruction.def), so we map
  // it to the self-defined __dfsan::fp_neg.
  if (UO.getOpcode() != Instruction::FNeg) return;
  if (!ClTraceFP) return;
  Value *Shadow1 = TF.getShadow(UO.getOperand(0));
  // combineShadows reads UO.getOperand(0) directly and bitcasts the FP operand
  // to an integer before the union call; the second operand stays zero.
  Value *CombinedShadow =
    TF.combineShadows(Shadow1, TF.TT.ZeroPrimitiveShadow, DfsanFpNeg, &UO);
  TF.setShadow(&UO, CombinedShadow);
}

void TaintVisitor::visitBinaryOperator(BinaryOperator &BO) {
  if (BO.getType()->isFloatingPointTy() && !ClTraceFP) return;
  Value *CombinedShadow =
    TF.combineBinaryOperatorShadows(&BO, BO.getOpcode());
  TF.setShadow(&BO, CombinedShadow);
}

void TaintVisitor::visitCastInst(CastInst &CI) {
  // Special case: if this is the bitcast (there is exactly 1 allowed) between
  // a musttail call and a ret, don't instrument. New instructions are not
  // allowed after a musttail call.
  if (auto *C = dyn_cast<CallInst>(CI.getOperand(0)))
    if (C->isMustTailCall())
      return;
  Value *CombinedShadow =
    TF.combineCastInstShadows(&CI, CI.getOpcode());
  TF.setShadow(&CI, CombinedShadow);
}

void TaintFunction::visitCmpInst(CmpInst *I) {
  // get operand
  Value *Op1 = I->getOperand(0);
  Value *Op2 = I->getOperand(1);
  Value *Op1Shadow = getShadow(Op1);
  Value *Op2Shadow = getShadow(Op2);
  if (TT.isZeroShadow(Op1Shadow) && TT.isZeroShadow(Op2Shadow))
    return;

  Module *M = F->getParent();
  auto &DL = M->getDataLayout();
  unsigned size = DL.getTypeSizeInBits(Op1->getType());
  // same 64-bit ceiling as combineShadows: truncating wider operands while
  // reporting their real width would hand the solver a wrong formula
  if (size > 64)
    return;

  IRBuilder<> IRB(I);
  Op1 = IRB.CreateZExtOrTrunc(Op1, TT.Int64Ty);
  Op2 = IRB.CreateZExtOrTrunc(Op2, TT.Int64Ty);
  ConstantInt *Size = ConstantInt::get(TT.Int32Ty, size);
  ConstantInt *Predicate = ConstantInt::get(TT.Int32Ty, I->getPredicate());
  ConstantInt *CID = ConstantInt::get(TT.Int32Ty, TT.getInstructionId(I));

  IRB.CreateCall(TT.TaintTraceCmpFn, {Op1Shadow, Op2Shadow, Size, Predicate,
                 Op1, Op2, CID});
}

void TaintVisitor::visitCmpInst(CmpInst &CI) {
  // FIXME: integer only now
  if (!ClTraceFP && !isa<ICmpInst>(CI)) return;
#if 0 //TODO make an option
  TF.visitCmpInst(&CI);
#endif
  Value *CombinedShadow =
    TF.combineCmpInstShadows(&CI, CI.getOpcode());
  TF.setShadow(&CI, CombinedShadow);
}

void TaintFunction::visitSwitchInst(SwitchInst *I) {
  Module *M = F->getParent();
  auto &DL = M->getDataLayout();
  // get operand
  Value *Cond = I->getCondition();
  Value *CondShadow = getShadow(Cond);
  if (TT.isZeroShadow(CondShadow))
    return;
  uint32_t cid = TT.getInstructionId(I);
  if (cid == TT.InvalidInstructionId)
    return;
  TT.documentBranchId(cid, I, "switch");
  unsigned size = DL.getTypeSizeInBits(Cond->getType());
  ConstantInt *Size = ConstantInt::get(TT.Int32Ty, size);
  ConstantInt *Predicate = ConstantInt::get(TT.Int32Ty, 32); // EQ, ==
  ConstantInt *CID = ConstantInt::get(TT.Int32Ty, cid);

  IRBuilder<> IRB(I);
  for (auto C : I->cases()) {
    Value *CV = C.getCaseValue();

    // Each case gets its own id.  They all used to share the switch's cid,
    // which left (cid, direction) unable to say *which* case, and so left every
    // case unjoinable with the fuzzer's per-case-block edge ids.  The case
    // value is taken zero-extended to 64 bits because that is the form the
    // CreateZExtOrTrunc below hands the runtime, and the form AFL++'s ids file
    // has to agree on; see symsan::switch_case_cid in include/branch_id.h.
    uint64_t CaseValue =
        C.getCaseValue()->getValue().zextOrTrunc(64).getZExtValue();
    uint32_t case_cid = symsan::switch_case_cid(cid, CaseValue);
    TT.documentBranchId(case_cid, I, "switch-case",
                        "case=" + std::to_string(CaseValue));
    ConstantInt *CaseCID = ConstantInt::get(TT.Int32Ty, case_cid);

    Cond = IRB.CreateZExtOrTrunc(Cond, TT.Int64Ty);
    CV = IRB.CreateZExtOrTrunc(CV, TT.Int64Ty);
    IRB.CreateCall(TT.TaintTraceCmpFn, {CondShadow, TT.ZeroPrimitiveShadow,
                   Size, Predicate, Cond, CV, CaseCID});
  }
  // The switch's own cid, not any case's: the runtime uses it to tell that the
  // case it has stashed belongs to this switch.
  IRB.CreateCall(TT.TaintTraceSwitchEndFn, {CID});
}

void TaintVisitor::visitSwitchInst(SwitchInst &SWI) {
  TF.visitSwitchInst(&SWI);
}

void TaintVisitor::visitLandingPadInst(LandingPadInst &LPI) {
  // We do not need to track data through LandingPadInst.
  //
  // For the C++ exceptions, if a value is thrown, this value will be stored
  // in a memory location provided by __cxa_allocate_exception(...) (on the
  // throw side) or  __cxa_begin_catch(...) (on the catch side).
  // This memory will have a shadow, so with the loads and stores we will be
  // able to propagate labels on data thrown through exceptions, without any
  // special handling of the LandingPadInst.
  //
  // The second element in the pair result of the LandingPadInst is a
  // register value, but it is for a type ID and should never be tainted.
  TF.setShadow(&LPI, TF.TT.getZeroShadow(&LPI));
}

// Is GV a lookup table we can safely treat as a constant array?
//
// Note we deliberately do NOT use GV->isConstant(): tables are routinely
// declared plain `static` rather than `const` (e.g. `static uint8_t hex[16]`),
// and at -O0 GlobalOpt never runs to infer constancy, so isConstant() would
// silently miss the common case.  GlobalStatus is the analysis GlobalOpt itself
// uses to answer this.
//
// NotStored only tells us the global is never written *in this module*, so it
// is sufficient only when no other module can reach it -- hence the linkage
// check.  An external non-const global could be written from another TU.
static bool isReadOnlyLookupTable(const GlobalVariable *GV, const DataLayout &DL,
                                  uint64_t &NumElements, uint64_t &ElemSize) {
  if (!GV->hasInitializer() || GV->isDeclaration())
    return false;
  // A non-const global with external linkage could be written from another
  // translation unit, so "no stores in this module" would not be sound.
  if (!GV->hasLocalLinkage() && !GV->isConstant())
    return false;

  GlobalStatus GS;
  if (GlobalStatus::analyzeGlobal(GV, GS))
    return false; // analysis bailed out; assume the worst
  if (GS.StoredType != GlobalStatus::NotStored)
    return false;

  ArrayType *ATy = dyn_cast<ArrayType>(GV->getValueType());
  if (!ATy)
    return false;
  Type *ETy = ATy->getElementType();
  // Only integer elements: the loaded value has to fit in a label's 64-bit
  // value slot, and i2s inverts by scanning for an exact integer match.
  if (!ETy->isIntegerTy() || ETy->getIntegerBitWidth() > 64)
    return false;

  NumElements = ATy->getNumElements();
  ElemSize = DL.getTypeAllocSize(ETy);
  if (NumElements == 0 || ElemSize == 0)
    return false;
  if (NumElements * ElemSize > ClMaxTableBytes)
    return false;
  return true;
}

/// Find the read-only global arrays worth treating as lookup tables.
///
/// Must run before any instrumentation: getShadowForGlobal() passes a global's
/// address to __taint_trace_global, and GlobalStatus::analyzeGlobal() gives up
/// on any global whose address escapes into a call -- so asking the question
/// later always answers "unanalyzable", and no table is ever found.
void Taint::findReadOnlyTables(Module &M) {
  if (!ClTraceTableLookup)
    return;
  const DataLayout &DL = M.getDataLayout();
  for (GlobalVariable &GV : M.globals()) {
    uint64_t NumElements = 0, ElemSize = 0;
    if (isReadOnlyLookupTable(&GV, DL, NumElements, ElemSize))
      ReadOnlyTables[&GV] = {NumElements, ElemSize};
  }
}

void TaintFunction::visitGEPInst(GetElementPtrInst *I) {
  Module *M = F->getParent();
  auto &DL = M->getDataLayout();
  int64_t CurrentOffset = 0;

  IRBuilder<> IRB(I);
  Value *Base = I->getPointerOperand();
  Value *Shadow = getShadow(Base->stripPointerCasts());
  if (auto *GV = dyn_cast<GlobalVariable>(Base->stripPointerCasts())) {
    // if the base pointer is a global variable, and without ucsan,
    // we can't get its shadow from the shadow map
    if (!ClWithUCSan) {
      Shadow = getShadowForGlobal(GV, IRB);
    }
  }

  Type *POTy = I->getPointerOperandType();
  Type *ETy = POTy;
  for (auto &Idx: I->indices()) {
    // reference: DataLayout::getIndexedOffsetInType
    Value *Index = &*Idx;
    if (StructType *STy = dyn_cast<StructType>(ETy)) {
      // index into struct has to be constant
      assert(isa<ConstantInt>(Index) && "inllegal struct index");
      unsigned FieldNo = cast<ConstantInt>(Index)->getZExtValue();
      const StructLayout *SL = DL.getStructLayout(STy);
      CurrentOffset += SL->getElementOffset(FieldNo);
      ETy = STy->getTypeAtIndex(FieldNo);
    } else {
      uint64_t NumElements = 0;
      int64_t ElemSize = 0;
      if (PointerType *PTy = dyn_cast<PointerType>(ETy)) {
        assert(PTy == POTy && "inllegal pointer index");
        ETy = I->getSourceElementType();
        NumElements = 0; // we don't know the number of elements
        ElemSize = DL.getTypeAllocSize(ETy);
      } else if (ArrayType *ATy = dyn_cast<ArrayType>(ETy)) {
        ETy = ATy->getElementType();
        NumElements = ATy->getNumElements();
        ElemSize = DL.getTypeAllocSize(ETy);
      } else {
        VectorType *VTy = dyn_cast<VectorType>(ETy);
        assert(VTy && "inllegal index type");
        ETy = VTy->getElementType();
        NumElements = VTy->getElementCount().getFixedValue();
        ElemSize = DL.getTypeStoreSize(ETy);
        break;
      }

      if (isa<ConstantInt>(Index)) {
        int64_t arrayIdx = cast<ConstantInt>(Index)->getSExtValue();
        CurrentOffset += arrayIdx * ElemSize;
      } else if (Index->getType()->isIntegerTy()) { // FIXEME: handle vector type
        // non-constant index, check if it's tainted
        Value *IndexShadow = getShadow(Index);
        if (!TT.isZeroShadow(IndexShadow)) {
          Index = IRB.CreateZExtOrTrunc(Index, TT.Int64Ty);
          ConstantInt *Offset = ConstantInt::get(TT.Int64Ty, CurrentOffset);
          ConstantInt *NE = ConstantInt::get(TT.Int64Ty, NumElements);
          ConstantInt *ES = ConstantInt::get(TT.Int64Ty, ElemSize);
          Value *Ptr = IRB.CreatePtrToInt(I->getPointerOperand(), TT.Int64Ty);
          ConstantInt *CID = ConstantInt::get(TT.Int32Ty, TT.getInstructionId(I));
          if (ClSolveUB) {
            // check if index can go out of bounds
            // -fsanitize=local-bounds
            // must be added before tracing GEP, otherwise index_label == index
            // will be added as nested constraint
            IRB.CreateCall(TT.TaintSolveBoundsFn,
                           {Shadow, Ptr, IndexShadow, Index, NE, ES, Offset, CID});
          }
          if (ClTraceGEPOffset) {
            IRB.CreateCall(TT.TaintTraceGEPFn,
                           {Shadow, Ptr, IndexShadow, Index, NE, ES, Offset, CID});
          }
          if (ClTraceTableLookup) {
            // If this GEP indexes a read-only global table, remember it so the
            // load that consumes it can be symbolized (visitLoadInst).  Note we
            // check the *underlying* object, and only accept a GlobalVariable:
            // glibc's ctype tables are reached via __ctype_b_loc(), so the base
            // is a load rather than a global and they are skipped -- which is
            // what keeps this from firing on every isupper()/tolower().
            auto *GV = dyn_cast<GlobalVariable>(getUnderlyingObject(Base));
            auto TblItr = GV ? TT.ReadOnlyTables.find(GV)
                             : TT.ReadOnlyTables.end();
            if (TblItr != TT.ReadOnlyTables.end()) {
              Value *TablePtr = IRB.CreatePtrToInt(GV, TT.Int64Ty);
              TableGEPs[I] = {IndexShadow, Index, TablePtr,
                              TblItr->second.first, TblItr->second.second};
            }
          }
        } else {
          break;
        }
      }
    }
  }

  // we need to check GEP for two reasons:
  // 1. For constant offset GEPs on string op pointers, create fstr_off label
  // to track the offset (e.g., sep + 1 where sep is from strchr)
  // 2. For symbolic ptr (e.g., from UCSan), we need to trace the offset
  if (!TT.isZeroShadow(Shadow)) {
    IRBuilder<> IRB(I->getNextNode());
    Shadow = IRB.CreateCall(TT.TaintGEPOffsetFn,
        {Shadow, IRB.CreateBitOrPointerCast(I, TT.VoidPtrTy),
                 IRB.CreateBitOrPointerCast(Base, TT.VoidPtrTy)});
  }

  setShadow(I, Shadow);
}

void TaintVisitor::visitGetElementPtrInst(GetElementPtrInst &GEPI) {
  TF.visitGEPInst(&GEPI);
}

void TaintVisitor::visitExtractElementInst(ExtractElementInst &I) {
  //FIXME:
}

void TaintVisitor::visitInsertElementInst(InsertElementInst &I) {
  //FIXME:
}

void TaintVisitor::visitShuffleVectorInst(ShuffleVectorInst &I) {
  //FIXME:
}

void TaintVisitor::visitExtractValueInst(ExtractValueInst &I) {
  IRBuilder<> IRB(&I);
  Value *Agg = I.getAggregateOperand();
  Value *AggShadow = TF.getShadow(Agg);
  Value *ResShadow = IRB.CreateExtractValue(AggShadow, I.getIndices());
  TF.setShadow(&I, ResShadow);
}

void TaintVisitor::visitInsertValueInst(InsertValueInst &I) {
  IRBuilder<> IRB(&I);
  Value *AggShadow = TF.getShadow(I.getAggregateOperand());
  Value *InsShadow = TF.getShadow(I.getInsertedValueOperand());
  Value *Res = IRB.CreateInsertValue(AggShadow, InsShadow, I.getIndices());
  TF.setShadow(&I, Res);
}

Value *TaintFunction::visitAllocaInst(AllocaInst *I, Value *ArraySize,
                                      Type *ElTy) {
  // insert after the instruction to get the address
  BasicBlock::iterator ip(I);
  IRBuilder<> IRB(I->getParent(), ++ip);
  // prepare array size
  Value *Size = IRB.CreateZExtOrTrunc(ArraySize, TT.Int64Ty);
  Value *SizeShadow = getShadow(ArraySize);
  // get element size
  Module *M = F->getParent();
  auto &DL = M->getDataLayout();
  uint64_t es = DL.getTypeAllocSize(ElTy);
  ConstantInt *ElemSize = ConstantInt::get(TT.Int64Ty, es);
  // get address
  Value *Address = IRB.CreatePtrToInt(I, TT.Int64Ty);

  return IRB.CreateCall(TT.TaintTraceAllocaFn,
                        {SizeShadow, Size, ElemSize, Address});
}

void TaintVisitor::visitAllocaInst(AllocaInst &I) {
  bool AllLoadsStores = true;
  for (User *U : I.users()) {
    if (isa<LoadInst>(U)) {
      continue;
    }
    if (StoreInst *SI = dyn_cast<StoreInst>(U)) {
      if (SI->getPointerOperand() == &I) {
        continue;
      }
    }

    AllLoadsStores = false;
    break;
  }
  if (AllLoadsStores) {
    IRBuilder<> IRB(&I);
    AllocaInst *AI = IRB.CreateAlloca(TF.TT.getShadowTy(I.getAllocatedType()),
                                      I.getArraySize(), I.getName() + ".taint");
    TF.AllocaShadowMap[&I] = AI;
    if (ClTraceBound) {
      // set shadow to uninit
      IRB.CreateStore(TF.TT.getUninitializedShadow(I.getAllocatedType()), AI);
    }
  }
  if (!ClTraceBound) {
    TF.setShadow(&I, TF.TT.ZeroPrimitiveShadow);
  } else {
    Type *T = I.getAllocatedType();
    Value *ArraySize = I.getArraySize();
    bool TrackBounds = I.isArrayAllocation() | T->isArrayTy() | T->isStructTy();
    if (TrackBounds) {
      // array could be VLA, rely on runtime
      Value *Bounds = TF.visitAllocaInst(&I, ArraySize, T);
      TF.setShadow(&I, Bounds);
    } else {
      TF.setShadow(&I, TF.TT.ZeroPrimitiveShadow); // no bounds
    }
    // set uninit shadow for allocation with constant size
    if (!AllLoadsStores && isa<ConstantInt>(ArraySize)) {
      Value *Init = TF.TT.UninitializedPrimitiveShadow;
      // XXX: skip __va_list_tag, as we don't trace llvm.va_start
      if (ArrayType *AT = dyn_cast<ArrayType>(T)) {
        T = AT->getElementType();
      }
      if (T->isStructTy() &&
          T->getStructName().find("__va_list_tag") != StringRef::npos) {
        // FIXME: don't set uninit, assuming llvm.va_start will be called
        Init = TF.TT.ZeroPrimitiveShadow;
      }
      // handle not all loads and stores cases here
      IRBuilder<> IRB(I.getNextNode());
      auto DL = I.getModule()->getDataLayout();
      auto size = I.getAllocationSizeInBits(DL);
      assert(size != std::nullopt);
      Value *Size =
          ConstantInt::get(TF.TT.IntptrTy, (size->getFixedValue() + 7) >> 3);
      IRB.CreateCall(TF.TT.TaintSetLabelFn,
                     {Init,
                      IRB.CreateBitCast(&I, PointerType::getUnqual(*TF.TT.Ctx)),
                      Size});
    }
  }
}

Value* TaintFunction::visitSelectInst(Value *Cond, Value *TrueShadow,
                                      Value *FalseShadow, SelectInst *I) {
  Value *CondShadow = getShadow(Cond);
  Type *T = I->getType();
  if (!T->isIntegerTy(1)) {
    // most cases
    visitCondition(Cond, I);
    return TrueShadow == FalseShadow ? TrueShadow :
        SelectInst::Create(Cond, TrueShadow, FalseShadow, "", I);
  }

  // special case, when select is used to implement logical AND and OR
  IRBuilder<> IRB(I);
  Cond = IRB.CreateZExt(Cond, TT.Int8Ty);
  Value *TrueVal = IRB.CreateZExt(I->getTrueValue(), TT.Int8Ty);
  Value *FalseVal = IRB.CreateZExt(I->getFalseValue(), TT.Int8Ty);
  ConstantInt *CID = ConstantInt::get(TT.Int32Ty, TT.getInstructionId(I));
  return IRB.CreateCall(TT.TaintTraceSelectFn,
                        {CondShadow, TrueShadow, FalseShadow, Cond,
                         TrueVal, FalseVal, CID});
}

void TaintVisitor::visitSelectInst(SelectInst &I) {
  Value *Condition = I.getCondition();
  Value *TrueShadow = TF.getShadow(I.getTrueValue());
  Value *FalseShadow = TF.getShadow(I.getFalseValue());

  if (isa<VectorType>(Condition->getType())) {
    //FIXME:
    errs() << "WARNING: vector condition in Select" << I << "\n";
    TF.setShadow(&I, TF.TT.ZeroPrimitiveShadow);
  } else {
    Value *ShadowSel =
        TF.visitSelectInst(Condition, TrueShadow, FalseShadow, &I);
    TF.setShadow(&I, ShadowSel);
  }
}

void TaintVisitor::visitMemSetInst(MemSetInst &I) {
  // check bounds before memset
  if (ClTraceBound) {
    TF.checkBounds(I.getDest(), I.getLength(), &I);
  }
  if (ClSolveUB) {
    TF.solveBounds(I.getDest(), I.getLength(), &I);
  }
  IRBuilder<> IRB(&I);
  Value *ValShadow = TF.getShadow(I.getValue());
  IRB.CreateCall(
      TF.TT.TaintSetLabelFn,
      {ValShadow,
       IRB.CreateBitCast(I.getDest(), PointerType::getUnqual(*TF.TT.Ctx)),
       IRB.CreateZExtOrTrunc(I.getLength(), TF.TT.IntptrTy)});
}

void TaintVisitor::visitMemTransferInst(MemTransferInst &I) {
  // check bounds before memcpy
  if (ClTraceBound) {
    TF.checkBounds(I.getDest(), I.getLength(), &I);
    TF.checkBounds(I.getSource(), I.getLength(), &I);
  }
  if (ClSolveUB) {
    TF.solveBounds(I.getDest(), I.getLength(), &I);
    TF.solveBounds(I.getSource(), I.getLength(), &I);
  }
  IRBuilder<> IRB(&I);
  Value *DestShadow = TF.TT.getShadowAddress(I.getDest(), IRB);
  Value *SrcShadow = TF.TT.getShadowAddress(I.getSource(), IRB);
  Value *LenShadow = IRB.CreateMul(
      I.getLength(),
      ConstantInt::get(I.getLength()->getType(), TF.TT.ShadowWidthBytes));
  Type *Int8Ptr = PointerType::getUnqual(*TF.TT.Ctx);
  DestShadow = IRB.CreateBitCast(DestShadow, Int8Ptr);
  SrcShadow = IRB.CreateBitCast(SrcShadow, Int8Ptr);
  auto *MTI = cast<MemTransferInst>(
      IRB.CreateCall(I.getFunctionType(), I.getCalledOperand(),
                     {DestShadow, SrcShadow, LenShadow, I.getVolatileCst()}));
  if (ClPreserveAlignment) {
    MTI->setDestAlignment(((I.getDestAlign()) ? MaybeAlign(Align((I.getDestAlign())->value() * (uint64_t)(TF.TT.ShadowWidthBytes))) : MaybeAlign()));
    MTI->setSourceAlignment(((I.getSourceAlign()) ? MaybeAlign(Align((I.getSourceAlign())->value() * (uint64_t)(TF.TT.ShadowWidthBytes))) : MaybeAlign()));
  } else {
    MTI->setDestAlignment(Align(TF.TT.ShadowWidthBytes));
    MTI->setSourceAlignment(Align(TF.TT.ShadowWidthBytes));
  }
}

static bool isAMustTailRetVal(Value *RetVal) {
  // Tail call may have a bitcast between return.
  if (auto *I = dyn_cast<BitCastInst>(RetVal)) {
    RetVal = I->getOperand(0);
  }
  if (auto *I = dyn_cast<CallInst>(RetVal)) {
    return I->isMustTailCall();
  }
  return false;
}

void TaintVisitor::visitReturnInst(ReturnInst &RI) {
  Value *RV = RI.getReturnValue();
  if (!TF.IsNativeABI && RV) {
    // Don't emit the instrumentation for musttail call returns.
    if (isAMustTailRetVal(RV))
      return;

    Value *S = TF.getShadow(RV);
    IRBuilder<> IRB(&RI);
    Type *RT = TF.F->getFunctionType()->getReturnType();
    unsigned Size = getDataLayout().getTypeAllocSize(TF.TT.getShadowTy(RT));
    if (Size <= RetvalTLSSize) {
      // If the size overflows, stores nothing. At callsite, oversized return
      // shadows are set to zero.
      IRB.CreateAlignedStore(S, TF.getRetvalTLS(RT, IRB), ShadowTLSAlignment);
    }
  }
}

void TaintVisitor::addShadowArguments(Function *F, CallBase &CB,
                                      std::vector<Value *> &Args,
                                      IRBuilder<> &IRB) {
  FunctionType *FT = F->getFunctionType();

  auto *I = CB.arg_begin();

  // Adds non-variable argument shadows.
  for (unsigned N = FT->getNumParams(); N != 0; ++I, --N) {
    // Finds potential shadow for GV
    auto *GV = dyn_cast<GlobalVariable>((*I)->stripPointerCasts());
    Value *Shadow = GV ? TF.getShadowForGlobal(GV, IRB)
                       : TF.getShadow(*I);
    Args.push_back(Shadow); // we don't collapse shadow
  }

  // Adds variable argument shadows.
  if (FT->isVarArg()) {
    auto *LabelVATy = ArrayType::get(TF.TT.PrimitiveShadowTy,
                                     CB.arg_size() - FT->getNumParams());
    auto *LabelVAAlloca =
        new AllocaInst(LabelVATy, getDataLayout().getAllocaAddrSpace(),
                       "labelva", &TF.F->getEntryBlock().front());

    for (unsigned N = 0; I != CB.arg_end(); ++I, ++N) {
      auto LabelVAPtr = IRB.CreateStructGEP(LabelVATy, LabelVAAlloca, N);
      auto *GV = dyn_cast<GlobalVariable>((*I)->stripPointerCasts());
      Value *Shadow = GV ? TF.getShadowForGlobal(GV, IRB)
                         : TF.getShadow(*I);
      IRB.CreateStore(Shadow, LabelVAPtr);
    }

    Args.push_back(IRB.CreateStructGEP(LabelVATy, LabelVAAlloca, 0));
  }

  // Adds the return value shadow.
  Type *RetTy = FT->getReturnType();
  if (!RetTy->isVoidTy()) {
    if (!TF.LabelReturnAlloca) {
      TF.LabelReturnAlloca =
          new AllocaInst(TF.TT.getShadowTy(RetTy), // we dont collapse shadow
                         getDataLayout().getAllocaAddrSpace(),
                         "labelreturn", &TF.F->getEntryBlock().front());
    }
    Args.push_back(TF.LabelReturnAlloca);
  }
}

bool TaintVisitor::visitWrappedCallBase(Function *F, CallBase &CB) {
  IRBuilder<> IRB(&CB);
  Value *Shadow = nullptr;
  FunctionType *FT = F->getFunctionType();
  switch (TF.TT.getWrapperKind(F)) {
  case Taint::WK_Warning:
    CB.setCalledFunction(F);
    IRB.CreateCall(TF.TT.TaintUnimplementedFn,
                   IRB.CreateGlobalStringPtr(F->getName()));
    TF.TT.buildExternWeakCheckIfNeeded(IRB, F);
    TF.setShadow(&CB, TF.TT.getZeroShadow(&CB));
    return true;
  case Taint::WK_Discard:
    CB.setCalledFunction(F);
    TF.TT.buildExternWeakCheckIfNeeded(IRB, F);
    TF.setShadow(&CB, TF.TT.getZeroShadow(&CB));
    return true;
  case Taint::WK_Functional:
    CB.setCalledFunction(F);
    TF.TT.buildExternWeakCheckIfNeeded(IRB, F);
    //FIXME:
    // visitOperandShadowInst(CS);
    return true;
  case Taint::WK_Memcmp: {
    // int memcmp(const void *s1, const void *s2, size_t n)
    assert(CB.arg_size() == 3 && !FT->getReturnType()->isVoidTy());
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    FunctionCallee DfswFn = TF.TT.Mod->getOrInsertFunction("__dfsw_memcmp", CustomFn.TransformedType);

    std::vector<Value *> Args;
    // Add original arguments
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      Args.push_back(CB.getArgOperand(i));
    // Add shadow arguments (including return label pointer)
    addShadowArguments(F, CB, Args, IRB);

    CallInst *CustomCI = IRB.CreateCall(DfswFn, Args);

    // Load return shadow
    LoadInst *LabelLoad = IRB.CreateLoad(TF.TT.getShadowTy(FT->getReturnType()), TF.LabelReturnAlloca);
    TF.setShadow(CustomCI, LabelLoad);

    CB.replaceAllUsesWith(CustomCI);
    CB.eraseFromParent();
    return true;
  }
  case Taint::WK_Strcmp: {
    // int strcmp(const char *s1, const char *s2)
    assert(CB.arg_size() == 2 && !FT->getReturnType()->isVoidTy());
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    FunctionCallee DfswFn = TF.TT.Mod->getOrInsertFunction("__dfsw_strcmp", CustomFn.TransformedType);

    std::vector<Value *> Args;
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      Args.push_back(CB.getArgOperand(i));
    addShadowArguments(F, CB, Args, IRB);

    CallInst *CustomCI = IRB.CreateCall(DfswFn, Args);

    LoadInst *LabelLoad = IRB.CreateLoad(TF.TT.getShadowTy(FT->getReturnType()), TF.LabelReturnAlloca);
    TF.setShadow(CustomCI, LabelLoad);

    CB.replaceAllUsesWith(CustomCI);
    CB.eraseFromParent();
    return true;
  }
  case Taint::WK_Strncmp: {
    // int strncmp(const char *s1, const char *s2, size_t n)
    assert(CB.arg_size() == 3 && !FT->getReturnType()->isVoidTy());
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    FunctionCallee DfswFn = TF.TT.Mod->getOrInsertFunction("__dfsw_strncmp", CustomFn.TransformedType);

    std::vector<Value *> Args;
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      Args.push_back(CB.getArgOperand(i));
    addShadowArguments(F, CB, Args, IRB);

    CallInst *CustomCI = IRB.CreateCall(DfswFn, Args);

    LoadInst *LabelLoad = IRB.CreateLoad(TF.TT.getShadowTy(FT->getReturnType()), TF.LabelReturnAlloca);
    TF.setShadow(CustomCI, LabelLoad);

    CB.replaceAllUsesWith(CustomCI);
    CB.eraseFromParent();
    return true;
  }
  case Taint::WK_Strchr: {
    // char *strchr(char *s, int c)
    assert(CB.arg_size() == 2 && !FT->getReturnType()->isVoidTy());
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    FunctionCallee DfswFn = TF.TT.Mod->getOrInsertFunction("__dfsw_strchr", CustomFn.TransformedType);

    std::vector<Value *> Args;
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      Args.push_back(CB.getArgOperand(i));
    addShadowArguments(F, CB, Args, IRB);

    CallInst *CustomCI = IRB.CreateCall(DfswFn, Args);

    LoadInst *LabelLoad = IRB.CreateLoad(TF.TT.getShadowTy(FT->getReturnType()), TF.LabelReturnAlloca);
    TF.setShadow(CustomCI, LabelLoad);

    CB.replaceAllUsesWith(CustomCI);
    CB.eraseFromParent();
    return true;
  }
  case Taint::WK_Strrchr: {
    // char *strrchr(char *s, int c)
    assert(CB.arg_size() == 2 && !FT->getReturnType()->isVoidTy());
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    FunctionCallee DfswFn = TF.TT.Mod->getOrInsertFunction("__dfsw_strrchr", CustomFn.TransformedType);

    std::vector<Value *> Args;
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      Args.push_back(CB.getArgOperand(i));
    addShadowArguments(F, CB, Args, IRB);

    CallInst *CustomCI = IRB.CreateCall(DfswFn, Args);

    LoadInst *LabelLoad = IRB.CreateLoad(TF.TT.getShadowTy(FT->getReturnType()), TF.LabelReturnAlloca);
    TF.setShadow(CustomCI, LabelLoad);

    CB.replaceAllUsesWith(CustomCI);
    CB.eraseFromParent();
    return true;
  }
  case Taint::WK_Strstr: {
    // char *strstr(char *haystack, char *needle)
    assert(CB.arg_size() == 2 && !FT->getReturnType()->isVoidTy());
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    FunctionCallee DfswFn = TF.TT.Mod->getOrInsertFunction("__dfsw_strstr", CustomFn.TransformedType);

    std::vector<Value *> Args;
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      Args.push_back(CB.getArgOperand(i));
    addShadowArguments(F, CB, Args, IRB);

    CallInst *CustomCI = IRB.CreateCall(DfswFn, Args);

    LoadInst *LabelLoad = IRB.CreateLoad(TF.TT.getShadowTy(FT->getReturnType()), TF.LabelReturnAlloca);
    TF.setShadow(CustomCI, LabelLoad);

    CB.replaceAllUsesWith(CustomCI);
    CB.eraseFromParent();
    return true;
  }
  case Taint::WK_Prefixof: {
    // int prefixof(const char *str, const char *prefix)
    assert(CB.arg_size() == 2 && !FT->getReturnType()->isVoidTy());
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    FunctionCallee DfswFn = TF.TT.Mod->getOrInsertFunction("__dfsw_prefixof", CustomFn.TransformedType);

    std::vector<Value *> Args;
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      Args.push_back(CB.getArgOperand(i));
    addShadowArguments(F, CB, Args, IRB);

    CallInst *CustomCI = IRB.CreateCall(DfswFn, Args);

    LoadInst *LabelLoad = IRB.CreateLoad(TF.TT.getShadowTy(FT->getReturnType()), TF.LabelReturnAlloca);
    TF.setShadow(CustomCI, LabelLoad);

    CB.replaceAllUsesWith(CustomCI);
    CB.eraseFromParent();
    return true;
  }
  case Taint::WK_Suffixof: {
    // int suffixof(const char *str, const char *suffix)
    assert(CB.arg_size() == 2 && !FT->getReturnType()->isVoidTy());
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    FunctionCallee DfswFn = TF.TT.Mod->getOrInsertFunction("__dfsw_suffixof", CustomFn.TransformedType);

    std::vector<Value *> Args;
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      Args.push_back(CB.getArgOperand(i));
    addShadowArguments(F, CB, Args, IRB);

    CallInst *CustomCI = IRB.CreateCall(DfswFn, Args);

    LoadInst *LabelLoad = IRB.CreateLoad(TF.TT.getShadowTy(FT->getReturnType()), TF.LabelReturnAlloca);
    TF.setShadow(CustomCI, LabelLoad);

    CB.replaceAllUsesWith(CustomCI);
    CB.eraseFromParent();
    return true;
  }
  case Taint::WK_Strcat: {
    // char *strcat(char *dest, const char *src)
    assert(CB.arg_size() == 2 && !FT->getReturnType()->isVoidTy());
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    FunctionCallee DfswFn = TF.TT.Mod->getOrInsertFunction("__dfsw_strcat", CustomFn.TransformedType);

    std::vector<Value *> Args;
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      Args.push_back(CB.getArgOperand(i));
    addShadowArguments(F, CB, Args, IRB);

    CallInst *CustomCI = IRB.CreateCall(DfswFn, Args);

    LoadInst *LabelLoad = IRB.CreateLoad(TF.TT.getShadowTy(FT->getReturnType()), TF.LabelReturnAlloca);
    TF.setShadow(CustomCI, LabelLoad);

    CB.replaceAllUsesWith(CustomCI);
    CB.eraseFromParent();
    return true;
  }
  case Taint::WK_Strsub: {
    // char *strsub(char *s, size_t len)
    assert(CB.arg_size() == 3 && !FT->getReturnType()->isVoidTy());
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    FunctionCallee DfswFn = TF.TT.Mod->getOrInsertFunction("__dfsw_strsub", CustomFn.TransformedType);

    std::vector<Value *> Args;
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      Args.push_back(CB.getArgOperand(i));
    addShadowArguments(F, CB, Args, IRB);

    CallInst *CustomCI = IRB.CreateCall(DfswFn, Args);

    LoadInst *LabelLoad = IRB.CreateLoad(TF.TT.getShadowTy(FT->getReturnType()), TF.LabelReturnAlloca);
    TF.setShadow(CustomCI, LabelLoad);

    CB.replaceAllUsesWith(CustomCI);
    CB.eraseFromParent();
    return true;
  }
  case Taint::WK_Custom:
    // Don't try to handle invokes of custom functions, it's too complicated.
    // Instead, invoke the dfsw$ wrapper, which will in turn call the __dfsw_
    // wrapper.
    CallInst *CI = dyn_cast<CallInst>(&CB);
    if (!CI)
      return false;

    FunctionType *FT = F->getFunctionType();
    TransformedFunction CustomFn = TF.TT.getCustomFunctionType(FT);
    std::string CustomFName = "__dfsw_";
    CustomFName += F->getName();
    FunctionCallee CustomF =
        TF.TT.Mod->getOrInsertFunction(CustomFName, CustomFn.TransformedType);
    if (Function *CustomFn = dyn_cast<Function>(CustomF.getCallee())) {
      CustomFn->copyAttributesFrom(F);

      // Custom functions returning non-void will write to the return label.
      if (!FT->getReturnType()->isVoidTy()) {
        CustomFn->removeFnAttrs(TF.TT.ReadOnlyNoneAttrs);
      }
    }

    std::vector<Value *> Args;

    // Adds non-variable arguments.
    auto *I = CB.arg_begin();
    for (unsigned N = FT->getNumParams(); N != 0; ++I, --N) {
      // Opaque pointers: cannot recover a function pointee type, so custom-
      // wrapper trampolines are gone; pass the argument through unchanged.
      Args.push_back(*I);
    }

    // Adds shadow arguments.
    const unsigned ShadowArgStart = Args.size();
    addShadowArguments(F, CB, Args, IRB);

    // Adds variable arguments.
    append_range(Args, drop_begin(CB.args(), FT->getNumParams()));

    CallInst *CustomCI = IRB.CreateCall(CustomF, Args);
    CustomCI->setCallingConv(CI->getCallingConv());
    CustomCI->setAttributes(TransformFunctionAttributes(
        CustomFn, CI->getContext(), CI->getAttributes()));

    // Update the parameter attributes of the custom call instruction to
    // zero extend the shadow parameters. This is required for targets
    // which consider ShadowTy an illegal type.
    for (unsigned N = 0; N < FT->getNumParams(); N++) {
      const unsigned ArgNo = ShadowArgStart + N;
      if (CustomCI->getArgOperand(ArgNo)->getType() ==
          TF.TT.PrimitiveShadowTy) {
        CustomCI->addParamAttr(ArgNo, Attribute::ZExt);
      }
    }

    // Loads the return value shadow and origin.
    Type *RetTy = FT->getReturnType();
    if (!RetTy->isVoidTy()) {
      // we don't collapse shadow
      LoadInst *LabelLoad =
          IRB.CreateLoad(TF.TT.getShadowTy(RetTy), TF.LabelReturnAlloca);
      TF.setShadow(CustomCI, LabelLoad);

    }

    CI->replaceAllUsesWith(CustomCI);
    CI->eraseFromParent();
    return true;
  }
  return false;
}

void TaintVisitor::visitIntrinsicCallBase(Function *F, CallBase &CB) {
  // filter some obvious ones
  StringRef FN = F->getName();

  // Constrained FP intrinsics (llvm.experimental.constrained.*) carry an
  // explicit rounding-mode operand.  Default (non-strict) compilation never
  // emits them -- plain fadd/fmul/... are round-to-nearest -- but targets built
  // with strict FP / FENV_ACCESS (e.g. code that calls fesetround) do.  Capture
  // them HERE, before the blanket "llvm.experimental" filter below drops all
  // taint, so the solver sees rounding-mode-correct arithmetic.  The rounding
  // selector is packed into the high byte of `op` (the same slot cmp uses for
  // its predicate; FP arithmetic never carries a predicate).  A compile-time
  // constant mode packs a constant; the common round.dynamic case reads the live
  // MXCSR via @llvm.get.rounding at runtime and ORs the mapped selector into
  // `op` -- so `op` is a runtime value there, not a constant.  This mirrors what
  // the SMT-LIB benchmark path (driver/smttest.cpp) already carries in
  // AstNode::index(); the read sides are parsers/rgd-parser.cpp (RGD/jigsaw) and
  // solvers/z3-ts.cpp (fgtest union-table path).
  if (ClTraceFP) {
    Intrinsic::ID CId = F->getIntrinsicID();

    // Constrained fcmp/fcmps: comparisons don't round, but strict FP lowers even
    // `a < b` to these intrinsics, so without capturing them the branch loses all
    // taint.  Model exactly like a regular fcmp (combineCmpInstShadows): op =
    // FCmp with the LLVM predicate in the high byte, op1/op2 = operand bit
    // patterns, size = operand width.  (fcmps is the signaling variant; the
    // quiet/signaling distinction is a NaN-exception detail, irrelevant here.)
    if (CId == Intrinsic::experimental_constrained_fcmp ||
        CId == Intrinsic::experimental_constrained_fcmps) {
      Value *S1 = TF.getShadow(CB.getArgOperand(0));
      Value *S2 = TF.getShadow(CB.getArgOperand(1));
      if (TF.TT.isZeroShadow(S1) && TF.TT.isZeroShadow(S2))
        return;
      Type *OpTy = CB.getArgOperand(0)->getType();
      if (OpTy->getScalarType()->getPrimitiveSizeInBits() <= 64) {
        IRBuilder<> IRB(&CB);
        auto &DL = CB.getModule()->getDataLayout();
        uint64_t Size = DL.getTypeSizeInBits(OpTy);
        uint16_t Pred =
            (uint16_t)cast<ConstrainedFPCmpIntrinsic>(&CB)->getPredicate();
        uint16_t OpV = (uint16_t)Instruction::FCmp | (Pred << 8);
        auto FpToInt = [&](Value *V) -> Value * {
          Type *Ty = V->getType();
          if (Ty->isHalfTy())        V = IRB.CreateBitCast(V, TF.TT.Int16Ty);
          else if (Ty->isFloatTy())  V = IRB.CreateBitCast(V, TF.TT.Int32Ty);
          else if (Ty->isDoubleTy()) V = IRB.CreateBitCast(V, TF.TT.Int64Ty);
          return IRB.CreateZExtOrTrunc(V, TF.TT.Int64Ty);
        };
        CallInst *C = IRB.CreateCall(
            TF.TT.TaintUnionFn,
            {S1, S2, ConstantInt::get(TF.TT.Int16Ty, OpV),
             ConstantInt::get(TF.TT.Int16Ty, Size),
             FpToInt(CB.getArgOperand(0)), FpToInt(CB.getArgOperand(1))});
        C->addRetAttr(Attribute::ZExt);
        C->addParamAttr(0, Attribute::ZExt);
        C->addParamAttr(1, Attribute::ZExt);
        TF.setShadow(&CB, C);
        return;
      }
    }
  }

  if (ClTraceFP && CB.getType()->isFloatingPointTy() &&
      CB.getType()->getScalarType()->getPrimitiveSizeInBits() <= 64) {
    Intrinsic::ID CId = F->getIntrinsicID();
    uint16_t CFpOp = 0;         // base opcode (LLVM opcode for arith; fp_sqrt)
    bool CBinary = false, CIsSqrt = false, CTernary = false;
    switch (CId) {
      case Intrinsic::experimental_constrained_fadd:
        CFpOp = Instruction::FAdd; CBinary = true; break;
      case Intrinsic::experimental_constrained_fsub:
        CFpOp = Instruction::FSub; CBinary = true; break;
      case Intrinsic::experimental_constrained_fmul:
        CFpOp = Instruction::FMul; CBinary = true; break;
      case Intrinsic::experimental_constrained_fdiv:
        CFpOp = Instruction::FDiv; CBinary = true; break;
      case Intrinsic::experimental_constrained_sqrt:
        CFpOp = DfsanFpSqrt; CIsSqrt = true; break;
      case Intrinsic::experimental_constrained_fmuladd:
        CTernary = true; break;  // a*b + c, decomposed to FMul then FAdd
      default: break;
    }
    if (CFpOp != 0 || CTernary) {
      // Only the FP operands carry taint; the trailing metadata operands
      // (rounding mode + exception behavior) never do, so check just those.
      unsigned NumFp = CTernary ? 3 : (CBinary ? 2 : 1);
      bool NeedInst = false;
      for (unsigned I = 0; I < NumFp; ++I) {
        if (!TF.TT.isZeroShadow(TF.getShadow(CB.getArgOperand(I)))) {
          NeedInst = true;
          break;
        }
      }
      if (!NeedInst)
        return;

      IRBuilder<> IRB(&CB);
      auto &DL = CB.getModule()->getDataLayout();
      uint64_t Size = DL.getTypeSizeInBits(CB.getType());
      // FP operands are bitcast to same-width integers before the union call,
      // matching combineShadows().
      auto FpToInt = [&](Value *V) -> Value * {
        Type *Ty = V->getType();
        if (Ty->isHalfTy())        V = IRB.CreateBitCast(V, TF.TT.Int16Ty);
        else if (Ty->isFloatTy())  V = IRB.CreateBitCast(V, TF.TT.Int32Ty);
        else if (Ty->isDoubleTy()) V = IRB.CreateBitCast(V, TF.TT.Int64Ty);
        return IRB.CreateZExtOrTrunc(V, TF.TT.Int64Ty);
      };
      // Map an LLVM compile-time RoundingMode to the dfsan fp_rounding_mode
      // selector, or -1 when it is round.dynamic / unknown (resolve at runtime).
      auto StaticSel = [&](std::optional<RoundingMode> RM) -> int {
        if (!RM.has_value())
          return -1;
        switch (*RM) {
          case RoundingMode::NearestTiesToEven: return DfsanFpRmRne; // 1
          case RoundingMode::TowardPositive:    return DfsanFpRmRtp; // 2
          case RoundingMode::TowardNegative:    return DfsanFpRmRtn; // 3
          case RoundingMode::TowardZero:        return DfsanFpRmRtz; // 4
          case RoundingMode::NearestTiesToAway: return DfsanFpRmRna; // 0
          default:                              return -1; // Dynamic/Invalid
        }
      };
      std::optional<RoundingMode> RM =
          cast<ConstrainedFPIntrinsic>(&CB)->getRoundingMode();
      int Sel = StaticSel(RM);
      // Build the packed `op` value (i16) for a given base opcode, folding the
      // rounding selector into the high byte.
      auto PackedOp = [&](uint16_t Base) -> Value * {
        if (Sel >= 0)
          return ConstantInt::get(TF.TT.Int16Ty,
                                  Base | (uint16_t(Sel) << 8));
        // round.dynamic: read the live rounding mode (FLT_ROUNDS encoding) and
        // map it to our selector, then OR into the high byte at runtime.
        // FLT_ROUNDS: 0=toward-zero, 1=to-nearest, 2=toward+inf, 3=toward-inf,
        //             4=to-nearest-away.  Default (incl. -1/indeterminate) -> RNE.
        Value *Fr = IRB.CreateIntrinsic(Intrinsic::get_rounding, {}, {});
        Type *Ity = Fr->getType();
        auto C = [&](int v) { return ConstantInt::get(Ity, v); };
        Value *S = C(DfsanFpRmRne);
        S = IRB.CreateSelect(IRB.CreateICmpEQ(Fr, C(4)), C(DfsanFpRmRna), S);
        S = IRB.CreateSelect(IRB.CreateICmpEQ(Fr, C(3)), C(DfsanFpRmRtn), S);
        S = IRB.CreateSelect(IRB.CreateICmpEQ(Fr, C(2)), C(DfsanFpRmRtp), S);
        S = IRB.CreateSelect(IRB.CreateICmpEQ(Fr, C(0)), C(DfsanFpRmRtz), S);
        Value *S16 = IRB.CreateZExtOrTrunc(S, TF.TT.Int16Ty);
        Value *Hi  = IRB.CreateShl(S16, ConstantInt::get(TF.TT.Int16Ty, 8));
        return IRB.CreateOr(Hi, ConstantInt::get(TF.TT.Int16Ty, Base));
      };
      auto MakeUnion = [&](Value *L1, Value *L2, Value *Op16,
                           Value *O1, Value *O2) -> Value * {
        CallInst *C = IRB.CreateCall(
            TF.TT.TaintUnionFn,
            {L1, L2, Op16, ConstantInt::get(TF.TT.Int16Ty, Size), O1, O2});
        C->addRetAttr(Attribute::ZExt);
        C->addParamAttr(0, Attribute::ZExt);
        C->addParamAttr(1, Attribute::ZExt);
        return C;
      };
      Value *Zero64 = ConstantInt::get(TF.TT.Int64Ty, 0);
      if (CBinary) {
        Value *Res = MakeUnion(TF.getShadow(CB.getArgOperand(0)),
                               TF.getShadow(CB.getArgOperand(1)), PackedOp(CFpOp),
                               FpToInt(CB.getArgOperand(0)),
                               FpToInt(CB.getArgOperand(1)));
        TF.setShadow(&CB, Res);
        return;
      }
      if (CIsSqrt) {
        // unary; l2 = 0.  The operand value is unused (an instrumented unary
        // intrinsic always has a symbolic operand), but pass it for symmetry.
        Value *Res = MakeUnion(TF.getShadow(CB.getArgOperand(0)),
                               TF.TT.ZeroPrimitiveShadow, PackedOp(DfsanFpSqrt),
                               FpToInt(CB.getArgOperand(0)), Zero64);
        TF.setShadow(&CB, Res);
        return;
      }
      if (CTernary) {
        // constrained fmuladd: a*b + c.  Decompose into FMul then FAdd, both
        // carrying the rounding selector (double-rounds vs a true fused op, but
        // the <=1-ULP difference is immaterial for branch flipping), matching
        // the non-constrained fma/fmuladd handling below.
        Value *SA = TF.getShadow(CB.getArgOperand(0));
        Value *SB = TF.getShadow(CB.getArgOperand(1));
        Value *SC = TF.getShadow(CB.getArgOperand(2));
        Value *Mul = MakeUnion(SA, SB, PackedOp(Instruction::FMul),
                               FpToInt(CB.getArgOperand(0)),
                               FpToInt(CB.getArgOperand(1)));
        Value *Res = MakeUnion(Mul, SC, PackedOp(Instruction::FAdd), Zero64,
                               FpToInt(CB.getArgOperand(2)));
        TF.setShadow(&CB, Res);
        return;
      }
    }
  }

  if ((FN).starts_with("llvm.va_") || // varabile length
      (FN).starts_with("llvm.gc")  || // garbaage collection
      (FN).starts_with("llvm.experimental") ||
      (FN).starts_with("llvm.lifetime")
     ) {
    return;
  }
  // intrinsic, check argument
  bool NeedsInstrumentation = false;
  for (unsigned I = 0, N = CB.arg_size(); I < N; ++I) {
    Value *Shadow = TF.getShadow(CB.getArgOperand(I));
    if (!TF.TT.isZeroShadow(Shadow)) {
      NeedsInstrumentation = true;
      break;
    }
  }
  if (!NeedsInstrumentation)
    return;

  Intrinsic::ID IId = F->getIntrinsicID();

  // bswap: decompose into Extract-per-byte then Concat in reverse order.
  // __taint_union(l1=low, l2=high, Concat) → z3::concat(high, low) (little-endian)
  if (IId == Intrinsic::bswap) {
    Value *Shadow = TF.getShadow(CB.getArgOperand(0));
    unsigned TotalBits = CB.getArgOperand(0)->getType()->getIntegerBitWidth();
    unsigned NumBytes = TotalBits / 8;

    // Extract = last_llvm_op + 4 = 71, Concat = last_llvm_op + 5 = 72 (for LLVM 14)
    const uint16_t OpExtract = 71;
    const uint16_t OpConcat  = 72;

    IRBuilder<> IRB(&CB);
    Value *ZeroShadow = TF.TT.ZeroPrimitiveShadow;
    Value *ExtractOp = ConstantInt::get(TF.TT.Int16Ty, OpExtract);
    Value *ConcatOp  = ConstantInt::get(TF.TT.Int16Ty, OpConcat);
    Value *ByteSize  = ConstantInt::get(TF.TT.Int16Ty, 8);
    Value *Zero64    = ConstantInt::get(TF.TT.Int64Ty, 0);

    auto MakeUnionCall = [&](Value *L1, Value *L2, Value *Op, Value *Size,
                             Value *Op1, Value *Op2) -> Value * {
      CallInst *C = IRB.CreateCall(TF.TT.TaintUnionFn, {L1, L2, Op, Size, Op1, Op2});
      C->addRetAttr(Attribute::ZExt);
      C->addParamAttr(0, Attribute::ZExt);
      C->addParamAttr(1, Attribute::ZExt);
      return C;
    };

    // Extract byte i → input bits [i*8+7 : i*8]
    SmallVector<Value *, 8> ByteLabels(NumBytes);
    for (unsigned I = 0; I < NumBytes; ++I)
      ByteLabels[I] = MakeUnionCall(Shadow, ZeroShadow, ExtractOp, ByteSize,
                                    Zero64, ConstantInt::get(TF.TT.Int64Ty, I * 8));

    // Concat reversed: result LSB = input byte[NumBytes-1], MSB = input byte[0]
    // Build: z3::concat(byte[0], concat(byte[1], ... concat(byte[N-2], byte[N-1])...))
    // Using __taint_union(l1=low, l2=high) → z3::concat(l2, l1)
    Value *Result = ByteLabels[NumBytes - 1];
    unsigned AccumBits = 8;
    for (int I = (int)NumBytes - 2; I >= 0; --I) {
      AccumBits += 8;
      Value *CSize = ConstantInt::get(TF.TT.Int16Ty, AccumBits);
      Result = MakeUnionCall(Result, ByteLabels[I], ConcatOp, CSize, Zero64, Zero64);
    }

    TF.setShadow(&CB, Result);
    return;
  }

  // bitreverse: one op node, not a decomposition.  Reversing an i64 the way
  // bswap is handled above would take 64 Extracts plus 63 Concats per dynamic
  // execution, and clang's idiom recognizer turns the reflection loop of every
  // reflected CRC into an @llvm.bitreverse.i8 per message byte -- so the
  // decomposition would be paid thousands of times per trace.  The solvers
  // expand it instead: z3 as a concat of single-bit extracts, jigsaw as the
  // native intrinsic.  Without this the shadow is dropped and the whole message
  // silently goes concrete (see tests/symsan/bitreverse*.c).
  if (IId == Intrinsic::bitreverse) {
    Value *Arg = CB.getArgOperand(0);
    Type *ArgTy = Arg->getType();
    // The intrinsic is also defined on vectors, and getIntegerBitWidth() is a
    // cast<IntegerType> away from asserting on one, so ask before assuming.
    if (ArgTy->isIntegerTy() && ArgTy->getIntegerBitWidth() <= 64) {
      unsigned Bits = ArgTy->getIntegerBitWidth();
      Value *Shadow = TF.getShadow(Arg);
      IRBuilder<> IRB(&CB);
      CallInst *C = IRB.CreateCall(
          TF.TT.TaintUnionFn,
          {Shadow, TF.TT.ZeroPrimitiveShadow,
           ConstantInt::get(TF.TT.Int16Ty, DfsanBitReverse),
           ConstantInt::get(TF.TT.Int16Ty, Bits),
           IRB.CreateZExtOrTrunc(Arg, TF.TT.Int64Ty),
           ConstantInt::get(TF.TT.Int64Ty, 0)});
      C->addRetAttr(Attribute::ZExt);
      C->addParamAttr(0, Attribute::ZExt);
      C->addParamAttr(1, Attribute::ZExt);
      TF.setShadow(&CB, C);
      return;
    }
    // A vector, or wider than a label's op1 slot: fall through and drop the
    // shadow, the way this file already does for everything it cannot model.
  }

  // Floating-point intrinsics: map to the self-defined FP ops so the z3 solver
  // can reconstruct them via the fpa theory.  Only modeled under ClTraceFP.
  if (ClTraceFP) {
    // fma / fmuladd compute a*b + c.  A label node holds only two operands, so
    // model the ternary by decomposition into FMul then FAdd, reusing the
    // existing FP-arith solver support.  This double-rounds relative to a true
    // fused multiply-add, but the (at most 1-ULP) difference is immaterial for
    // branch flipping.  This path is essential, not optional: clang contracts
    // the extremely common source pattern `a*b±c` into @llvm.fmuladd by default
    // (-ffp-contract=on) even at -O0, so without this those branches vanish.
    if ((IId == Intrinsic::fma || IId == Intrinsic::fmuladd) &&
        CB.getType()->isFloatingPointTy()) {
      IRBuilder<> IRB(&CB);
      auto &DL = CB.getModule()->getDataLayout();
      uint64_t Size = DL.getTypeSizeInBits(CB.getType());
      Value *SA = TF.getShadow(CB.getArgOperand(0));
      Value *SB = TF.getShadow(CB.getArgOperand(1));
      Value *SC = TF.getShadow(CB.getArgOperand(2));
      if (Size <= 64 &&
          !(TF.TT.isZeroShadow(SA) && TF.TT.isZeroShadow(SB) &&
            TF.TT.isZeroShadow(SC))) {
        auto FpToInt = [&](Value *V) -> Value * {
          Type *Ty = V->getType();
          if (Ty->isHalfTy())        V = IRB.CreateBitCast(V, TF.TT.Int16Ty);
          else if (Ty->isFloatTy())  V = IRB.CreateBitCast(V, TF.TT.Int32Ty);
          else if (Ty->isDoubleTy()) V = IRB.CreateBitCast(V, TF.TT.Int64Ty);
          return IRB.CreateZExtOrTrunc(V, TF.TT.Int64Ty);
        };
        auto MakeUnion = [&](Value *L1, Value *L2, uint16_t Op,
                             Value *O1, Value *O2) -> Value * {
          CallInst *C = IRB.CreateCall(
              TF.TT.TaintUnionFn,
              {L1, L2, ConstantInt::get(TF.TT.Int16Ty, Op),
               ConstantInt::get(TF.TT.Int16Ty, Size), O1, O2});
          C->addRetAttr(Attribute::ZExt);
          C->addParamAttr(0, Attribute::ZExt);
          C->addParamAttr(1, Attribute::ZExt);
          return C;
        };
        Value *Zero64 = ConstantInt::get(TF.TT.Int64Ty, 0);
        // mul = a * b  (LLVM opcodes match the __dfsan operators enum)
        Value *Mul = MakeUnion(SA, SB, Instruction::FMul,
                               FpToInt(CB.getArgOperand(0)),
                               FpToInt(CB.getArgOperand(1)));
        // result = mul + c.  The mul result is symbolic, so its op1 slot is
        // zeroed by the runtime anyway; the solver recomputes it from value_cache.
        Value *Res = MakeUnion(Mul, SC, Instruction::FAdd, Zero64,
                               FpToInt(CB.getArgOperand(2)));
        TF.setShadow(&CB, Res);
        return;
      }
    }
    uint16_t FpOp = 0;
    uint64_t RoundingMode = 0; // rounding selector for fp_round (carried in op1)
    bool IsBinary = false;
    switch (IId) {
      case Intrinsic::fabs:      FpOp = DfsanFpFabs; break;
      case Intrinsic::sqrt:      FpOp = DfsanFpSqrt; break;
      case Intrinsic::floor:     FpOp = DfsanFpRound; RoundingMode = DfsanFpRmRtn; break;
      case Intrinsic::ceil:      FpOp = DfsanFpRound; RoundingMode = DfsanFpRmRtp; break;
      case Intrinsic::trunc:     FpOp = DfsanFpRound; RoundingMode = DfsanFpRmRtz; break;
      case Intrinsic::round:     FpOp = DfsanFpRound; RoundingMode = DfsanFpRmRna; break;
      case Intrinsic::rint:      FpOp = DfsanFpRound; RoundingMode = DfsanFpRmRne; break;
      case Intrinsic::nearbyint: FpOp = DfsanFpRound; RoundingMode = DfsanFpRmRne; break;
      case Intrinsic::minnum:    FpOp = DfsanFpMin; IsBinary = true; break;
      case Intrinsic::maxnum:    FpOp = DfsanFpMax; IsBinary = true; break;
      case Intrinsic::copysign:  FpOp = DfsanFpCopysign; IsBinary = true; break;
      // fma / fmuladd (3 operands) are handled above by decomposition.
      default: break;
    }
    if (FpOp != 0 && CB.getType()->isFloatingPointTy()) {
      IRBuilder<> IRB(&CB);
      auto &DL = CB.getModule()->getDataLayout();
      uint64_t Size = DL.getTypeSizeInBits(CB.getType());
      // FP operands are bitcast to same-width integers before the union call,
      // matching combineShadows().
      auto FpToInt = [&](Value *V) -> Value * {
        Type *Ty = V->getType();
        if (Ty->isHalfTy())        V = IRB.CreateBitCast(V, TF.TT.Int16Ty);
        else if (Ty->isFloatTy())  V = IRB.CreateBitCast(V, TF.TT.Int32Ty);
        else if (Ty->isDoubleTy()) V = IRB.CreateBitCast(V, TF.TT.Int64Ty);
        return IRB.CreateZExtOrTrunc(V, TF.TT.Int64Ty);
      };
      Value *Op = ConstantInt::get(TF.TT.Int16Ty, FpOp);
      Value *SizeV = ConstantInt::get(TF.TT.Int16Ty, Size);
      Value *Shadow1 = TF.getShadow(CB.getArgOperand(0));
      Value *Result = nullptr;
      if (IsBinary) {
        Value *Shadow2 = TF.getShadow(CB.getArgOperand(1));
        Value *Op1 = FpToInt(CB.getArgOperand(0));
        Value *Op2 = FpToInt(CB.getArgOperand(1));
        CallInst *C = IRB.CreateCall(TF.TT.TaintUnionFn,
                                     {Shadow1, Shadow2, Op, SizeV, Op1, Op2});
        C->addRetAttr(Attribute::ZExt);
        C->addParamAttr(0, Attribute::ZExt);
        C->addParamAttr(1, Attribute::ZExt);
        Result = C;
      } else {
        // unary; l2 = 0.  For fp_round the rounding selector is carried in op1
        // (the operand value is unused: an instrumented unary intrinsic always
        // has a symbolic operand, so the solver rebuilds it from l1).
        Value *Op1 = (FpOp == DfsanFpRound)
                         ? ConstantInt::get(TF.TT.Int64Ty, RoundingMode)
                         : FpToInt(CB.getArgOperand(0));
        Value *Op2 = ConstantInt::get(TF.TT.Int64Ty, 0);
        CallInst *C = IRB.CreateCall(
            TF.TT.TaintUnionFn,
            {Shadow1, TF.TT.ZeroPrimitiveShadow, Op, SizeV, Op1, Op2});
        C->addRetAttr(Attribute::ZExt);
        C->addParamAttr(0, Attribute::ZExt);
        C->addParamAttr(1, Attribute::ZExt);
        Result = C;
      }
      TF.setShadow(&CB, Result);
      return;
    }
  }

  // Other intrinsics: symbolic propagation not yet implemented — skip.
}

void TaintVisitor::visitCallBase(CallBase &CB) {
  if (CB.isInlineAsm()) {
    // FIXME: inline asm
    return;
  }

  // handle intrinsics
  Function *F = CB.getCalledFunction();
  if (F && F->isIntrinsic()) {
    visitIntrinsicCallBase(F, CB);
    return;
  }

  // handle ucsan_check_pointer / ucsan_uncheck_pointer: both return a pointer
  // that aliases their first argument (real<->pseudo translation), so the
  // symsan taint label flows straight through from arg 0.
  if (F && ClWithUCSan &&
      (F->getName().equals("ucsan_check_pointer") ||
       F->getName().equals("ucsan_uncheck_pointer"))) {
    // just propagate the label
    Value *Shadow = TF.getShadow(CB.getArgOperand(0));
    if (!TF.TT.isZeroShadow(Shadow)) {
      TF.setShadow(&CB, Shadow);
    }
    return;
  }

  // Calls to this function are synthesized in wrappers, and we shouldn't
  // instrument them.
  if (F == TF.TT.TaintVarargWrapperFn.getCallee()->stripPointerCasts())
    return;

  IRBuilder<> IRB(&CB);

  // trace indirect call
  bool isUCSanCheckedIndirectCall = false;
  if (CB.getCalledFunction() == nullptr) {
    Value *Shadow = TF.getShadow(CB.getCalledOperand());
    if (!TF.TT.isZeroShadow(Shadow))
      IRB.CreateCall(TF.TT.TaintTraceIndirectCallFn, {Shadow});

    // Check if the function pointer is from UCSan (ucsan_check_pointer)
    Value *FPtr = CB.getCalledOperand()->stripPointerCasts();
    auto *FPtrInst = dyn_cast<Instruction>(FPtr);
    if (ClWithUCSan || (FPtrInst && FPtrInst->getMetadata("ucsan.checked"))) {
      isUCSanCheckedIndirectCall = true;
    }
  }

  DenseMap<Value *, Function *>::iterator UnwrappedFnIt =
      TF.TT.UnwrappedFnMap.find(CB.getCalledOperand());
  if (UnwrappedFnIt != TF.TT.UnwrappedFnMap.end()) {
    if (visitWrappedCallBase(UnwrappedFnIt->second, CB))
      return;
  }

  // reset IRB
  IRB.SetInsertPoint(&CB);

  FunctionType *FT = CB.getFunctionType();
  const DataLayout &DL = getDataLayout();

  // Stores argument shadows.
  unsigned ArgOffset = 0;
  for (unsigned I = 0, N = FT->getNumParams(); I != N; ++I) {
    unsigned Size =
        DL.getTypeAllocSize(TF.TT.getShadowTy(FT->getParamType(I)));
    // Stop storing if arguments' size overflows. Inside a function, arguments
    // after overflow have zero shadow values.
    if (ArgOffset + Size > ArgTLSSize)
      break;
    Value *Arg = CB.getArgOperand(I);
    auto *GV = dyn_cast<GlobalVariable>(Arg->stripPointerCasts());
    Value *Shadow = GV ? TF.getShadowForGlobal(GV, IRB)
                       : TF.getShadow(Arg);
    IRB.CreateAlignedStore(Shadow,
                           TF.getArgTLS(FT->getParamType(I), ArgOffset, IRB),
                           ShadowTLSAlignment);
    ArgOffset += alignTo(Size, ShadowTLSAlignment);
  }

  Instruction *Next = nullptr;
  if (!CB.getType()->isVoidTy()) {
    // For UCSan-checked indirect calls, find the PHINode introduced by UCSanPass.
    // The return value may come from either the actual call or ucsan_wrap_retval,
    // merged via a PHINode. We need to load the shadow after the PHINode.
    PHINode *RetPhiNode = nullptr;
    Instruction *ShadowTarget = &CB;
    if (isUCSanCheckedIndirectCall) {
      for (User *U : CB.users()) {
        if (PHINode *PN = dyn_cast<PHINode>(U)) {
          RetPhiNode = PN;
          ShadowTarget = PN;
          break;
        }
      }
    }

    if (InvokeInst *II = dyn_cast<InvokeInst>(&CB)) {
      if (II->getNormalDest()->getSinglePredecessor()) {
        Next = &II->getNormalDest()->front();
      } else {
        BasicBlock *NewBB =
            SplitEdge(II->getParent(), II->getNormalDest(), &TF.DT);
        Next = &NewBB->front();
      }
    } else {
      assert(CB.getIterator() != CB.getParent()->end());
      if (RetPhiNode) {
        // Load shadow after the PHINode
        Next = RetPhiNode->getParent()->getFirstNonPHI();
      } else {
        Next = CB.getNextNode();
      }
    }

    // Don't emit the epilogue for musttail call returns.
    if (isa<CallInst>(CB) && cast<CallInst>(CB).isMustTailCall())
      return;

    // Loads the return value shadow.
    IRBuilder<> NextIRB(Next);
    unsigned Size = DL.getTypeAllocSize(TF.TT.getShadowTy(&CB));
    if (Size > RetvalTLSSize) {
      // Set overflowed return shadow to be zero.
      TF.setShadow(ShadowTarget, TF.TT.getZeroShadow(&CB));
    } else {
      LoadInst *LI = NextIRB.CreateAlignedLoad(
          TF.TT.getShadowTy(&CB), TF.getRetvalTLS(CB.getType(), NextIRB),
          ShadowTLSAlignment, "_dfsret");
      TF.SkipInsts.insert(LI);
      TF.setShadow(ShadowTarget, LI);
      TF.NonZeroChecks.push_back(LI);
    }
  }
}

void TaintVisitor::visitPHINode(PHINode &PN) {
  Type *ShadowTy = TF.TT.getShadowTy(&PN);
  PHINode *ShadowPN =
      PHINode::Create(ShadowTy, PN.getNumIncomingValues(), "", &PN);

  // Give the shadow phi node valid predecessors to fool SplitEdge into working.
  Value *UndefShadow = UndefValue::get(ShadowTy);
  for (BasicBlock *BB : PN.blocks())
    ShadowPN->addIncoming(UndefShadow, BB);

  TF.setShadow(&PN, ShadowPN);
  TF.PHIFixups.push_back({&PN, ShadowPN});
}

static inline bool isLoopLatch(const BasicBlock *BB, const BasicBlock *Header) {
  const BasicBlock *Succ = nullptr;
  SmallVector<const BasicBlock*> Visited;
  while (BB != Header) {
    Visited.push_back(BB);
    if ((Succ = BB->getSingleSuccessor()) == nullptr)
      return false;
    BB = Succ;
    if (Visited.end() != std::find(Visited.begin(), Visited.end(), BB))
      return false; // found a cycle
  }
  return true;
}

void TaintFunction::visitCondition(Value *Condition, Instruction *I) {
  IRBuilder<> IRB(I);
  // get operand
  Value *Shadow = getShadow(Condition);
  uint8_t flag = 0;
  if (ClTraceLoop && isa<BranchInst>(I)) {
    // check loop exit and latch
    BasicBlock *BB = I->getParent();
    Loop *L = LI->getLoopFor(BB);
    if (L) {
      BranchInst *BI = cast<BranchInst>(I);
      BasicBlock *TB = I->getSuccessor(0); // true branch
      BasicBlock *FB = I->getSuccessor(1); // false branch
      if (isLoopLatch(TB, L->getHeader())) // True branch loop latch
        flag |= TrueBranchLoopLatch; // return to the loop header
      if (isLoopLatch(FB, L->getHeader())) // False branch loop latch
        flag |= FalseBranchLoopLatch; // return to the loop header
      if (!L->contains(TB)) // True branch loop exit
        flag |= TrueBranchLoopExit;
      if (!L->contains(FB)) // False branch loop exit
        flag |= FalseBranchLoopExit;
    }
  }
  // we are not interested if the condition is not tainted,
  // except for loop exit
  if (TT.isZeroShadow(Shadow) && (flag & LoopExitBranch) == 0)
    return;
  uint32_t cid = TT.getInstructionId(I);
  if (cid == TT.InvalidInstructionId)
    return; // XXX: forget about loop?
  TT.documentBranchId(cid, I, isa<BranchInst>(I) ? "br" : "select");
  ConstantInt *LF = ConstantInt::get(TT.Int8Ty, flag);
  ConstantInt *CID = ConstantInt::get(TT.Int32Ty, cid);
  IRB.CreateCall(TT.TaintTraceCondFn, {Shadow, Condition, LF, CID});
}

void TaintVisitor::visitBranchInst(BranchInst &BR) {
  if (BR.isUnconditional()) return;
  TF.visitCondition(BR.getCondition(), &BR);
}

namespace {
class TaintPass : public PassInfoMixin<TaintPass> {
private:
  std::vector<std::string> ABIListFiles;

public:
  TaintPass(
      const std::vector<std::string> &ABIListFiles = std::vector<std::string>())
      : ABIListFiles(ABIListFiles) {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    if (Taint(ABIListFiles).runImpl(M)) {
      return PreservedAnalyses::none();
    }
    return PreservedAnalyses::all();
  }

  static bool isRequired() { return true; }
};
}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "TaintPass", "v1.1",
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(TaintPass());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "taint") {
                    MPM.addPass(TaintPass());
                    return true;
                  }
                  return false;
                });
          }};
}
