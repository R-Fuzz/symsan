//===- UCSanPass.cpp - Under-Constrained Execution Pass ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
/// \file
/// This file implements the UCSan pass for under-constrained execution.
///
/// CONCEPTUAL OVERVIEW:
/// ====================
/// UCSan enables safe execution of functions in isolation, even with
/// uninitialized or invalid pointers. Given a YAML metadata file specifying
/// an entry point and scope, UCSan performs three key transformations:
///
/// 1. SCOPE-BASED FUNCTION REMOVAL:
///    - All functions NOT in scope are removed from the module
///    - Replaced with "dangle" wrappers that safely handle out-of-scope calls
///    - Enables testing individual functions without complete program context
///
/// 2. LAZY POINTER INITIALIZATION (checkPointer):
///    - Instruments all pointer dereferences (loads, stores, memops)
///    - Takes a pseudo-pointer as input, translate to valid pointer
///    - Check if the memory object has been allocated;
//       if not, allocates memory on-demand at runtime
///    - This is the KEY feature enabling under-constrained execution
///
/// 3. MEMORY OBJECT SIZE TRACKING:
///    - Tracks GEP offsets and Cast operations
///    - Estimates sizes of underlying memory objects
///    - Enables runtime bounds checking (checkBounds)
///
/// STANDALONE CAPABILITY:
/// ======================
/// UCSan-instrumented binaries can run WITHOUT symbolic execution. They provide
/// safe under-constrained execution with lazy allocation. To add symbolic
/// reasoning, the IR is pipelined to TaintPass (SymSan), which runs AFTER this
/// pass and adds constraint collection.
///
/// INTEGRATION WITH TaintPass:
/// ===========================
/// - This pass marks all instrumented instructions with "ucsan.checked" metadata
/// - TaintPass checks this metadata and skips redundant pointer validation
/// - Enables efficient pipeline: UCSanPass (safety) → TaintPass (symbolics)
///
//===----------------------------------------------------------------------===//

#include "llvm/ADT/None.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/Analysis/ValueTracking.h"
#include <map>
#include <set>
#include <vector>
#include <string>

using namespace llvm;

namespace {

// Constants for shadow memory alignment
// Must match sizeof(ucsan_label) = sizeof(i16) = 2 bytes
static const Align ShadowTLSAlignment = Align(2);
static const unsigned ArgTLSSize = 800;
static const unsigned kRetvalTLSSize = 800;

static const char *BBIDName = "dfsan.bb";

// Command line options
static cl::opt<bool> ClTraceBound("ucsan-trace-bound",
                                   cl::desc("Enable bounds checking"),
                                   cl::Hidden, cl::init(true));

static cl::opt<bool> ClTraceBB("ucsan-trace-bb",
                                cl::desc("Enable basic block tracing"),
                                cl::Hidden, cl::init(false));

// The ABI list files control how shadow parameters are passed.
static cl::list<std::string> ClABIListFiles(
    "ucsan-abilist",
    cl::desc("File listing native ABI functions and how the pass treats them"),
    cl::Hidden);

class UCSanABIList {
  std::unique_ptr<SpecialCaseList> SCL;

 public:
  UCSanABIList() = default;

  void set(std::unique_ptr<SpecialCaseList> List) { SCL = std::move(List); }

  bool isValid() const { return SCL != nullptr; }

  /// Returns whether either this function or its source file are listed in the
  /// given category.
  bool isIn(const Function &F, StringRef Category) const {
    if (!SCL) return false;
    return isIn(*F.getParent(), Category) ||
           SCL->inSection("taint", "fun", F.getName(), Category);
  }

  /// Returns whether this module is listed in the given category.
  bool isIn(const Module &M, StringRef Category) const {
    if (!SCL) return false;
    return SCL->inSection("taint", "src", M.getModuleIdentifier(), Category);
  }
};

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
// UCSan shadow memory layout (x86_64)
// Shadow: 0x480000000000 - 0x680000000000 (2TB)
static const MemoryMapParams Linux_X86_64_MemoryMapParams = {
    0x700000000000, // AndMask (keep old style)
    0,              // XorMask (not used)
    0x480000000000, // ShadowBase (not used)
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
  TransformedFunction(const TransformedFunction&) = delete;
  TransformedFunction& operator=(const TransformedFunction&) = delete;

  // Allow moves.
  TransformedFunction(TransformedFunction&&) = default;
  TransformedFunction& operator=(TransformedFunction&&) = default;

  /// Type of the function before the transformation.
  FunctionType *OriginalType;

  /// Type of the function after the transformation.
  FunctionType *TransformedType;

  /// Transforming a function may change the position of arguments.  This
  /// member records the mapping from each argument's old position to its new
  /// position.  Argument positions are zero-indexed.
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
                            llvm::makeArrayRef(ArgumentAttributes));
}

// YAML structures for metadata parsing
struct ArgMapEntry {
  int idx;
  int ucsan_idx;
};

struct UCSanScopeCustom {
  std::string ref_name;
  std::vector<ArgMapEntry> arg_maps;
};

struct UCSanScope {
  std::string entry;
  std::vector<std::string> scope;
  std::map<std::string, UCSanScopeCustom> custom;
};

} // namespace

// YAML traits for parsing
namespace llvm {
namespace yaml {

template<>
struct MappingTraits<ArgMapEntry> {
  static void mapping(yaml::IO &io, ArgMapEntry &entry) {
    io.mapRequired("idx", entry.idx);
    io.mapRequired("ucsan_idx", entry.ucsan_idx);
  }
};

template<>
struct SequenceTraits<std::vector<ArgMapEntry>> {
  static size_t size(yaml::IO &io, std::vector<ArgMapEntry> &seq) {
    return seq.size();
  }
  static ArgMapEntry& element(yaml::IO &io, std::vector<ArgMapEntry> &seq, size_t index) {
    if (index >= seq.size())
      seq.resize(index + 1);
    return seq[index];
  }
};

template<>
struct MappingTraits<UCSanScopeCustom> {
  static void mapping(yaml::IO &io, UCSanScopeCustom &c) {
    io.mapRequired("ref_name", c.ref_name);
    io.mapRequired("arg_maps", c.arg_maps);
  }
};

template<>
struct MappingTraits<UCSanScope> {
  static void mapping(yaml::IO &io, UCSanScope &sc) {
    io.mapRequired("entry", sc.entry);
    io.mapOptional("scope", sc.scope);
    io.mapOptional("custom", sc.custom);
  }
};

template<>
struct CustomMappingTraits<std::map<std::string, UCSanScopeCustom>> {
  static void inputOne(IO &io, StringRef Key, std::map<std::string, UCSanScopeCustom> &V) {
    io.mapRequired(Key.str().c_str(), V[Key.str()]);
  }

  static void output(IO &io, std::map<std::string, UCSanScopeCustom> &V) {
    for (auto &Entry : V) {
      io.mapRequired(Entry.first.c_str(), Entry.second);
    }
  }
};

} // namespace yaml
} // namespace llvm

namespace {

class UCSan {
  friend struct UCSanFunction;
  friend class UCSanVisitor;

  // UCSan uses 16-bit labels (separate from SymSan's 32-bit labels)
  enum {
    ShadowWidthBits  = 16,
    ShadowWidthBytes = ShadowWidthBits / 8
  };

  enum WrapperKind {
    WK_None,
    WK_Custom,
    WK_AutoCustom
  };

  Module *Mod;
  LLVMContext *Ctx;

  // Basic types
  IntegerType *Int8Ty;
  IntegerType *Int16Ty;
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  IntegerType *Int1Ty;
  IntegerType *IntptrTy;
  PointerType *VoidPtrTy;

  // UCSan still needs sanitizer shadow memory
  IntegerType *PrimitiveShadowTy;
  PointerType *PrimitiveShadowPtrTy;
  ConstantInt *ZeroPrimitiveShadow;
  ConstantInt *UninitPrimitiveShadow;
  ConstantInt *ShadowPtrAndMask;
  ConstantInt *ShadowPtrXorMask;
  ConstantInt *ShadowPtrBase;
  ConstantInt *ShadowPtrMul;
  Constant *ArgTLS;
  Constant *RetvalTLS;

  // Runtime function types
  FunctionType *UCCheckPointerFnTy;
  FunctionType *UCCheckPointerArgFnTy;
  FunctionType *UCCheckUBIFnTy;
  FunctionType *UCCombineLabelFnTy;
  FunctionType *UCSetLabelForArgsFnTy;
  FunctionType *UCLoadPointerShadowFnTy;
  FunctionType *UCStorePointerShadowFnTy;
  FunctionType *UCResignShadowFnTy;
  FunctionType *UCWrapRetvalFnTy;
  FunctionType *UCSetLabelFnTy;
  FunctionType *UCTraceBBFnTy;
  FunctionType *UCTraceAllocaFnTy;
  FunctionType *UCPushStackFrameFnTy;
  FunctionType *UCPopStackFrameFnTy;

  // Runtime functions
  FunctionCallee UCCheckPointerFn;
  FunctionCallee UCCheckPointerArgFn;
  FunctionCallee UCCheckUBIFn;
  FunctionCallee UCCombineLabelFn;
  FunctionCallee UCSetLabelForArgsFn;
  FunctionCallee UCLoadPointerShadowFn;
  FunctionCallee UCStorePointerShadowFn;
  FunctionCallee UCResignShadowFn;
  FunctionCallee UCWrapRetvalFn;
  FunctionCallee UCSetLabelFn;
  FunctionCallee UCTraceBBFn;
  FunctionCallee UCTraceAllocaFn;
  FunctionCallee UCPushStackFrameFn;
  FunctionCallee UCPopStackFrameFn;
  // FunctionCallee PopulateDataSegmentFn;

  FunctionCallee LLVMReturnAddrFn;
  FunctionCallee ExitFn;

  SmallPtrSet<Value *, 16> UCRuntimeFunctions;

  /// Memory map parameters used in calculation mapping application addresses
  /// to shadow addresses and origin addresses.
  const MemoryMapParams *MapParams;

  // Metadata-driven scope
  UCSanScope Scope;
  std::map<std::string, Function*> CustomFuncs;
  std::map<std::string, FunctionType*> CustomFuncTypes;
  DenseMap<Value *, Function *> UnwrappedFnMap;

  // ABIList for custom function detection
  UCSanABIList ABIList;
  AttributeMask ReadOnlyNoneAttrs;

  void initializeRuntimeFunctions(Module &M);
  void initializeCustomFunctionTypes();
  bool loadMetadata();
  bool initializeModule(Module &M);

  Function *buildDangleFunction(Function *F);
  Function *buildDriverWrapperFunction(Function *F);
  Function *getCustomFunction(const Function *F);

  WrapperKind getWrapperKind(Function *F);
  TransformedFunction getCustomFunctionType(FunctionType *T);

  // Helper functions for shadow management (simplified for standalone)
  Value *getShadowAddress(Value *Addr, IRBuilder<> &IRB);

  /// Returns a zero constant with the shadow type of OrigTy.
  ///
  /// getZeroShadow({T1,T2,...}) = {getZeroShadow(T1),getZeroShadow(T2,...}
  /// getZeroShadow([n x T]) = [n x getZeroShadow(T)]
  /// getZeroShadow(other type) = i32(0)
  ///
  /// Note that a zero shadow is always i32(0) when shouldTrackFieldsAndIndices
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
  /// getShadowTy(other type) = i32
  ///
  /// Note that a shadow type is always i32 when shouldTrackFieldsAndIndices
  /// returns false.
  Type *getShadowTy(Type *OrigTy);
  /// Returns the shadow type of of V's type.
  Type *getShadowTy(Value *V);

  /// Returns an uninitialized shadow value with the shadow type of OrigTy.
  Constant *getUninitShadow(Type *OrigTy);

  /// Marks an instruction as "nosanitize" so TaintPass will skip it
  inline void markNosanitize(Value *V) {
    Instruction *I = dyn_cast<Instruction>(V);
    if (I) I->setMetadata("nosanitize", MDNode::get(*Ctx, None));
  }

  /// Marks a function as "nosanitize" so TaintPass will skip instrumenting it
  inline void markFunctionNosanitize(Function *F) {
    if (F) F->addFnAttr(Attribute::DisableSanitizerInstrumentation);
  }

public:
  UCSan() = default;

  bool runImpl(Module &M);
};

struct UCSanFunction {
  UCSan &UC;
  Function *F;
  DominatorTree DT;

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
  SmallVector<Instruction *, 8> RemovalInsts;

  struct CachedShadow {
    BasicBlock *Block; // The block where Shadow is defined.
    Value *Shadow;
  };
  /// Maps a value to its latest shadow value in terms of domination tree.
  DenseMap<std::pair<Value *, Value *>, CachedShadow> CachedShadows;

  // Pointer checking state
  DenseMap<Value *, Instruction *> CheckedPtrMap;
  DenseSet<Value *> CheckedPtrSet;
  SmallVector<Value *, 16> NonZeroChecks;

  /// Computes the shadow address for a given function argument.
  ///
  /// Shadow = ArgTLS+ArgOffset.
  Value *getArgTLS(Type *T, unsigned ArgOffset, IRBuilder<> &IRB);

  /// Computes the shadow address for a retval.
  Value *getRetvalTLS(Type *T, IRBuilder<> &IRB);

  Value *getShadow(Value *V);
  void setShadow(Instruction *I, Value *Shadow);

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
  Value *loadShadow(Value *Addr, uint64_t Size, Align Align, Type *Ty, Instruction *Pos);
  
  /// XXX: we do not union taint labels for aggregate types before store;
  ///      instead, we store each privimitive field individually.
  ///
  /// Store all primitive subtypes of T, using the aggrate shadow value.
  ///
  /// SS(Addr, {T1,T2, ...}) = SS(SubAddr, T1), SS(SubAddr, T2), ...
  /// SS(Addr, [T1,T2,...]) = SS(SubAddr, T1), SS(SubAddr, T2), ...
  /// SS(Addr, PS) = SS(Addr, PS)
  void storeShadow(Value *Addr, uint64_t Size, Align Align, Value *Shadow, Type *Ty, Instruction *Pos);

  Value *checkPointer(Value *Ptr, Value *Size, bool dereference, IRBuilder<> &IRB);

  UCSanFunction(UCSan &UC, Function *F)
      : UC(UC), F(F) {
    DT.recalculate(*F);
  }

private:
  /// Loads a primivite shadow label
  Value *loadPrimitiveShadow(Value *Addr, uint64_t Size, Align Align,
                             Type *Ty, IRBuilder<> &IRB);
  /// Loads shadow recursively for aggregate types
  Value *loadShadowRecursive(Value *Shadow, SmallVector<unsigned, 4> &Indices,
                             Type *SubTy, Value *Addr, uint64_t Size,
                             Align Align, IRBuilder<> &IRB);
  /// Stores an aggregate shadow label
  void storeShadowRecursive(Value *Shadow, SmallVector<unsigned, 4> &Indices,
                            Type *SubTy, Value *Addr, uint64_t Size,
                            Align Align, IRBuilder<> &IRB);
  /// Returns the shadow value of an argument A.
  Value *getShadowForTLSArgument(Argument *A);
};

class UCSanVisitor : public InstVisitor<UCSanVisitor> {
public:
  UCSanFunction &UF;

  UCSanVisitor(UCSanFunction &UF) : UF(UF) {}

  const DataLayout &getDataLayout() const {
    return UF.F->getParent()->getDataLayout();
  }

  void visitCastInst(CastInst &CI);
  void visitCallBase(CallBase &CB);
  void visitReturnInst(ReturnInst &RI);
  void visitAllocaInst(AllocaInst &AI);
  void visitBranchInst(BranchInst &BI);
  void visitBinaryOperator(BinaryOperator &BO);
  void visitCmpInst(CmpInst &CI);
  void visitAtomicRMWInst(AtomicRMWInst &I);
  void visitLoadInst(LoadInst &LI);
  void visitStoreInst(StoreInst &SI);
  void visitMemCpyInst(MemCpyInst &I);
  void visitMemSetInst(MemSetInst &I);
  void visitMemMoveInst(MemMoveInst &I);
  void visitGetElementPtrInst(GetElementPtrInst &GEPI);
  void visitSelectInst(SelectInst &I);
  void visitPHINode(PHINode &PN);
  // void visitIntrinsicInst(IntrinsicInst &I);

private:
  // Returns false when this is an invoke of a custom function.
  bool visitWrappedCallBase(Function *F, CallBase &CB);
  void visitIndirectCallBase(Value *CV, CallBase &CB);
  void visitInlineAsm(InlineAsm *IA, CallBase &CB);
};

// Initialize runtime functions
void UCSan::initializeRuntimeFunctions(Module &M) {
  Function *F = nullptr;

  // Pointer checking: void* ucsan_check_pointer(void*, i16, i64, i1)
  UCCheckPointerFnTy = FunctionType::get(
    VoidPtrTy,
    {VoidPtrTy, PrimitiveShadowTy, Int64Ty, Int1Ty},
    false);
  UCCheckPointerFn = M.getOrInsertFunction("ucsan_check_pointer", UCCheckPointerFnTy);
  F = dyn_cast<Function>(UCCheckPointerFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // Pointer argument checking: void ucsan_check_ptr_arg(i16*, i32, void*)
  UCCheckPointerArgFnTy = FunctionType::get(
    Type::getVoidTy(*Ctx),
    {PrimitiveShadowPtrTy, Int32Ty, VoidPtrTy},
    false);
  UCCheckPointerArgFn = M.getOrInsertFunction("ucsan_check_ptr_arg", UCCheckPointerArgFnTy);
  F = dyn_cast<Function>(UCCheckPointerArgFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // UBI checking: void ucsan_check_ubi(i16)
  UCCheckUBIFnTy = FunctionType::get(
    Type::getVoidTy(*Ctx),
    {PrimitiveShadowTy},
    false);
  UCCheckUBIFn = M.getOrInsertFunction("ucsan_check_ubi", UCCheckUBIFnTy);
  F = dyn_cast<Function>(UCCheckUBIFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // Label combination for binary ops: i16 ucsan_combine_label(i16, i16)
  UCCombineLabelFnTy = FunctionType::get(
    PrimitiveShadowTy,
    {PrimitiveShadowTy, PrimitiveShadowTy},
    false);
  UCCombineLabelFn = M.getOrInsertFunction("ucsan_combine_label", UCCombineLabelFnTy);
  F = dyn_cast<Function>(UCCombineLabelFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // Shadow resignation: i16 ucsan_resign_shadow(void*, i16*, i64, void*)
  UCResignShadowFnTy = FunctionType::get(
    PrimitiveShadowTy,
    {VoidPtrTy, PrimitiveShadowPtrTy, Int64Ty, VoidPtrTy},
    false);
  UCResignShadowFn = M.getOrInsertFunction("ucsan_resign_shadow", UCResignShadowFnTy);
  F = dyn_cast<Function>(UCResignShadowFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // Return value wrapping: void* ucsan_wrap_retval(i64, i16*, i1, void*)
  // Returns pointer to __ucsan_wrapped_return_tls where the actual return value is stored
  UCWrapRetvalFnTy = FunctionType::get(
    VoidPtrTy,
    {Int64Ty, PrimitiveShadowPtrTy, Int1Ty, VoidPtrTy},
    false);
  UCWrapRetvalFn = M.getOrInsertFunction("ucsan_wrap_retval", UCWrapRetvalFnTy);
  F = dyn_cast<Function>(UCWrapRetvalFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // Argument initialization: i16* ucsan_set_label_for_args(i32, i32, i8, i64)
  UCSetLabelForArgsFnTy = FunctionType::get(
    PrimitiveShadowPtrTy,
    {Int32Ty, Int32Ty, Int8Ty, Int64Ty},
    false);
  UCSetLabelForArgsFn = M.getOrInsertFunction("ucsan_set_label_for_args", UCSetLabelForArgsFnTy);
  F = dyn_cast<Function>(UCSetLabelForArgsFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // Load pointer shadow: i16 ucsan_load_pointer_shadow(i16*, i64, i1)
  UCLoadPointerShadowFnTy = FunctionType::get(
    PrimitiveShadowTy,
    {PrimitiveShadowPtrTy, Int64Ty, Int1Ty},
    false);
  UCLoadPointerShadowFn = M.getOrInsertFunction("ucsan_load_pointer_shadow", UCLoadPointerShadowFnTy);
  F = dyn_cast<Function>(UCLoadPointerShadowFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // Store pointer shadow: void ucsan_store_pointer_shadow(i16, i16*, i64)
  UCStorePointerShadowFnTy = FunctionType::get(
    Type::getVoidTy(*Ctx),
    {PrimitiveShadowTy, PrimitiveShadowPtrTy, Int64Ty},
    false);
  UCStorePointerShadowFn = M.getOrInsertFunction("ucsan_store_pointer_shadow", UCStorePointerShadowFnTy);
  F = dyn_cast<Function>(UCStorePointerShadowFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // LLVM return address intrinsic
  LLVMReturnAddrFn = M.getOrInsertFunction("llvm.returnaddress",
    FunctionType::get(VoidPtrTy, {Int32Ty}, false));
  UCRuntimeFunctions.insert(LLVMReturnAddrFn.getCallee()->stripPointerCasts());

  // void exit(i32) with noreturn attribute
  ExitFn = M.getOrInsertFunction("exit",
    FunctionType::get(Type::getVoidTy(*Ctx), {Int32Ty}, false));
  if (Function *F = dyn_cast<Function>(ExitFn.getCallee()->stripPointerCasts())) {
    F->addFnAttr(Attribute::NoReturn);
    UCRuntimeFunctions.insert(F);
  }

  // void ucsan_set_label(i16, void*, i64)
  UCSetLabelFnTy = FunctionType::get(
    Type::getVoidTy(*Ctx),
    {PrimitiveShadowTy, VoidPtrTy, Int64Ty},
    false);
  UCSetLabelFn = M.getOrInsertFunction("ucsan_set_label", UCSetLabelFnTy);
  F = dyn_cast<Function>(UCSetLabelFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  if (ClTraceBB) {
    // void __taint_trace_bb(i32, i32)
    UCTraceBBFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx),
      {Int32Ty, Int32Ty},
      false);
    UCTraceBBFn = M.getOrInsertFunction("__taint_trace_bb", UCTraceBBFnTy);
    F = dyn_cast<Function>(UCTraceBBFn.getCallee()->stripPointerCasts());
    markFunctionNosanitize(F);
    UCRuntimeFunctions.insert(F);
  }

  // i16 ucsan_trace_alloca(i64 Size, i64 ElemSize, i64 Address)
  // Returns a shadow label representing bounds for this stack allocation
  UCTraceAllocaFnTy = FunctionType::get(
    PrimitiveShadowTy,
    {Int64Ty, Int64Ty, Int64Ty},
    false);
  UCTraceAllocaFn = M.getOrInsertFunction("ucsan_trace_alloca", UCTraceAllocaFnTy);
  F = dyn_cast<Function>(UCTraceAllocaFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // void ucsan_push_stack_frame()
  // Called at function entry to save the current stack top
  UCPushStackFrameFnTy = FunctionType::get(Type::getVoidTy(*Ctx), {}, false);
  UCPushStackFrameFn = M.getOrInsertFunction("ucsan_push_stack_frame", UCPushStackFrameFnTy);
  F = dyn_cast<Function>(UCPushStackFrameFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // void ucsan_pop_stack_frame()
  // Called at function exit to restore the stack top
  UCPopStackFrameFnTy = FunctionType::get(Type::getVoidTy(*Ctx), {}, false);
  UCPopStackFrameFn = M.getOrInsertFunction("ucsan_pop_stack_frame", UCPopStackFrameFnTy);
  F = dyn_cast<Function>(UCPopStackFrameFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);
}

void UCSan::initializeCustomFunctionTypes() {
  // Custom function types will be populated based on YAML metadata
  // TODO: add more custom function prototypes here
  CustomFuncTypes["malloc"] = FunctionType::get(VoidPtrTy, {Int64Ty}, false);
  CustomFuncTypes["free"] = FunctionType::get(Type::getVoidTy(*Ctx), {VoidPtrTy}, false);
  CustomFuncTypes["realloc"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, Int64Ty}, false);
  CustomFuncTypes["calloc"] = FunctionType::get(VoidPtrTy, {Int64Ty, Int64Ty}, false);
  CustomFuncTypes["strdup"] = FunctionType::get(VoidPtrTy, {VoidPtrTy}, false);
  CustomFuncTypes["exit"] = FunctionType::get(Type::getVoidTy(*Ctx), {Int32Ty}, false);
}

bool UCSan::loadMetadata() {
  char* filename = getenv("METADATA");
  if (!filename)
    return false;

  int fd;
  std::vector<char> Buf;
  if (sys::fs::openFileForRead(filename, fd)) {
    errs() << "Warning: Cannot open metadata file: " << filename << "\n";
    return false;
  }

  sys::fs::file_status Status;
  if (sys::fs::status(fd, Status)) {
    errs() << "Warning: Cannot stat metadata file: " << filename << "\n";
    sys::fs::closeFile(fd);
    return false;
  }

  Buf.resize(Status.getSize());
  auto ReadResult = sys::fs::readNativeFile(sys::fs::convertFDToNativeFile(fd),
                                            MutableArrayRef<char>(Buf.data(), Buf.size()));
  if (!ReadResult) {
    errs() << "Warning: Cannot read metadata file: " << filename << "\n";
    sys::fs::closeFile(fd);
    return false;
  }

  yaml::Input yin(StringRef(Buf.data(), Buf.size()));
  yin >> Scope;

  if (yin.error()) {
    errs() << "Error parsing YAML metadata: " << filename << "\n";
    sys::fs::closeFile(fd);
    return false;
  }

  sys::fs::closeFile(fd);
  return true;
}

// Helper: Get shadow type for a given type (simplified for standalone UCSan)
Type *UCSan::getShadowTy(Value *V) {
  return getShadowTy(V->getType());
}

Type *UCSan::getShadowTy(Type *OrigTy) {
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

/// Returns a zero shadow constant.
Constant *UCSan::getZeroShadow(Type *OrigTy) {
  if (!isa<ArrayType>(OrigTy) && !isa<StructType>(OrigTy))
    return ZeroPrimitiveShadow;
  Type *ShadowTy = getShadowTy(OrigTy);
  return ConstantAggregateZero::get(ShadowTy);
}

Constant *UCSan::getZeroShadow(Value *V) {
  return getZeroShadow(V->getType());
}

/// Checks if a value is a zero shadow.
bool UCSan::isZeroShadow(Value *V) {
  Type *T = V->getType();
  if (!isa<ArrayType>(T) && !isa<StructType>(T)) {
    if (const ConstantInt *CI = dyn_cast<ConstantInt>(V))
      return CI->isZero();
    return false;
  }

  return isa<ConstantAggregateZero>(V);
}

/// Returns an uninitialized shadow constant.
Constant *UCSan::getUninitShadow(Type *OrigTy) {
  if (!isa<ArrayType>(OrigTy) && !isa<StructType>(OrigTy))
    return UninitPrimitiveShadow;
  Type *ShadowTy = getShadowTy(OrigTy);
  if (ArrayType *AT = dyn_cast<ArrayType>(ShadowTy)) {
    SmallVector<Constant *, 4> Elements(AT->getNumElements(),
                                        getUninitShadow(AT->getElementType()));
    return ConstantArray::get(AT, Elements);
  } else if (StructType *ST = dyn_cast<StructType>(ShadowTy)) {
    SmallVector<Constant *, 4> Elements(ST->getNumElements());
    for (unsigned I = 0, N = ST->getNumElements(); I < N; ++I)
      Elements[I] = getUninitShadow(ST->getElementType(I));
    return ConstantStruct::get(ST, Elements);
  }
  llvm_unreachable("Unexpected type for uninitialized shadow");
}

/// Get the shadow memory address for a given data address.
/// Shadow memory layout: shadow_addr = ((data_addr & mask) << 1) + ShadowBase
/// For 16-bit labels, each byte gets 2 bytes of shadow memory.
Value *UCSan::getShadowAddress(Value *Addr, IRBuilder<> &IRB) {
  assert(Addr != RetvalTLS && "Reinstrumenting?");
  // Formula: ((ptr & ShadowMask) * 2) + ShadowBase
  Value *OffsetLong = IRB.CreatePointerCast(Addr, IntptrTy);
  markNosanitize(OffsetLong);
  if (ShadowPtrAndMask) {
    OffsetLong = IRB.CreateAnd(OffsetLong, ShadowPtrAndMask);
    markNosanitize(OffsetLong);
  }
  if (ShadowPtrXorMask) {
    OffsetLong = IRB.CreateXor(OffsetLong, ShadowPtrXorMask);
    markNosanitize(OffsetLong);
  }
  if (ShadowPtrMul) {
    OffsetLong = IRB.CreateMul(OffsetLong, ShadowPtrMul);
    markNosanitize(OffsetLong);
  }
  if (ShadowPtrBase) {
    OffsetLong = IRB.CreateAdd(OffsetLong, ShadowPtrBase);
    markNosanitize(OffsetLong);
  }
  Value *ShadowAddr = IRB.CreateIntToPtr(OffsetLong, PrimitiveShadowPtrTy);
  markNosanitize(ShadowAddr);
  return ShadowAddr;
}

/// Computes the shadow address for a given function argument.
///
/// Shadow = ArgTLS + ArgOffset.
/// UCSan uses shadow memory to track pointer aliasing - which pointers
/// point to the same memory object. This is essential for lazy allocation
/// and pseudo-pointer translation.
Value *UCSanFunction::getArgTLS(Type *T, unsigned ArgOffset, IRBuilder<> &IRB) {
  Value *Base = IRB.CreatePointerCast(UC.ArgTLS, UC.IntptrTy);
  UC.markNosanitize(Base);
  if (ArgOffset) {
    Base = IRB.CreateAdd(Base, ConstantInt::get(UC.IntptrTy, ArgOffset));
    UC.markNosanitize(Base);
  }
  Base = IRB.CreateIntToPtr(Base, PointerType::get(UC.getShadowTy(T), 0),
                             "_dfsarg");
  UC.markNosanitize(Base);
  return Base;
}

/// Computes the shadow address for a return value.
/// UCSan uses this to track symbolic labels on return values,
/// enabling pointer aliasing tracking across function boundaries.
Value *UCSanFunction::getRetvalTLS(Type *T, IRBuilder<> &IRB) {
  Value *Ret = IRB.CreatePointerCast(
      UC.RetvalTLS, PointerType::get(UC.getShadowTy(T), 0), "_dfsret");
  UC.markNosanitize(Ret);
  return Ret;
}

/// Get shadow value for a given LLVM value.
/// UCSan uses shadows to track pointer aliasing.
Value *UCSanFunction::getShadow(Value *V) {
  if (!isa<Argument>(V) && !isa<Instruction>(V))
    return UC.getZeroShadow(V);
  Value *&Shadow = ValShadowMap[V];
  if (!Shadow) {
    if (Argument *A = dyn_cast<Argument>(V)) {
      Shadow = getShadowForTLSArgument(A);
    } else {
      Shadow = UC.getZeroShadow(V);
    }
  }
  return Shadow;
}

/// Set shadow value for an instruction.
void UCSanFunction::setShadow(Instruction *I, Value *Shadow) {
  assert(!ValShadowMap.count(I));
  ValShadowMap[I] = Shadow;
}

/// Get shadow for a function argument from TLS.
Value *UCSanFunction::getShadowForTLSArgument(Argument *A) {
  unsigned ArgOffset = 0;
  const DataLayout &DL = F->getParent()->getDataLayout();
  for (auto &FArg : F->args()) {
    if (!FArg.getType()->isSized()) {
      if (A == &FArg)
        return UC.getZeroShadow(A);
      continue;
    }

    unsigned Size = DL.getTypeAllocSize(UC.getShadowTy(&FArg));
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
    LoadInst *LI = IRB.CreateAlignedLoad(UC.getShadowTy(&FArg), ArgShadowPtr,
                                         ShadowTLSAlignment);
    UC.markNosanitize(LI);
    return LI;
  }

  return UC.getZeroShadow(A);
}

/// Load primitive shadow corresponding to bytes [Addr, Addr+Size), where
// Addr has alignment Align, and take the union of each of those shadows.
Value *UCSanFunction::loadPrimitiveShadow(Value *Addr, uint64_t Size, Align Align,
                                          Type *Ty, IRBuilder<> &IRB) {
  if (Size == 0)
    return UC.ZeroPrimitiveShadow;

  Value *ShadowAddr = UC.getShadowAddress(Addr, IRB);
  // TOOD: Optimize for non-pointer types
  CallInst *FallbackCall = IRB.CreateCall(
      UC.UCLoadPointerShadowFn,
      {ShadowAddr, ConstantInt::get(UC.Int64Ty, Size),
       ConstantInt::get(UC.Int1Ty, Ty->isPointerTy())});
  FallbackCall->addRetAttr(Attribute::ZExt);
  UC.markNosanitize(FallbackCall);
  return FallbackCall;
}

/// Recursive helper to load shadow for aggregate types.
Value *UCSanFunction::loadShadowRecursive(
    Value *Shadow, SmallVector<unsigned, 4> &Indices, Type *SubTy,
    Value *Addr, uint64_t Size, Align InstAlign, IRBuilder<> &IRB) {
  auto &DL = F->getParent()->getDataLayout();

  if (!isa<ArrayType>(SubTy) && !isa<StructType>(SubTy)) {
    uint64_t SubSize = DL.getTypeStoreSize(SubTy);
    assert(Size >= SubSize);
    InstAlign = Align(std::min(InstAlign.value(), (uint64_t)DL.getABITypeAlignment(SubTy)));
    // load a primitive shadow from address
    Value *PrimitiveShadow = loadPrimitiveShadow(Addr, SubSize, InstAlign, SubTy, IRB);
    // then insert the primitive shadow into the sub-field
    Value *Insert = IRB.CreateInsertValue(Shadow, PrimitiveShadow, Indices);
    UC.markNosanitize(Insert);
    return Insert;
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
      UC.markNosanitize(SubAddr);
      Shadow = loadShadowRecursive(Shadow, Indices, ElemTy,
                                   SubAddr, Size - Offset, InstAlign, IRB);
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
      UC.markNosanitize(SubAddr);
      Shadow = loadShadowRecursive(Shadow, Indices, ElemTy,
                                   SubAddr, Size - Offset, InstAlign, IRB);
      Indices.pop_back();
    }
    return Shadow;
  }
  llvm_unreachable("Unexpected shadow type");
}

/// Load shadow from shadow memory for a given address.
Value *UCSanFunction::loadShadow(Value *Addr, uint64_t Size, Align Align,
                                 Type *Ty, Instruction *Pos) {
  IRBuilder<> IRB(Pos);
  // if loading from a local variable, load label from its shadow alloca
  if (AllocaInst *AI = dyn_cast<AllocaInst>(Addr)) {
    const auto i = AllocaShadowMap.find(AI);
    if (i != AllocaShadowMap.end()) {
      LoadInst *LI = IRB.CreateLoad(UC.getShadowTy(Ty), i->second);
      UC.markNosanitize(LI);
      return LI;
    }
  }

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
    return UC.ZeroPrimitiveShadow;

  const llvm::Align ShadowAlign(Align.value() * UCSan::ShadowWidthBytes);

  // now check if we're loading an aggragate object
  if (!isa<ArrayType>(Ty) && !isa<StructType>(Ty))
    return loadPrimitiveShadow(Addr, Size, ShadowAlign, Ty, IRB);

  // if loading an aggregate object, load its shadow recursively
  SmallVector<unsigned, 4> Indices;
  Type *ShadowTy = UC.getShadowTy(Ty);
  Value *Shadow = UndefValue::get(ShadowTy);
  Shadow = loadShadowRecursive(Shadow, Indices, Ty, Addr, Size, ShadowAlign, IRB);
  return Shadow;
}

void UCSanFunction::storeShadowRecursive(
    Value *Shadow, SmallVector<unsigned, 4> &Indices, Type *SubTy,
    Value *Addr, uint64_t Size, Align InstAlign, IRBuilder<> &IRB) {
  auto &DL = F->getParent()->getDataLayout();

  if (!isa<ArrayType>(SubTy) && !isa<StructType>(SubTy)) {
    uint64_t SubSize = DL.getTypeStoreSize(SubTy);
    assert(Size >= SubSize);
    InstAlign = Align(std::min(InstAlign.value(),
                           (uint64_t)DL.getABITypeAlignment(SubTy)));
    // load a primitive shadow from the sub-field
    Value *PrimitiveShadow = IRB.CreateExtractValue(Shadow, Indices);
    UC.markNosanitize(PrimitiveShadow);
    // then store the primitive shadow into the shadow address
    Value *ShadowAddr = UC.getShadowAddress(Addr, IRB);
    CallInst *CI = IRB.CreateCall(UC.UCStorePointerShadowFn,
        {PrimitiveShadow, ShadowAddr, ConstantInt::get(UC.Int64Ty, SubSize)});
    UC.markNosanitize(CI);
    return;
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
      UC.markNosanitize(SubAddr);
      storeShadowRecursive(Shadow, Indices, ElemTy,
                           SubAddr, Size - Offset, InstAlign, IRB);
      Indices.pop_back();
    }
    return;
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
      UC.markNosanitize(SubAddr);
      storeShadowRecursive(Shadow, Indices, ElemTy,
                           SubAddr, Size - Offset, InstAlign, IRB);
      Indices.pop_back();
    }
    return;
  }
  llvm_unreachable("Unexpected shadow type");
}

/// Store shadow to shadow memory for a given address.
void UCSanFunction::storeShadow(Value *Addr, uint64_t Size, Align Alignment,
                                Value *Shadow, Type *Ty, Instruction *Pos) {
  IRBuilder<> IRB(Pos);
  if (AllocaInst *AI = dyn_cast<AllocaInst>(Addr)) {
    const auto i = AllocaShadowMap.find(AI);
    if (i != AllocaShadowMap.end()) {
      StoreInst *SI = IRB.CreateStore(Shadow, i->second);
      UC.markNosanitize(SI);
      SkipInsts.insert(SI);
      return;
    }
  }

  const Align ShadowAlign(Alignment.value() * UCSan::ShadowWidthBytes);
  Value *ShadowAddr = UC.getShadowAddress(Addr, IRB);
  // check if the shadow is zero, if so, clear the shadow memory regardless
  // of the shadow type
  if (UC.isZeroShadow(Shadow)) {
    IntegerType *ShadowTy =
        IntegerType::get(*UC.Ctx, Size * UC.ShadowWidthBits);
    Value *ExtZeroShadow = ConstantInt::get(ShadowTy, 0);
    Value *ExtShadowAddr =
        IRB.CreateBitCast(ShadowAddr, PointerType::getUnqual(ShadowTy));
    UC.markNosanitize(ExtShadowAddr);
    Value *SI = IRB.CreateAlignedStore(ExtZeroShadow, ExtShadowAddr, ShadowAlign);
    UC.markNosanitize(SI);
    return;
  }

  // now check if we're storing an aggragate shadow object
  if (!isa<ArrayType>(Ty) && !isa<StructType>(Ty)) {
    // TODO: Optimize for non-pointer types
    CallInst *CI = IRB.CreateCall(
        UC.UCStorePointerShadowFn,
        {Shadow, ShadowAddr, ConstantInt::get(UC.Int64Ty, Size)});
    UC.markNosanitize(CI);
    return;
  }

  // if storing an aggregate shadow object, store its shadow recursively
  // we want to do this so union_store may have a chance to simplify some
  // constraints
  SmallVector<unsigned, 4> Indices;
  storeShadowRecursive(Shadow, Indices, Ty,
                       Addr, Size, ShadowAlign, IRB);
}

Function *UCSan::buildDangleFunction(Function *F) {
  // Creates wrapper for out-of-scope functions
  // This allows in-scope code to call out-of-scope functions safely
  // The wrapper handles shadow management and pointer checking

  FunctionType *FT = F->getFunctionType();
  std::string FN = "__external$" + F->getName().str();
  Function *NewF = Function::Create(FT, GlobalValue::LinkageTypes::PrivateLinkage,
                                    F->getAddressSpace(), FN, Mod);
  markFunctionNosanitize(NewF);  // Mark dangle wrapper so TaintPass skips it
  FunctionType *NewFT = NewF->getFunctionType();
  BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", NewF);
  IRBuilder<> IRB(BB);

  // Create UCSanFunction context for shadow memory access
  UCSanFunction UF(*this, NewF);

  const DataLayout &DL = Mod->getDataLayout();
  bool resign_ptrargs = getenv("KO_RESIGN_PTRARGS") != nullptr;
  bool checker_ubi = getenv("KO_CHECKER_UBI") != nullptr;

  // Get return address for tracking
  auto RetAddr = IRB.CreateCall(LLVMReturnAddrFn, {ConstantInt::get(Int32Ty, 0)}, "retaddr");

  // Process pointer arguments if needed
  if (resign_ptrargs || checker_ubi) {
    unsigned ArgOffset = 0;
    unsigned n = FT->getNumParams();

    for (auto arg = NewF->arg_begin(); n != 0; ++arg, --n) {
      if (arg->getType()->isPointerTy()) {
        // Get size of pointed-to type
        ConstantInt *CI;
        if (arg->getType()->getPointerElementType()->isSized()) {
          CI = ConstantInt::get(Int64Ty, DL.getTypeSizeInBits(arg->getType()->getPointerElementType()) / 8);
        } else {
          CI = ConstantInt::get(Int64Ty, 0);
        }

        // Get shadow address for this argument from TLS
        // UCSan uses shadow memory to track pointer aliasing
        Value *shadow = UF.getArgTLS(arg->getType(), ArgOffset, IRB);

        // Check UBI if enabled
        if (checker_ubi) {
          Value *loaded_shadow = IRB.CreateAlignedLoad(PrimitiveShadowTy, shadow, ShadowTLSAlignment);
          IRB.CreateCall(UCCheckUBIFn, {loaded_shadow});
        }

        // Resign shadow if enabled
        if (resign_ptrargs) {
          Value *BCI = IRB.CreatePointerCast(&*arg, PrimitiveShadowPtrTy);
          IRB.CreateCall(UCResignShadowFn, {BCI, shadow, CI, RetAddr});
        }
      }

      // Update offset for next argument
      unsigned Size = DL.getTypeAllocSize(getShadowTy(&*arg));
      ArgOffset += alignTo(Size, ShadowTLSAlignment);
    }
  }

  // Wrap return value
  Type *RT = FT->getReturnType();
  if (!RT->isVoidTy()) {
    Value *retvaltls = UF.getRetvalTLS(RT, IRB);

    // For struct/array return types, we need to call ucsan_wrap_retval for each
    // primitive element so that both ucsan and symsan labels are properly wrapped.
    // ucsan_wrap_retval returns a pointer to __ucsan_wrapped_return_tls where
    // the actual return value is stored. We must load immediately after each call
    // before the next call overwrites it, then assemble the struct.
    std::function<Value *(Type *, Value *, SmallVector<unsigned, 4> &)> wrapRetvalRecursive =
        [&](Type *SubTy, Value *ShadowAddr, SmallVector<unsigned, 4> &Indices) -> Value * {
      if (!isa<ArrayType>(SubTy) && !isa<StructType>(SubTy)) {
        // Primitive type: call ucsan_wrap_retval and load from returned pointer
        ConstantInt *size = ConstantInt::get(Int64Ty, DL.getTypeSizeInBits(SubTy));
        ConstantInt *is_ptr = ConstantInt::get(Int1Ty, SubTy->isPointerTy());
        Value *ret_ptr = IRB.CreateCall(UCWrapRetvalFn, {size, ShadowAddr, is_ptr, RetAddr});
        // Load the value from the returned pointer (pointing to __ucsan_wrapped_return_tls)
        Value *typed_ptr = IRB.CreateBitOrPointerCast(ret_ptr, SubTy->getPointerTo());
        Value *loaded_val = IRB.CreateLoad(SubTy, typed_ptr);
        return loaded_val;
      }

      // For aggregate types, recursively wrap each element and assemble
      Value *Result = UndefValue::get(SubTy);

      if (ArrayType *AT = dyn_cast<ArrayType>(SubTy)) {
        Type *ElemTy = AT->getElementType();
        for (unsigned Idx = 0; Idx < AT->getNumElements(); Idx++) {
          Value *SubShadowAddr = IRB.CreateConstGEP2_32(
              getShadowTy(SubTy), ShadowAddr, 0, Idx);
          markNosanitize(SubShadowAddr);
          Indices.push_back(Idx);
          Value *ElemVal = wrapRetvalRecursive(ElemTy, SubShadowAddr, Indices);
          Indices.pop_back();
          Result = IRB.CreateInsertValue(Result, ElemVal, Idx);
        }
        return Result;
      }

      if (StructType *ST = dyn_cast<StructType>(SubTy)) {
        for (unsigned Idx = 0; Idx < ST->getNumElements(); Idx++) {
          Type *ElemTy = ST->getElementType(Idx);
          Value *SubShadowAddr = IRB.CreateConstGEP2_32(
              getShadowTy(SubTy), ShadowAddr, 0, Idx);
          markNosanitize(SubShadowAddr);
          Indices.push_back(Idx);
          Value *ElemVal = wrapRetvalRecursive(ElemTy, SubShadowAddr, Indices);
          Indices.pop_back();
          Result = IRB.CreateInsertValue(Result, ElemVal, Idx);
        }
        return Result;
      }

      llvm_unreachable("Unexpected type in wrapRetvalRecursive");
    };

    SmallVector<unsigned, 4> Indices;
    Value *RetVal = wrapRetvalRecursive(RT, retvaltls, Indices);
    IRB.CreateRet(RetVal);
  } else {
    IRB.CreateRetVoid();
  }

  return NewF;
}

Function *UCSan::buildDriverWrapperFunction(Function *F) {
  // Creates main() wrapper that calls the entry point function
  // This replaces the standard main() and initializes arguments symbolically

  // Check if we should skip wrapper creation
  if (getenv("NOT_ENTRY_OBJECT")) {
    return F;
  }

  // Create new main() with standard signature: int main(int argc, char **argv)
  Type *ArgvTy = PointerType::getUnqual(PointerType::getUnqual(Int8Ty));
  FunctionType *FT = FunctionType::get(Int32Ty, {Int32Ty, ArgvTy}, false);
  Function *NewF = Function::Create(FT, GlobalValue::LinkageTypes::ExternalLinkage,
                                    F->getAddressSpace(), "main", Mod);
  // Set argument names for clarity
  NewF->getArg(0)->setName("argc");
  NewF->getArg(1)->setName("argv");

  // Only copy function-level attributes, not parameter or return attributes
  NewF->setAttributes(AttributeList::get(*Ctx, F->getAttributes().getFnAttrs(),
                                         AttributeSet(), {}));
  markFunctionNosanitize(NewF);  // Mark driver wrapper so TaintPass skips it

  BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", NewF);
  IRBuilder<> IRB(BB);

  // Handle the entry point function
  if (F->isVarArg()) {
    // VarArg functions not yet supported for entry points
    errs() << "Warning: VarArg entry points not supported\n";
    assert(false && "Not implemented");
    IRB.CreateRet(ConstantInt::get(Int32Ty, 1));
    return NewF;
  }

  FunctionType *EntryFT = F->getFunctionType();
  const DataLayout &DL = Mod->getDataLayout();

  // Initialize arguments for the entry point
  std::vector<Value *> Args;
  for (Function::arg_iterator ai = F->arg_begin(), ae = F->arg_end(); ai != ae; ++ai) {
    ConstantInt *ArgNo = ConstantInt::get(Int32Ty, ai->getArgNo());
    ConstantInt *ArgSize = ConstantInt::get(Int32Ty, DL.getTypeSizeInBits(ai->getType()));
    ConstantInt *IsPtr = ConstantInt::get(Int8Ty, ai->getType()->isPointerTy());
    ConstantInt *InitVal = ConstantInt::get(Int64Ty, 0);

    // Call runtime to create symbolic argument
    // Returns a pointer that we cast to the appropriate type
    Value *casted_arg = IRB.CreateCall(UCSetLabelForArgsFn, {ArgNo, ArgSize, IsPtr, InitVal});
    Args.push_back(IRB.CreateBitOrPointerCast(casted_arg, ai->getType()));
  }

  // Call the actual entry point function
  IRB.CreateCall(F, Args);

  // Return 0 (success)
  IRB.CreateRet(ConstantInt::get(Int32Ty, 0));

  // Add basic block tracing to entry point if enabled
  if (ClTraceBB) {
    unsigned int BBCount = 0;
    for (Function::iterator BI = F->begin(), BE = F->end(); BI != BE; ++BI, ++BBCount) {
      ConstantInt *BBID = ConstantInt::get(Int32Ty, BBCount);

      // Add trace call at beginning of basic block
      CallInst *CI = CallInst::Create(UCTraceBBFn,
                      {ConstantInt::get(Int32Ty, 0), BBID},
                      "", &*BI->getFirstNonPHI());

      // Add metadata for BB tracking
      MDNode *MD = MDNode::get(Mod->getContext(),
                              {ConstantAsMetadata::get(BBID)});
      BI->getTerminator()->setMetadata(BBIDName, MD);
    }
  }

  return NewF;
}

Function *UCSan::getCustomFunction(const Function *F) {
  // Handles auto-custom function wrapping based on YAML configuration
  // Maps arguments from one function signature to another

  auto Name = F->getName().str();

  // Check if already built
  if (CustomFuncs.find(Name) != CustomFuncs.end()) {
    return CustomFuncs[Name];
  }

  // Check if this is a custom function in metadata
  if (Scope.custom.find(Name) == Scope.custom.end()) {
    return nullptr; // Not a custom function
  }

  auto &CustomEntry = Scope.custom[Name];

  // Verify referenced function type exists
  if (CustomFuncTypes.find(CustomEntry.ref_name) == CustomFuncTypes.end()) {
    errs() << "Error: Referenced function " << CustomEntry.ref_name << " not found\n";
    return nullptr;
  }

  // Create wrapper function
  auto Linkage = Function::InternalLinkage;
  auto WrappedName = "__auto_dfsw_" + Name;
  auto RefedName = "__dfsw_" + CustomEntry.ref_name;

  FunctionType *RefedFuncType = CustomFuncTypes[CustomEntry.ref_name];
  FunctionType *WrapperType = FunctionType::get(F->getReturnType(),
                                                F->getFunctionType()->params(),
                                                F->isVarArg());

  Function *WrapperFunc = Function::Create(WrapperType, Linkage, WrappedName, *Mod);
  markFunctionNosanitize(WrapperFunc);  // Mark custom wrapper so TaintPass skips it
  BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", WrapperFunc);
  IRBuilder<> IRB(BB);

  // Create UCSanFunction context for shadow memory access
  UCSanFunction UF(*this, WrapperFunc);

  // Get or insert the referenced function
  FunctionCallee RefedFunc = Mod->getOrInsertFunction(RefedName, RefedFuncType);

  // Build argument mapping
  std::map<unsigned int, unsigned int> ArgMap;
  std::map<unsigned int, unsigned int> ArgTLSMap;

  for (auto &ArgMapEntry : CustomEntry.arg_maps) {
    ArgMap[ArgMapEntry.ucsan_idx] = ArgMapEntry.idx;
  }

  const DataLayout &DL = Mod->getDataLayout();
  unsigned ArgOffset = 0;

  // Calculate shadow offsets for each argument
  for (unsigned i = 0, e = F->arg_size(); i != e; ++i) {
    ArgTLSMap[i] = ArgOffset;
    unsigned Size = DL.getTypeAllocSize(getShadowTy(F->getArg(i)->getType()));
    ArgOffset += alignTo(Size, ShadowTLSAlignment);
  }

  // Build actual arguments for referenced function
  std::vector<Value *> Args;

  // Add regular arguments
  for (unsigned i = 0, e = RefedFuncType->getNumParams(); i != e; ++i) {
    if (ArgMap.find(i) == ArgMap.end()) {
      errs() << "Error: Argument " << i << " not in arg_maps\n";
      return nullptr;
    }
    unsigned idx = ArgMap[i];
    Args.push_back(WrapperFunc->getArg(idx));
  }

  // Add shadow arguments from TLS (UCSan uses shadow memory for pointer aliasing)
  for (unsigned i = 0, e = RefedFuncType->getNumParams(); i != e; ++i) {
    unsigned idx = ArgMap[i];
    Value *argtls = UF.getArgTLS(F->getArg(idx)->getType(), ArgTLSMap[idx], IRB);
    Value *ArgShadow = IRB.CreateLoad(PrimitiveShadowTy, argtls);
    Args.push_back(ArgShadow);
  }

  // Handle return value
  if (!F->getReturnType()->isVoidTy()) {
    Value *retvaltls = UF.getRetvalTLS(F->getReturnType(), IRB);
    Args.push_back(retvaltls);

    Value *RetVal = IRB.CreateCall(RefedFunc, Args);
    Value *CastedRetVal = IRB.CreateBitOrPointerCast(RetVal, F->getReturnType());
    IRB.CreateRet(CastedRetVal);
  } else {
    IRB.CreateCall(RefedFunc, Args);
    IRB.CreateRetVoid();
  }

  CustomFuncs[Name] = WrapperFunc;
  return WrapperFunc;
}

UCSan::WrapperKind UCSan::getWrapperKind(Function *F) {
  // Check ABIList for custom functions (priority)
  if (ABIList.isIn(*F, "custom"))
    return WK_Custom;

  // Check if function is in the custom map from YAML metadata
  if (Scope.custom.find(F->getName().str()) != Scope.custom.end()) {
    return WK_AutoCustom;
  }
  return WK_None;
}

TransformedFunction UCSan::getCustomFunctionType(FunctionType *T) {
  SmallVector<Type *, 4> ArgTypes;

  // Some parameters of the custom function being constructed are
  // parameters of T.  Record the mapping from parameters of T to
  // parameters of the custom function, so that parameter attributes
  // at call sites can be updated.
  std::vector<unsigned> ArgumentIndexMapping;
  for (unsigned i = 0, ie = T->getNumParams(); i != ie; ++i) {
    Type* param_type = T->getParamType(i);
    ArgumentIndexMapping.push_back(ArgTypes.size());
    ArgTypes.push_back(param_type);
  }
  for (unsigned i = 0, e = T->getNumParams(); i != e; ++i)
    ArgTypes.push_back(PrimitiveShadowTy);
  if (T->isVarArg())
    ArgTypes.push_back(PrimitiveShadowPtrTy);
  Type *RetType = T->getReturnType();
  if (!RetType->isVoidTy())
    ArgTypes.push_back(PrimitiveShadowPtrTy);
  return TransformedFunction(
      T, FunctionType::get(T->getReturnType(), ArgTypes, T->isVarArg()),
      ArgumentIndexMapping);
}

Value *UCSanFunction::checkPointer(Value *Ptr, Value *Size, bool dereference,
                                    IRBuilder<> &IRB) {
  Type *Ty = Ptr->getType();
  Value *SPtr = Ptr->stripPointerCasts();
  bool cacheable = isa<Constant>(Size);
  assert(dereference && "Must dereference pointer when calling this function");

  if (cacheable) {
    // cache is only possible if size is a constant
    auto itr = CheckedPtrMap.find(Ptr);
    if (itr != CheckedPtrMap.end()) {
      // finding related instructions
      // worst case, cast(ptr) -> check_ptr -> cast(ptr)
      Instruction *I1 = itr->second, *I2 = nullptr, *I3 = nullptr;
      CallBase *CB = nullptr;
      if (isa<CastInst>(I1)) {
        I2 = dyn_cast<Instruction>(I1->getOperand(0));
        CB = dyn_cast<CallBase>(I2);
        I3 = dyn_cast<Instruction>(I2->getOperand(0));
      } else {
        CB = dyn_cast<CallBase>(I1);
        I2 = dyn_cast<Instruction>(I1->getOperand(0));
      }

      // update size if needed
      assert(CB && "Checked pointer must be a CallBase");
      auto OldSize = dyn_cast<ConstantInt>(CB->getArgOperand(2));
      auto NewSize = dyn_cast<ConstantInt>(Size);
      assert(OldSize && NewSize && "Size must be a constant");
      if (NewSize->getZExtValue() > OldSize->getZExtValue()) {
        // update size
        CB->setArgOperand(2, Size);
      }

      // cached check pointer must dominate the new use
      auto *TBB = IRB.GetInsertBlock();
      auto *SBB = itr->second->getParent();
      if (DT.dominates(SBB, TBB)) {
        // The check is already in a dominating block, no need to move it.
        return itr->second;
      }

      // not dominating, move the checks to a dominating basic block
      Instruction *Pos = nullptr;
      if (isa<GlobalVariable>(Ptr) || isa<Argument>(Ptr)) {
        Pos = F->getEntryBlock().getTerminator();
      } else if (Instruction *I = dyn_cast<Instruction>(Ptr)) {
        // move to after the source of Ptr
        Pos = I->getNextNode();
        while (isa<PHINode>(Pos) || isa<AllocaInst>(Pos)) {
          Pos = Pos->getNextNode();
        }
        // handle load shadow - skip the shadow if it exists
        if (CB->getArgOperand(1) == Pos) {
          Pos = Pos->getNextNode();
        }
      } else {
        errs() << "Unexpected pointer type for checkPointer: " << *Ptr << "\n"
              << "\t" << *SPtr << "\n";
      }
      if (Pos) {
        I1->moveBefore(Pos);
        if (I2) I2->moveBefore(I1);
        if (I3) I3->moveBefore(I2);
        return itr->second;
      } else {
        cacheable = false; // do not cache if we need to move the instruction
        // fall through to insert the check pointer
      }
    }
  }

  if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(SPtr)) {
    // If this is a GEP, we need to check the base pointer.
    SPtr = GEP->getPointerOperand();
  }

  if (!isa<AllocaInst>(SPtr)) {
    Value *Addr = Ptr;
    if (Ty != UC.VoidPtrTy) {
      Addr = IRB.CreateBitCast(Ptr, UC.VoidPtrTy);
      UC.markNosanitize(Addr);
    }

    // Get shadow for the pointer from TLS (for arguments) or shadow memory
    Value* Shadow = getShadow(Ptr);

    Value *ExtSize = IRB.CreateZExtOrTrunc(Size, UC.Int64Ty);
    if (ExtSize != Size) {
      UC.markNosanitize(ExtSize);
    }
    ConstantInt *Deref = ConstantInt::get(UC.Int1Ty, dereference);

    CallInst *NewAddr = IRB.CreateCall(
      UC.UCCheckPointerFn, {Addr, Shadow, ExtSize, Deref});
    UC.markNosanitize(NewAddr);

    Value *Checked = NewAddr;
    if (Ty != NewAddr->getType()) {
      Checked = IRB.CreateBitCast(NewAddr, Ty);
      UC.markNosanitize(Checked);
    }

    if (cacheable) {
      // only cache if size is a constant
      CheckedPtrMap[Ptr] = cast<Instruction>(Checked);
    }

    return Checked;
  } else {
    // AllocaInst doesn't need checking
    return Ptr;
  }
}

void UCSanVisitor::visitLoadInst(LoadInst &LI) {
  auto &DL = LI.getModule()->getDataLayout();
  Type *Ty = LI.getType();
  uint64_t StoreSize = DL.getTypeStoreSize(Ty);
  if (StoreSize == 0) return;

  Value *Ptr = LI.getPointerOperand();
  ConstantInt *Size = ConstantInt::get(UF.UC.Int64Ty, StoreSize);

  // Check and replace pointer
  IRBuilder<> IRB(&LI);
  Ptr = UF.checkPointer(Ptr, Size, true, IRB);
  LI.setOperand(0, Ptr);

  Value *Shadow = UF.loadShadow(Ptr, StoreSize, LI.getAlign(), Ty, &LI);
  if (!UF.UC.isZeroShadow(Shadow))
    UF.NonZeroChecks.push_back(Shadow);

  UF.setShadow(&LI, Shadow);

  // Mark as checked for TaintPass
  LI.setMetadata("ucsan.checked",
                 MDNode::get(*UF.UC.Ctx, None));
}

void UCSanVisitor::visitStoreInst(StoreInst &SI) {
  if (SI.getMetadata("nosanitize")) return;

  auto &DL = SI.getModule()->getDataLayout();
  uint64_t StoreSize = DL.getTypeStoreSize(SI.getValueOperand()->getType());
  if (StoreSize == 0) return;

  Value *Ptr = SI.getPointerOperand();
  ConstantInt *Size = ConstantInt::get(UF.UC.Int64Ty, StoreSize);

  // Check and replace pointer
  IRBuilder<> IRB(&SI);
  Ptr = UF.checkPointer(Ptr, Size, true, IRB);
  SI.setOperand(SI.getPointerOperandIndex(), Ptr);

  Value *Val = SI.getValueOperand();
  Type *Ty = Val->getType();
  Value *Shadow = UF.getShadow(Val);
  UF.storeShadow(Ptr, StoreSize, SI.getAlign(), Shadow, Ty, &SI);

  // Mark as checked
  SI.setMetadata("ucsan.checked",
                 MDNode::get(*UF.UC.Ctx, None));
}

void UCSanVisitor::visitMemCpyInst(MemCpyInst &I) {
  IRBuilder<> IRB(&I);
  Value *Length = IRB.CreateZExtOrTrunc(I.getLength(), UF.UC.Int64Ty);
  if (Length != I.getLength()) {
    UF.UC.markNosanitize(Length);
  }

  // Check source and destination pointers
  Value *src = UF.checkPointer(I.getRawSource(), Length, true, IRB);
  Value *dest = UF.checkPointer(I.getRawDest(), Length, true, IRB);

  I.setSource(src);
  I.setDest(dest);

  // create a memcpy call to copy the shadow
  Value *ShadowLength = IRB.CreateMul(
      Length,
      ConstantInt::get(UF.UC.Int64Ty, UCSan::ShadowWidthBytes));
  UF.UC.markNosanitize(ShadowLength);
  auto MemCpyInst = llvm::Intrinsic::getDeclaration(I.getModule(),
      llvm::Intrinsic::memcpy,
      {UF.UC.PrimitiveShadowPtrTy, UF.UC.PrimitiveShadowPtrTy, UF.UC.Int64Ty});
  Value *CI = IRB.CreateCall(MemCpyInst,
      {UF.UC.getShadowAddress(dest, IRB),
       UF.UC.getShadowAddress(src, IRB),
       ShadowLength,
       I.getVolatileCst()});
  UF.UC.markNosanitize(CI);

  I.setMetadata("ucsan.checked", MDNode::get(*UF.UC.Ctx, None));
}

void UCSanVisitor::visitMemSetInst(MemSetInst &I) {
  IRBuilder<> IRB(&I);
  Value *Length = IRB.CreateZExtOrTrunc(I.getLength(), UF.UC.Int64Ty);
  if (Length != I.getLength()) {
    UF.UC.markNosanitize(Length);
  }

  // Check destination pointer
  Value *dest = UF.checkPointer(I.getRawDest(), Length, true, IRB);

  I.setDest(dest);

  // update shadow
  Value *ValShadow = UF.getShadow(I.getValue());
  Value *CI = IRB.CreateCall(UF.UC.UCSetLabelFn, {ValShadow, dest, Length});
  UF.UC.markNosanitize(CI);

  I.setMetadata("ucsan.checked", MDNode::get(*UF.UC.Ctx, None));
}

void UCSanVisitor::visitMemMoveInst(MemMoveInst &I) {
  IRBuilder<> IRB(&I);
  Value *Length = IRB.CreateZExtOrTrunc(I.getLength(), UF.UC.Int64Ty);
  if (Length != I.getLength()) {
    UF.UC.markNosanitize(Length);
  }

  // Check source and destination pointers
  Value *src = UF.checkPointer(I.getRawSource(), Length, true, IRB);
  Value *dest = UF.checkPointer(I.getRawDest(), Length, true, IRB);

  I.setDest(dest);
  I.setSource(src);

  // memmove shadow
  Value *DestShadowAddr = IRB.CreateBitCast(
      UF.UC.getShadowAddress(dest, IRB), UF.UC.VoidPtrTy);
  UF.UC.markNosanitize(DestShadowAddr);
  Value *SrcShadowAddr = IRB.CreateBitCast(
      UF.UC.getShadowAddress(src, IRB), UF.UC.VoidPtrTy);
  UF.UC.markNosanitize(SrcShadowAddr);
  Value *ShadowLength = IRB.CreateMul(
      Length,
      ConstantInt::get(UF.UC.Int64Ty, UCSan::ShadowWidthBytes));
  UF.UC.markNosanitize(ShadowLength);
  auto MemMoveDecl = llvm::Intrinsic::getDeclaration(I.getModule(),
      llvm::Intrinsic::memmove,
      {UF.UC.PrimitiveShadowPtrTy, UF.UC.PrimitiveShadowPtrTy, UF.UC.Int64Ty});
  auto *MTI = cast<llvm::MemMoveInst>(
      IRB.CreateCall(MemMoveDecl,
      {DestShadowAddr, SrcShadowAddr, ShadowLength, I.getVolatileCst()}));
  MTI->setDestAlignment(Align(UF.UC.ShadowWidthBytes));
  MTI->setSourceAlignment(Align(UF.UC.ShadowWidthBytes));
  UF.UC.markNosanitize(MTI);

  I.setMetadata("ucsan.checked", MDNode::get(*UF.UC.Ctx, None));
}

void UCSanVisitor::visitGetElementPtrInst(GetElementPtrInst &GEPI) {
  // use the type of the pointer operand to estimate object size
  Value *Ptr = GEPI.getPointerOperand();
  if (UF.CheckedPtrSet.count(Ptr) == 0 &&
      !isa<AllocaInst>(Ptr->stripPointerCasts())) {
    IRBuilder<> IRB(&GEPI);
    const DataLayout &DL = getDataLayout();
    Value *Size = ConstantInt::get(UF.UC.Int64Ty,
        DL.getTypeAllocSize(GEPI.getSourceElementType()));
    Value *Addr = IRB.CreateBitCast(Ptr, UF.UC.VoidPtrTy);
    UF.UC.markNosanitize(Addr);
    Value *Checked = IRB.CreateCall(UF.UC.UCCheckPointerFn,
      { Addr, UF.getShadow(Ptr), Size, ConstantInt::get(UF.UC.Int1Ty, false) });
    UF.UC.markNosanitize(Checked);
    UF.CheckedPtrSet.insert(Ptr);
  }
  // Propagate shadow through GEP
  Value *Shadow = UF.getShadow(Ptr);
  UF.setShadow(&GEPI, Shadow);
}

void UCSanVisitor::visitInlineAsm(InlineAsm *IA, CallBase &CB) {
  IRBuilder<> IRB(&CB);
  auto DL = CB.getModule()->getDataLayout();

  // first for each argument, use check pointer to get the real pointer
  for (unsigned I = 0; I < CB.arg_size(); ++I) {
    Value* Arg = CB.getArgOperand(I);
    Type* ArgTy = Arg->getType();
    if (ArgTy->isPointerTy()) {
      // if the arg is a compile time constant, we don't need to check
      if (isa<Constant>(Arg)) continue;
      // alloca doesn't need checking
      if (AllocaInst *AI = dyn_cast<AllocaInst>(Arg->stripPointerCasts())) {
        continue;
      }
      // get size of pointed-to type, if available
      unsigned ObjSize = 0;
      if (ArgTy->getPointerElementType()->isSized()) {
        ObjSize = DL.getTypeAllocSize(ArgTy->getPointerElementType());
      }

      Value *Size = ConstantInt::get(UF.UC.Int64Ty, ObjSize);
      Value *Ptr = UF.checkPointer(Arg, Size, true, IRB); // dereference pointer
      CB.setArgOperand(I, Ptr);
    }
  }

  // Next, handle specific inline assembly patterns
  // FIXME: inline asm
  auto AsmStr = IA->getAsmString();
  auto Constraints = IA->getConstraintString();

  if (AsmStr == " btq  $2,$1\x0A\x09/* output condition code c*/\x0A" &&
      Constraints == "={@ccc},*m,Ir,~{memory},~{dirflag},~{fpsr},~{flags}") {
    // handle bt instruction
    Value *BitBase = CB.getArgOperand(0);
    Value *BitOffset = CB.getArgOperand(1);
    Value *Load = IRB.CreateLoad(BitBase->getType()->getPointerElementType(), BitBase);
    UF.UC.markNosanitize(Load);
    Value *Shift = IRB.CreateShl(Load, BitOffset);
    UF.UC.markNosanitize(Shift);
    Value *And = IRB.CreateAnd(Shift, 1);
    UF.UC.markNosanitize(And);
    Value *Result = IRB.CreateTrunc(And, Type::getInt8Ty(*UF.UC.Ctx));
    UF.UC.markNosanitize(Result);

    CB.replaceAllUsesWith(Result);
    CB.eraseFromParent();
  } else if (AsmStr == ".byte 0x0f, 0x0b" &&
             Constraints == "~{dirflag},~{fpsr},~{flags}") {
    // handle ud2 instruction
    Value *Result = IRB.CreateCall(UF.UC.ExitFn,
                                   {ConstantInt::get(UF.UC.Int32Ty, 180)});
    UF.UC.markNosanitize(Result);
    CB.replaceAllUsesWith(Result);
    CB.eraseFromParent();
  } else if (AsmStr == "movq ${1:P}, $0" &&
             Constraints == "=r,im,~{dirflag},~{fpsr},~{flags}") {
    Type *PT = PointerType::getUnqual(CB.getType());
    Value *Base = IRB.CreateBitCast(CB.getArgOperand(0), PT);
    UF.UC.markNosanitize(Base);
    Value *Result = IRB.CreateLoad(PT, Base);
    UF.UC.markNosanitize(Result);
    CB.replaceAllUsesWith(Result);
    CB.eraseFromParent();
  } else if (AsmStr.find("__get_user_${") != StringRef::npos) {
    // handle __get_user_ inline assembly
    // get the number of bytes to read
    ConstantInt *SizeArg = dyn_cast<ConstantInt>(CB.getArgOperand(1));
    if (!SizeArg) {
      errs() << "Unsupported __get_user argument: " << CB << "\n";
      return;
    }
    unsigned Size = SizeArg->getZExtValue();
    if (Size != 1 && Size != 2 && Size != 4 && Size != 8) {
      errs() << "Unsupported size for __get_user: " << AsmStr << "\n";
      return;
    }
    // check uses before replacing
    for (auto *U : CB.users()) {
      if (auto *EI = dyn_cast<ExtractValueInst>(U)) {
        if (EI->getNumIndices() != 1) {
          errs() << "Unhandled extract of __get_user:" << *U << "\n";
          return;
        }
      } else {
        errs() << "Unhandled use of __get_user:" << *U << "\n";
        return;
      }
    }
    // replace with a load
    for (auto *U : CB.users()) {
      auto *EI = cast<ExtractValueInst>(U);
      auto Idx = EI->getIndices()[0];
      switch (Idx) {
        case 0: // return value
        {
          // replace with a nullptr
          auto *PTy = dyn_cast<PointerType>(EI->getType());
          assert(PTy && "Expected pointer type for __get_user return value 1");
          EI->replaceAllUsesWith(ConstantPointerNull::get(PTy));
          break;
        }
        case 1: // loaded value
        {
          LoadInst *LI = IRB.CreateLoad(EI->getType(), CB.getArgOperand(0));
          UF.UC.markNosanitize(LI);
          Value *Shadow = UF.loadShadow(CB.getArgOperand(0), Size, Align(1), EI->getType(), LI);
          UF.setShadow(LI, Shadow);
          EI->replaceAllUsesWith(LI);
          break;
        }
        case 2: // rsp
        {
          // use the original rsp value
          EI->replaceAllUsesWith(CB.getArgOperand(2));
          break;
        }
        default:
          errs() << "Unhandled index for __get_user: " << Idx << "\n";
      }
      // set as skipped
      UF.SkipInsts.insert(EI);
      // add for removal
      UF.RemovalInsts.push_back(EI);
    }
    CB.eraseFromParent();
  }

  return;
}

void UCSanVisitor::visitIndirectCallBase(Value *FPtr, CallBase &CB) {
  Value *Shadow = UF.getShadow(FPtr);
  Type *RT = CB.getFunctionType()->getReturnType();
  const DataLayout &DL = getDataLayout();

  // inline the under-constrained handling procedure
  // get the current basic block and its ID
  auto *curBB = CB.getParent();
  auto *BBID = curBB->getTerminator()->getMetadata(BBIDName);
  PHINode* RetPhiNode = nullptr;

  // check if the indirect called function is a valid one
  IRBuilder<> IRB(&CB);
  Instruction *TB, *EB;
  PointerType *FPtrTy = cast<PointerType>(FPtr->getType());
  // first, we check if the function pointer is null
  Value *Cond1 = IRB.CreateICmpNE(FPtr, ConstantPointerNull::get(FPtrTy));
  UF.UC.markNosanitize(Cond1);
  // second, we check if the function ptr is symbolic
  Value *Cond2 = IRB.CreateICmpEQ(Shadow, UF.UC.ZeroPrimitiveShadow);
  UF.UC.markNosanitize(Cond2);
  // Cond1 && Cond2
  Value *And = IRB.CreateAnd(Cond1, Cond2);
  UF.UC.markNosanitize(And);
  // if not null and not symbolic, we can call it directly
  SplitBlockAndInsertIfThenElse(And, &CB, &TB, &EB);
  // get the correct merge bb
  curBB = TB->getParent()->getSingleSuccessor();
  assert(curBB != nullptr && "Expected single successor after if-then-else");
  IRB.SetInsertPoint(curBB->getFirstNonPHI());
  // remove bbid from then else blocks, and reannotate current block
  if (BBID) {
    TB->getParent()->getTerminator()->setMetadata(BBIDName, nullptr);
    EB->getParent()->getTerminator()->setMetadata(BBIDName, nullptr);
    curBB->getTerminator()->setMetadata(BBIDName, BBID);
  }
  Value *retTB = nullptr, *retEB = nullptr;
  if (!RT->isVoidTy()) {
    RetPhiNode = IRB.CreatePHI(RT, 2);
    UF.UC.markNosanitize(RetPhiNode);
  }
  auto *FT = CB.getFunctionType();
  unsigned ArgOffset = 0;
  { // then block - *valid*: call the underlying function
    IRBuilder<> IRB_TB(TB);
    std::vector<Value *> Args;
    for (unsigned I = 0, N = FT->getNumParams(); I != N; ++I) {
      Value *Arg = CB.getArgOperand(I);
      unsigned Size = DL.getTypeAllocSize(UF.UC.getShadowTy(Arg));
      // Stop storing if arguments' size overflows. Inside a function, arguments
      // after overflow have zero shadow values.
      if (ArgOffset + Size > ArgTLSSize)
        break;
      StoreInst *SI = IRB_TB.CreateAlignedStore(
          UF.getShadow(CB.getArgOperand(I)),
          UF.getArgTLS(FT->getParamType(I), ArgOffset, IRB_TB),
          ShadowTLSAlignment);
      UF.UC.markNosanitize(SI);
      ArgOffset += alignTo(Size, ShadowTLSAlignment);
      Args.push_back(Arg);
    }
    retTB = IRB_TB.CreateCall(
        CB.getFunctionType(),
        FPtr,
        Args, "");
    if (RetPhiNode) RetPhiNode->addIncoming(retTB, IRB_TB.GetInsertBlock());
  }
  { // else block
    IRBuilder<> IRB_EB(EB);
    // resign shadow for args
    for (unsigned I = 0, N = FT->getNumParams(); I != N; ++I) {
      Value *Arg = CB.getArgOperand(I);
      unsigned Size = DL.getTypeAllocSize(UF.UC.getShadowTy(Arg));
      // Stop storing if arguments' size overflows. Inside a function, arguments
      // after overflow have zero shadow values.
      if (ArgOffset + Size > ArgTLSSize)
        break;
      if (getenv("KO_RESIGN_PTRARGS") && Arg->getType()->isPointerTy()) {
        // only resign ptr args
        std::vector<Value *> Args;
        ConstantInt *CI;
        if (Arg->getType()->getPointerElementType()->isSized()) {
          CI  = ConstantInt::get(UF.UC.Int64Ty,
              DL.getTypeSizeInBits(Arg->getType()->getPointerElementType()) / 8);
        } else {
          CI = ConstantInt::get(UF.UC.Int64Ty, 0);
        }
        auto BCI = IRB_EB.CreateBitCast(Arg, UF.UC.PrimitiveShadowPtrTy); // FIXME: cast to i32* (defined as void *)
        auto ArgTLS = UF.getArgTLS(Arg->getType(), ArgOffset, IRB_EB);
        Args.push_back(BCI);
        Args.push_back(ArgTLS);
        Args.push_back(CI);
        Args.push_back(ConstantPointerNull::get(UF.UC.VoidPtrTy));
        StoreInst *SI = IRB_EB.CreateAlignedStore(UF.getShadow(Arg), ArgTLS, ShadowTLSAlignment);
        UF.UC.markNosanitize(SI);
        CallInst *Call = IRB_EB.CreateCall(UF.UC.UCResignShadowFn, Args, "");
        UF.UC.markNosanitize(Call);
      }
      ArgOffset += alignTo(Size, ShadowTLSAlignment);
    }
    // wrap the returned value
    if (!RT->isVoidTy()) {
      std::vector<Value *> Args;
      ConstantInt *Size = ConstantInt::get(UF.UC.Int64Ty, DL.getTypeSizeInBits(RT));
      ConstantInt *isPtr = ConstantInt::get(UF.UC.Int1Ty, RT->isPointerTy());
      Args.push_back(Size);
      Args.push_back(UF.getRetvalTLS(RT, IRB_EB));
      Args.push_back(isPtr);
      Args.push_back(ConstantPointerNull::get(UF.UC.VoidPtrTy));
      Value *Ret = IRB_EB.CreateCall(UF.UC.UCWrapRetvalFn, Args, "");
      UF.UC.markNosanitize(Ret);
      if (!RT->isPointerTy()) { // if not a pointer return
        Type *PRT = RT->getPointerTo();
        Ret = IRB_EB.CreatePointerCast(Ret, PRT);
        UF.UC.markNosanitize(Ret);
        Ret = IRB_EB.CreateLoad(RT, Ret);
        UF.UC.markNosanitize(Ret);
      } else {
        Ret = IRB_EB.CreatePointerCast(Ret, RT);
        UF.UC.markNosanitize(Ret);
      }
      retEB = Ret;
      if (RetPhiNode) RetPhiNode->addIncoming(retEB, IRB_EB.GetInsertBlock());
    }
  }

  if (RetPhiNode) {
    UF.ValShadowMap[RetPhiNode] = UF.getShadow(&CB);
    CB.replaceAllUsesWith(RetPhiNode);
  }
  CB.eraseFromParent();

}

bool UCSanVisitor::visitWrappedCallBase(Function *F, CallBase &CB) {
  IRBuilder<> IRB(&CB);
  Value *Shadow = nullptr;
  const DataLayout &DL = getDataLayout();
  FunctionType *FT = F->getFunctionType();
  switch (UF.UC.getWrapperKind(F)) {
  case UCSan::WK_None:
    // No wrapper needed, fall through to default behavior
    llvm_unreachable("WK_None should not be handled here");
    return false;
  case UCSan::WK_AutoCustom:
    // invoke the custom function
    {
      int n = CB.arg_size(), I = 0;
      auto FT = CB.getFunctionType();
      unsigned ArgOffset = 0;

      for (auto arg = CB.arg_begin(); n != 0; ++arg, --n, I++) {
        unsigned Size =
            DL.getTypeAllocSize(UF.UC.getShadowTy(FT->getParamType(I)));
        // Stop storing if arguments' size overflows. Inside a function,
        // arguments after overflow have zero shadow values.
        if (ArgOffset + Size > ArgTLSSize)
          report_fatal_error("Argument size overflow in custom function");
        StoreInst *SI = IRB.CreateAlignedStore(
            UF.getShadow(CB.getArgOperand(I)),
            UF.getArgTLS(FT->getParamType(I), ArgOffset, IRB),
            ShadowTLSAlignment);
        UF.UC.markNosanitize(SI);
        ArgOffset += alignTo(Size, ShadowTLSAlignment);
      }

      CB.setCalledFunction(UF.UC.getCustomFunction(F));
      if (!FT->getReturnType()->isVoidTy()) {
        IRB.SetInsertPoint(CB.getNextNode());
        LoadInst *LI = IRB.CreateAlignedLoad(UF.UC.getShadowTy(&CB),
            UF.getRetvalTLS(CB.getType(), IRB),
            ShadowTLSAlignment, "_autoret");
        UF.UC.markNosanitize(LI);
        Shadow = LI;
        UF.setShadow(&CB, Shadow);
      }
    }
    return true;

  case UCSan::WK_Custom:
  {
    // Call the __dfsw_ wrapper with shadow arguments
    CallInst *CI = dyn_cast<CallInst>(&CB);
    if (!CI)
      return false;

    TransformedFunction CustomFn = UF.UC.getCustomFunctionType(FT);
    std::string CustomFName = "__dfsw_";
    CustomFName += F->getName();
    FunctionCallee CustomF =
        UF.UC.Mod->getOrInsertFunction(CustomFName, CustomFn.TransformedType);
    if (Function *CustomFnPtr = dyn_cast<Function>(CustomF.getCallee())) {
      CustomFnPtr->copyAttributesFrom(F);

      // Custom functions returning non-void will write to the return label.
      if (!FT->getReturnType()->isVoidTy()) {
        CustomFnPtr->removeFnAttrs(UF.UC.ReadOnlyNoneAttrs);
      }
    }

    std::vector<Value *> Args;

    // Adds non-variable arguments.
    auto *I = CB.arg_begin();
    for (unsigned N = FT->getNumParams(); N != 0; ++I, --N) {
      Type *T = (*I)->getType();
      if (isa<PointerType>(T)) {
        // Check pointer arguments before passing to custom function
        auto DL = getDataLayout();
        Value *sizeArg =
            ConstantInt::get(UF.UC.Int64Ty,
                             DL.getTypeAllocSize(T->getPointerElementType()));
        Value *rptr = UF.checkPointer(*I, sizeArg, true, IRB);
        Args.push_back(rptr);
      } else {
        Args.push_back(*I);
      }
    }

    // Then push shadow labels for each argument
    I = CB.arg_begin();
    const unsigned ShadowArgStart = Args.size();
    for (unsigned N = FT->getNumParams(); N != 0; ++I, --N) {
      Args.push_back(UF.getShadow(*I));
    }

    // For vararg functions, push shadow for varargs
    if (FT->isVarArg()) {
      auto *LabelVATy = ArrayType::get(UF.UC.PrimitiveShadowTy,
                                       CB.arg_size() - FT->getNumParams());
      auto *LabelVAAlloca = new AllocaInst(
          LabelVATy, getDataLayout().getAllocaAddrSpace(),
          "labelva", &UF.F->getEntryBlock().front());

      for (unsigned N = 0; I != CB.arg_end(); ++I, ++N) {
        auto *LabelVAPtr = IRB.CreateStructGEP(LabelVATy, LabelVAAlloca, N);
        UF.UC.markNosanitize(LabelVAPtr);
        auto *SI = IRB.CreateStore(UF.getShadow(*I), LabelVAPtr);
        UF.UC.markNosanitize(SI);
      }

      auto *VAA = IRB.CreateStructGEP(LabelVATy, LabelVAAlloca, 0);
      UF.UC.markNosanitize(VAA);
      Args.push_back(VAA);
    }

    // Add pointer to return label if function returns non-void
    Type *RetTy = FT->getReturnType();
    if (!RetTy->isVoidTy()) {
      if (!UF.LabelReturnAlloca) {
        UF.LabelReturnAlloca =
          new AllocaInst(UF.UC.getShadowTy(RetTy),
                         getDataLayout().getAllocaAddrSpace(),
                         "labelreturn", &UF.F->getEntryBlock().front());
      }
      Args.push_back(UF.LabelReturnAlloca);
    }

    // Add any remaining vararg arguments
    append_range(Args, drop_begin(CB.args(), FT->getNumParams()));

    CallInst *CustomCI = IRB.CreateCall(CustomF, Args);
    CustomCI->setCallingConv(CI->getCallingConv());
    CustomCI->setAttributes(TransformFunctionAttributes(
        CustomFn, *UF.UC.Ctx, CI->getAttributes()));
    UF.UC.markNosanitize(CustomCI);

    // Update the parameter attributes of the custom call instruction to
    // zero extend the shadow parameters. This is required for targets
    // which consider ShadowTy an illegal type.
    for (unsigned N = 0; N < FT->getNumParams(); N++) {
      const unsigned ArgNo = ShadowArgStart + N;
      if (CustomCI->getArgOperand(ArgNo)->getType() ==
          UF.UC.PrimitiveShadowTy) {
        CustomCI->addParamAttr(ArgNo, Attribute::ZExt);
      }
    }

    // Load the return value shadow
    if (!RetTy->isVoidTy()) {
        LoadInst *LabelLoad =
            IRB.CreateLoad(UF.UC.getShadowTy(RetTy), UF.LabelReturnAlloca);
        UF.UC.markNosanitize(LabelLoad);
        UF.setShadow(CustomCI, LabelLoad);
      }

      CI->replaceAllUsesWith(CustomCI);
      CI->eraseFromParent();
      return true;
    }
  }

  return false;
}

void UCSanVisitor::visitCallBase(CallBase &CB) {
  Function *F = CB.getCalledFunction();
  PHINode* RetPhiNode = nullptr;

  if (auto *IA = dyn_cast<InlineAsm>(CB.getCalledOperand())) {
    // handle inline assembly calls
    visitInlineAsm(IA, CB);
    return;
  }

  if (!F) {
    // indirect call
    visitIndirectCallBase(CB.getCalledOperand(), CB);
    return;
  }

  // intrinsics are handled elsewhere
  if (F->isIntrinsic()) {
    return;
  }

  DenseMap<Value *, Function *>::iterator UnwrappedFnIt =
      UF.UC.UnwrappedFnMap.find(F);
  if (UnwrappedFnIt != UF.UC.UnwrappedFnMap.end()) {
    if (visitWrappedCallBase(UnwrappedFnIt->second, CB))
      return;
  }

  IRBuilder<> IRB(&CB);
  FunctionType *FT = CB.getFunctionType();
  const DataLayout &DL = getDataLayout();

  // Stores argument shadows.
  if (F && F->hasName() && !F->getName().startswith("__dfsan") &&
      !F->getName().startswith("__taint")) {
    unsigned ArgOffset = 0;
    for (unsigned I = 0, N = FT->getNumParams(); I != N; ++I) {
      unsigned Size =
          DL.getTypeAllocSize(UF.UC.getShadowTy(FT->getParamType(I)));
      // Stop storing if arguments' size overflows. Inside a function, arguments
      // after overflow have zero shadow values.
      if (ArgOffset + Size > ArgTLSSize)
        break;
      StoreInst *SI = IRB.CreateAlignedStore(
          UF.getShadow(CB.getArgOperand(I)),
          UF.getArgTLS(FT->getParamType(I), ArgOffset, IRB),
          ShadowTLSAlignment);
      UF.UC.markNosanitize(SI);
      ArgOffset += alignTo(Size, ShadowTLSAlignment);
    }
  }

  Instruction *Next = nullptr;
  if (!CB.getType()->isVoidTy()) {
    if (InvokeInst *II = dyn_cast<InvokeInst>(&CB)) {
      if (II->getNormalDest()->getSinglePredecessor()) {
        Next = &II->getNormalDest()->front();
      } else {
        BasicBlock *NewBB =
            SplitEdge(II->getParent(), II->getNormalDest(), &UF.DT);
        Next = &NewBB->front();
      }
    } else {
      assert(CB.getIterator() != CB.getParent()->end());
      Next = CB.getNextNode();
    }

    // Don't emit the epilogue for musttail call returns.
    if (isa<CallInst>(CB) && cast<CallInst>(CB).isMustTailCall())
      return;

    IRBuilder<> NextIRB(Next);
    unsigned Size = DL.getTypeAllocSize(UF.UC.getShadowTy(&CB));
    if (Size > kRetvalTLSSize) {
      // Set overflowed return shadow to be zero.
      UF.setShadow(&CB, UF.UC.getZeroShadow(&CB));
    } else {
      LoadInst *LI = NextIRB.CreateAlignedLoad(
          UF.UC.getShadowTy(&CB), UF.getRetvalTLS(CB.getType(), NextIRB),
          ShadowTLSAlignment, "_dfsret");
      UF.UC.markNosanitize(LI);
      UF.SkipInsts.insert(LI);
      UF.setShadow(&CB, LI);
      UF.NonZeroChecks.push_back(LI);
    }
  }
}

void UCSanVisitor::visitCastInst(CastInst &CI) {
  // Propagate shadow through cast
  Value *Shadow = UF.getShadow(CI.getOperand(0));
  UF.setShadow(&CI, Shadow);
}

void UCSanVisitor::visitReturnInst(ReturnInst &RI) {
  IRBuilder<> IRB(&RI);

  // Pop stack frame before returning to free stack allocation labels
  CallInst *PopCall = IRB.CreateCall(UF.UC.UCPopStackFrameFn, {});
  UF.UC.markNosanitize(PopCall);

  if (RI.getReturnValue()) {
    Value *S = UF.getShadow(RI.getReturnValue());
    Type *RT = UF.F->getFunctionType()->getReturnType();
    unsigned Size = getDataLayout().getTypeAllocSize(UF.UC.getShadowTy(RT));
    if (Size <= kRetvalTLSSize) {
      StoreInst *SI = IRB.CreateAlignedStore(S, UF.getRetvalTLS(RT, IRB), ShadowTLSAlignment);
      UF.UC.markNosanitize(SI);
    }
  }

  if (ClTraceBB) {
    CallInst::Create(UF.UC.UCTraceBBFn,
      { ConstantInt::get(UF.UC.Int32Ty, -1), ConstantInt::get(UF.UC.Int32Ty, 0)},
      "", &RI);
  }
}

void UCSanVisitor::visitAtomicRMWInst(AtomicRMWInst &I) {
  auto &DL = I.getModule()->getDataLayout();
  Value *Ptr = I.getPointerOperand();
  Type *Ty = I.getType();
  unsigned StoreSize = DL.getTypeStoreSize(Ty);
  ConstantInt *Size = ConstantInt::get(UF.UC.Int64Ty, StoreSize);

  IRBuilder<> IRB(&I);
  Ptr = UF.checkPointer(Ptr, Size, true, IRB);
  I.setOperand(0, Ptr);

  // FIXME: AtomicRMWInst should not operate on ptrs
  UF.setShadow(&I, UF.UC.ZeroPrimitiveShadow);

  I.setMetadata("ucsan.checked", MDNode::get(*UF.UC.Ctx, None));
}

void UCSanVisitor::visitAllocaInst(AllocaInst &I) {
  Type *T = I.getAllocatedType();
  bool isArray = I.isArrayAllocation() || T->isArrayTy() || T->isStructTy();
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
    AllocaInst *AI = IRB.CreateAlloca(UF.UC.getShadowTy(T), I.getArraySize(),
                                      I.getName() + ".ucsan");
    UF.UC.markNosanitize(AI);
    UF.AllocaShadowMap[&I] = AI;
    if (getenv("KO_CHECKER_UBI")) {
      // Set shadow to kUninitializedLabel for UBI detection
      StoreInst *SI = IRB.CreateStore(UF.UC.UninitPrimitiveShadow, AI);
      UF.UC.markNosanitize(SI);
    }
  } else {
    // For complex allocas that aren't arrays/structs, set shadow memory to kUninitializedLabel
    if (getenv("KO_CHECKER_UBI") && !isArray) {
      IRBuilder<> IRB(I.getNextNode());
      auto DL = I.getModule()->getDataLayout();
      auto allocaSizeInBits = I.getAllocationSizeInBits(DL);
      if (allocaSizeInBits.hasValue()) {
        int allocaSizeInBytes = (allocaSizeInBits->getFixedValue() + 7) >> 3;
        Value* Size = ConstantInt::get(UF.UC.Int64Ty, allocaSizeInBytes);
        Value* Ptr = IRB.CreateBitOrPointerCast(&I, UF.UC.VoidPtrTy);
        if (Ptr != &I) { UF.UC.markNosanitize(Ptr); }
        CallInst *CI = IRB.CreateCall(UF.UC.UCSetLabelFn, {UF.UC.UninitPrimitiveShadow, Ptr, Size});
        UF.UC.markNosanitize(CI);
      }
    }
  }

  // Track bounds for stack allocations (arrays/structs)
  if (isArray) {
    // Insert after the alloca instruction to get the address
    BasicBlock::iterator ip(&I);
    IRBuilder<> IRB(I.getParent(), ++ip);

    // Get array size
    Value *Size = IRB.CreateZExtOrTrunc(I.getArraySize(), UF.UC.Int64Ty);
    if (Size != I.getArraySize()) {
      UF.UC.markNosanitize(Size);
    }

    // Get element size
    const DataLayout &DL = getDataLayout();
    uint64_t es = DL.getTypeAllocSize(I.getAllocatedType());
    ConstantInt *ElemSize = ConstantInt::get(UF.UC.Int64Ty, es);

    // Get address
    Value *Address = IRB.CreatePtrToInt(&I, UF.UC.Int64Ty);
    UF.UC.markNosanitize(Address);

    // Call runtime to track stack bounds: ucsan_trace_alloca(Size, ElemSize, Address)
    // (ucsan_trace_alloca sets shadow to kUninitializedLabel for UBI detection)
    CallInst *Bounds = IRB.CreateCall(UF.UC.UCTraceAllocaFn, {Size, ElemSize, Address});
    UF.UC.markNosanitize(Bounds);
    UF.setShadow(&I, Bounds);
  } else {
    UF.setShadow(&I, UF.UC.ZeroPrimitiveShadow);
  }
}

void UCSanVisitor::visitBranchInst(BranchInst &BI) {
  // Only check conditional branches
  if (BI.isUnconditional()) return;

  // Check if UBI checker is enabled
  if (!getenv("KO_CHECKER_UBI")) return;

  // Get shadow of branch condition
  Value *Condition = BI.getCondition();
  Value *Shadow = UF.getShadow(Condition);

  // Skip if shadow is statically known to be zero
  if (UF.UC.isZeroShadow(Shadow)) return;

  // Insert UBI check before the branch
  IRBuilder<> IRB(&BI);
  CallInst *CI = IRB.CreateCall(UF.UC.UCCheckUBIFn, {Shadow});
  UF.UC.markNosanitize(CI);
}

void UCSanVisitor::visitBinaryOperator(BinaryOperator &BO) {
  Value *Op1Shadow = UF.getShadow(BO.getOperand(0));
  Value *Op2Shadow = UF.getShadow(BO.getOperand(1));

  // If both shadows are zero, result is zero
  if (UF.UC.isZeroShadow(Op1Shadow) && UF.UC.isZeroShadow(Op2Shadow)) {
    UF.setShadow(&BO, UF.UC.getZeroShadow(&BO));
    return;
  }

  // Call runtime to combine labels
  IRBuilder<> IRB(&BO);
  CallInst *CombinedShadow = IRB.CreateCall(UF.UC.UCCombineLabelFn, {Op1Shadow, Op2Shadow});
  UF.UC.markNosanitize(CombinedShadow);
  UF.setShadow(&BO, CombinedShadow);
}

void UCSanVisitor::visitCmpInst(CmpInst &CI) {
  Value *Op1 = CI.getOperand(0);
  Value *Op2 = CI.getOperand(1);
  Value *Op1Shadow = UF.getShadow(Op1);
  Value *Op2Shadow = UF.getShadow(Op2);

  // If both shadows are zero, result is zero
  if (UF.UC.isZeroShadow(Op1Shadow) && UF.UC.isZeroShadow(Op2Shadow)) {
    UF.setShadow(&CI, UF.UC.getZeroShadow(&CI));
    return;
  }

  // If comparing with null pointer constant, just use the other operand's shadow
  if (isa<ConstantPointerNull>(Op1)) {
    UF.setShadow(&CI, Op2Shadow);
    return;
  }
  if (isa<ConstantPointerNull>(Op2)) {
    UF.setShadow(&CI, Op1Shadow);
    return;
  }

  // Call runtime to combine labels (comparing pointers is fine)
  IRBuilder<> IRB(&CI);
  CallInst *CombinedShadow = IRB.CreateCall(UF.UC.UCCombineLabelFn, {Op1Shadow, Op2Shadow});
  UF.UC.markNosanitize(CombinedShadow);
  UF.setShadow(&CI, CombinedShadow);
}

void UCSanVisitor::visitSelectInst(SelectInst &I) {
  Value *TrueShadow = UF.getShadow(I.getTrueValue());
  Value *FalseShadow = UF.getShadow(I.getFalseValue());

  Value *ShadowSel;
  if (TrueShadow == FalseShadow) {
    ShadowSel = TrueShadow;
  } else {
    ShadowSel = SelectInst::Create(I.getCondition(), TrueShadow, FalseShadow, "", &I);
  }
  UF.setShadow(&I, ShadowSel);
}

void UCSanVisitor::visitPHINode(PHINode &PN) {
  PHINode *ShadowPN =
      PHINode::Create(UF.UC.PrimitiveShadowTy, PN.getNumIncomingValues(), "", &PN);

  // Give the shadow phi node valid predecessors to fool SplitEdge into working.
  Value *UndefShadow = UndefValue::get(UF.UC.PrimitiveShadowTy);
  for (PHINode::block_iterator i = PN.block_begin(), e = PN.block_end(); i != e;
       ++i) {
    ShadowPN->addIncoming(UndefShadow, *i);
  }

  UF.PHIFixups.push_back({&PN, ShadowPN});
  UF.setShadow(&PN, ShadowPN);
}

bool UCSan::initializeModule(Module &M) {
  Triple TargetTriple(M.getTargetTriple());
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
  const DataLayout &DL = M.getDataLayout();

  // Initialize basic types
  Int1Ty = IntegerType::getInt1Ty(*Ctx);
  Int8Ty = IntegerType::getInt8Ty(*Ctx);
  Int16Ty = IntegerType::getInt16Ty(*Ctx);
  Int32Ty = IntegerType::getInt32Ty(*Ctx);
  Int64Ty = IntegerType::getInt64Ty(*Ctx);
  IntptrTy = M.getDataLayout().getIntPtrType(*Ctx);
  VoidPtrTy = PointerType::getUnqual(Int8Ty);

  PrimitiveShadowTy = IntegerType::get(*Ctx, ShadowWidthBits);  // 16-bit labels
  PrimitiveShadowPtrTy = PointerType::getUnqual(PrimitiveShadowTy);      // pointer to 16-bit shadow
  ZeroPrimitiveShadow = ConstantInt::getSigned(PrimitiveShadowTy, 0);
  UninitPrimitiveShadow = ConstantInt::getSigned(PrimitiveShadowTy, -1);
  ShadowPtrMul = ConstantInt::getSigned(IntptrTy, ShadowWidthBytes);  // 2 for 16-bit
  ShadowPtrAndMask = ShadowPtrXorMask = ShadowPtrBase = nullptr;
  if (MapParams->AndMask != 0)
    ShadowPtrAndMask = ConstantInt::get(IntptrTy, ~MapParams->AndMask);
  if (MapParams->XorMask != 0)
    ShadowPtrXorMask = ConstantInt::get(IntptrTy, MapParams->XorMask);
  if (MapParams->ShadowBase != 0)
    ShadowPtrBase = ConstantInt::get(IntptrTy, MapParams->ShadowBase);

  // Initialize runtime functions
  initializeRuntimeFunctions(M);

  // Load metadata
  if (!loadMetadata()) {
    report_fatal_error("Failed to load metadata");
  }
  initializeCustomFunctionTypes();

  // Initialize ABIList from command-line abilist files
  if (!ClABIListFiles.empty()) {
    std::vector<std::string> AllABIListFiles(ClABIListFiles.begin(), ClABIListFiles.end());
    ABIList.set(
        SpecialCaseList::createOrDie(AllABIListFiles, *vfs::getRealFileSystem()));
  }

  // Initialize ReadOnlyNoneAttrs for custom functions
  ReadOnlyNoneAttrs.addAttribute(Attribute::ReadOnly)
      .addAttribute(Attribute::ReadNone);

  return true;
}

bool UCSan::runImpl(Module &M) {
  initializeModule(M);
  bool Changed = false;

  Type *ArgTLSTy = ArrayType::get(Int64Ty, ArgTLSSize / 8);
  ArgTLS = Mod->getOrInsertGlobal("__ucsan_arg_tls", ArgTLSTy);
  if (GlobalVariable *G = dyn_cast<GlobalVariable>(ArgTLS)) {
    Changed |= G->getThreadLocalMode() != GlobalVariable::InitialExecTLSModel;
    G->setThreadLocalMode(GlobalVariable::InitialExecTLSModel);
  }

  Type *RetvalTLSTy = ArrayType::get(Int64Ty, kRetvalTLSSize / 8);
  RetvalTLS = Mod->getOrInsertGlobal("__ucsan_retval_tls", RetvalTLSTy);
  if (GlobalVariable *G = dyn_cast<GlobalVariable>(RetvalTLS)) {
    Changed |= G->getThreadLocalMode() != GlobalVariable::InitialExecTLSModel;
    G->setThreadLocalMode(GlobalVariable::InitialExecTLSModel);
  }

  std::vector<Function *> FnsToInstrument;
  std::vector<Function *> FnsOutOfScope;

  // make sure we have the entry function in metadata
  if (Scope.entry.empty()) {
    report_fatal_error("No entry function specified in metadata");
  }

  // Filter functions based on scope
  for (Function &F : M) {
    if (F.isIntrinsic()) continue;

    // Skip runtime functions (basic check)
    if (UCRuntimeFunctions.find(&F) != UCRuntimeFunctions.end()) {
      continue;
    }

    std::string FName = F.getName().str();

    // Check if function is in scope
    bool inScope = false;
    if (Scope.entry == FName) {
      inScope = true;
    } else {
      for (const auto &scopeFn : Scope.scope) {
        if (scopeFn == FName) {
          inScope = true;
          break;
        }
      }
    }

    if (inScope) {
      FnsToInstrument.push_back(&F);
    } else {
      if (getWrapperKind(&F) != WK_Custom &&
          getWrapperKind(&F) != WK_AutoCustom) {
        FnsOutOfScope.push_back(&F);
      } else {
        if (!F.isDeclaration()) F.deleteBody();
        UnwrappedFnMap[&F] = &F;
      }
    }

    if (Scope.entry != "main" && F.getName() == "main") {
      F.setName("__original$main");
    }
  }

  // Build dangle wrappers for out-of-scope functions
  for (Function *F : FnsOutOfScope) {
    if (Function *dangle = buildDangleFunction(F)) {
      F->replaceAllUsesWith(dangle);
      F->deleteBody();
    }
  }

  // Instrument in-scope functions
  for (Function *F : FnsToInstrument) {
    if (!F || F->isDeclaration()) continue;

    // Add driver wrapper for entry point
    bool isEntry = false;
    if (F->getName() == Scope.entry ||
        (Scope.entry == "main" && F->getName() == "__original$main")) {
      buildDriverWrapperFunction(F);
      isEntry = true;
    }

    // Annotate BBs for all functions (excluding entry)
    if (!isEntry) {
      unsigned int Idx = find(Scope.scope, F->getName()) - Scope.scope.begin() + 1;
      unsigned int BBCount = 0;
      for (Function::iterator BB = F->begin(); BB != F->end(); BB++, BBCount++) {
        auto *BBID = ConstantInt::get(Int32Ty, Idx * 100000 + BBCount);
        if (ClTraceBB) {
          CallInst::Create(UCTraceBBFn, {ConstantInt::get(Int32Ty, Idx), BBID},
                          "", &*BB->getFirstNonPHI());
        }
        MDNode *MD = MDNode::get(Mod->getContext(),
                                {ConstantAsMetadata::get(BBID)});
        BB->getTerminator()->setMetadata(BBIDName, MD);
      }
    }

    if (F->getLinkage() == GlobalValue::AvailableExternallyLinkage)
      F->setLinkage(GlobalValue::WeakAnyLinkage);

    // Instrument ALL functions (including entry point)
    removeUnreachableBlocks(*F);
    UCSanFunction UF(*this, F);

    // Insert push_stack_frame call at function entry for stack bounds tracking
    BasicBlock &EntryBB = F->getEntryBlock();
    IRBuilder<> EntryIRB(&*(EntryBB.getFirstInsertionPt()));
    CallInst *PushCall = EntryIRB.CreateCall(UCPushStackFrameFn, {});
    markNosanitize(PushCall);

    // UCSanVisitor may create new basic blocks, which confuses df_iterator.
    // Build a copy of the list before iterating over it.
    SmallVector<BasicBlock *, 4> BBList(depth_first(&F->getEntryBlock()));
    for (BasicBlock *BB : BBList) {
      Instruction *Inst = &BB->front();
      while (true) {
        // UCSanVisitor may split the current basic block, changing the current
        // instruction's next pointer and moving the next instruction to the
        // tail block from which we should continue.
        Instruction *Next = Inst->getNextNode();
        // UCSanVisitor may delete Inst, so keep track of whether it was a
        // terminator.
        bool IsTerminator = Inst->isTerminator();
        if (!UF.SkipInsts.count(Inst))
          UCSanVisitor(UF).visit(Inst);

        if (IsTerminator) break;
        Inst = Next;
      }
    }

    // We will not necessarily be able to compute the shadow for every phi node
    // until we have visited every block.  Therefore, the code that handles phi
    // nodes adds them to the PHIFixups list so that they can be properly
    // handled here.
    for (auto &P : UF.PHIFixups) {
      for (unsigned Val = 0, N = P.Phi->getNumIncomingValues(); Val != N;
           ++Val) {
        P.ShadowPhi->setIncomingValue(
            Val, UF.getShadow(P.Phi->getIncomingValue(Val)));
      }
    }

    // Removal instructions
    for (auto *RI : UF.RemovalInsts)
      RI->eraseFromParent();
  }

  // Fix initializer for declared global variables with external linkage
  for (GlobalVariable &GV : M.globals()) {
    if (GV.isDeclaration() && GV.hasExternalLinkage()) {
      GV.setLinkage(GlobalValue::WeakAnyLinkage);
      Constant *ZeroInit = Constant::getNullValue(GV.getValueType());
      GV.setInitializer(ZeroInit);
    }
  }

  return true;
}

} // anonymous namespace

namespace {
class UCSanPass : public PassInfoMixin<UCSanPass> {
public:
  UCSanPass() = default;

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    if (UCSan().runImpl(M)) {
      return PreservedAnalyses::none();
    }
    return PreservedAnalyses::all();
  }

  static bool isRequired() { return true; }
};
} // anonymous namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "UCSanPass", "v1.0",
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(UCSanPass());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "ucsan") {
                    MPM.addPass(UCSanPass());
                    return true;
                  }
                  return false;
                });
          }};
}
