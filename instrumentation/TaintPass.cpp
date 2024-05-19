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
#include "version.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/None.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
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
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Value.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DJB.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include <functional>

using namespace llvm;

// This must be consistent with ShadowWidthBits.
static const Align kShadowTLSAlignment = Align(4);

// The size of TLS variables. These constants must be kept in sync with the ones
// in dfsan.cpp.
static const unsigned kArgTLSSize = 800;
static const unsigned kRetvalTLSSize = 800;

// External symbol to be used when generating the shadow address for
// architectures with multiple VMAs. Instead of using a constant integer
// the runtime will set the external mask based on the VMA range.
const char kTaintExternShadowPtrMask[] = "__taint_shadow_ptr_mask";

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
// unknown.  The other supported annotations are "functional" and "discard",
// which are described below under Taint::WrapperKind.
static cl::list<std::string> ClABIListFiles(
    "taint-abilist",
    cl::desc("File listing native ABI functions and how the pass treats them"),
    cl::Hidden);

// Controls whether the pass uses IA_Args or IA_TLS as the ABI for instrumented
// functions (see Taint::InstrumentedABI below).
static cl::opt<bool> ClArgsABI(
    "taint-args-abi",
    cl::desc("Use the argument ABI rather than the TLS ABI"),
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

static cl::opt<bool> ClTraceGEPOffset(
    "taint-trace-gep",
    cl::desc("Trace GEP offset for solving."),
    cl::Hidden, cl::init(true));

static cl::opt<bool> ClTraceFP(
    "taint-trace-float-pointer",
    cl::desc("Propagate taint for floating pointer instructions."),
    cl::Hidden, cl::init(false));

static cl::opt<bool> ClTraceBound(
    "taint-trace-bound",
    cl::desc("Trace buffer bound info."),
    cl::Hidden, cl::init(true));

static StringRef GetGlobalTypeString(const GlobalValue &G) {
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
           SCL->inSection("dataflow", "type", GetGlobalTypeString(GA),
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
  /// position.  Argument positions are zero-indexed.  If the transformation
  /// from F to F' made the first argument of F into the third argument of F',
  /// then ArgumentIndexMapping[0] will equal 2.
  std::vector<unsigned> ArgumentIndexMapping;
};

/// Given function attributes from a call site for the original function,
/// return function attributes appropriate for a call to the transformed
/// function.
AttributeList TransformFunctionAttributes(
    const TransformedFunction& TransformedFunction,
    LLVMContext& Ctx, AttributeList CallSiteAttrs) {

  // Construct a vector of AttributeSet for each function argument.
  std::vector<llvm::AttributeSet> ArgumentAttributes(
      TransformedFunction.TransformedType->getNumParams());

  // Copy attributes from the parameter of the original function to the
  // transformed version.  'ArgumentIndexMapping' holds the mapping from
  // old argument position to new.
  for (unsigned i = 0, ie = TransformedFunction.ArgumentIndexMapping.size();
       i < ie; ++i) {
    unsigned TransformedIndex = TransformedFunction.ArgumentIndexMapping[i];
    ArgumentAttributes[TransformedIndex] = CallSiteAttrs.getParamAttributes(i);
  }

  // Copy annotations on varargs arguments.
  for (unsigned i = TransformedFunction.OriginalType->getNumParams(),
       ie = CallSiteAttrs.getNumAttrSets(); i < ie; ++i) {
    ArgumentAttributes.push_back(CallSiteAttrs.getParamAttributes(i));
  }

  return AttributeList::get(
      Ctx,
      CallSiteAttrs.getFnAttributes(),
      CallSiteAttrs.getRetAttributes(),
      llvm::makeArrayRef(ArgumentAttributes));
}

class Taint : public ModulePass {
  friend struct TaintFunction;
  friend class TaintVisitor;

  enum {
    ShadowWidthBits  = 32,
    ShadowWidthBytes = ShadowWidthBits / 8
  };

  /// Which ABI should be used for instrumented functions?
  enum InstrumentedABI {
    /// Argument and return value labels are passed through additional
    /// arguments and by modifying the return type.
    IA_Args,

    /// Argument and return value labels are passed through TLS variables
    /// __dfsan_arg_tls and __dfsan_retval_tls.
    IA_TLS
  };

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
  };

  Module *Mod;
  LLVMContext *Ctx;
  IntegerType *Int8Ty;
  IntegerType *Int16Ty;
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  IntegerType *IntptrTy;
  /// The shadow type for all primitive types and vector types.
  IntegerType *PrimitiveShadowTy;
  PointerType *PrimitiveShadowPtrTy;
  ConstantInt *ZeroPrimitiveShadow;
  ConstantInt *UninitializedPrimitiveShadow;
  ConstantInt *ShadowPtrMask;
  ConstantInt *ShadowPtrMul;
  Constant *ArgTLS;
  Constant *RetvalTLS;
  Constant *ExternalShadowMask;
  FunctionType *TaintUnionFnTy;
  FunctionType *TaintUnionLoadFnTy;
  FunctionType *TaintUnionStoreFnTy;
  FunctionType *TaintUnimplementedFnTy;
  FunctionType *TaintSetLabelFnTy;
  FunctionType *TaintNonzeroLabelFnTy;
  FunctionType *TaintVarargWrapperFnTy;
  FunctionType *TaintTraceCmpFnTy;
  FunctionType *TaintTraceCondFnTy;
  FunctionType *TaintTraceIndirectCallFnTy;
  FunctionType *TaintTraceGEPFnTy;
  FunctionType *TaintPushStackFrameFnTy;
  FunctionType *TaintPopStackFrameFnTy;
  FunctionType *TaintTraceAllocaFnTy;
  FunctionType *TaintCheckBoundsFnTy;
  FunctionType *TaintMemcmpFnTy;
  FunctionType *TaintStrcmpFnTy;
  FunctionType *TaintStrncmpFnTy;
  FunctionType *TaintDebugFnTy;
  FunctionCallee TaintUnionFn;
  FunctionCallee TaintCheckedUnionFn;
  FunctionCallee TaintUnionLoadFn;
  FunctionCallee TaintUnionStoreFn;
  FunctionCallee TaintUnimplementedFn;
  FunctionCallee TaintSetLabelFn;
  FunctionCallee TaintNonzeroLabelFn;
  FunctionCallee TaintVarargWrapperFn;
  FunctionCallee TaintTraceCmpFn;
  FunctionCallee TaintTraceCondFn;
  FunctionCallee TaintTraceIndirectCallFn;
  FunctionCallee TaintTraceGEPFn;
  FunctionCallee TaintPushStackFrameFn;
  FunctionCallee TaintPopStackFrameFn;
  FunctionCallee TaintTraceAllocaFn;
  FunctionCallee TaintCheckBoundsFn;
  FunctionCallee TaintMemcmpFn;
  FunctionCallee TaintStrcmpFn;
  FunctionCallee TaintStrncmpFn;
  FunctionCallee TaintDebugFn;
  Constant *CallStack;
  MDNode *ColdCallWeights;
  TaintABIList ABIList;
  DenseMap<Value *, Function *> UnwrappedFnMap;
  AttrBuilder ReadOnlyNoneAttrs;
  bool TaintRuntimeShadowMask = false;

  Value *getShadowAddress(Value *Addr, IRBuilder<> &IRB);
  bool isInstrumented(const Function *F);
  bool isInstrumented(const GlobalAlias *GA);
  FunctionType *getArgsFunctionType(FunctionType *T);
  FunctionType *getTrampolineFunctionType(FunctionType *T);
  TransformedFunction getCustomFunctionType(FunctionType *T);
  InstrumentedABI getInstrumentedABI();
  WrapperKind getWrapperKind(Function *F);
  void addGlobalNamePrefix(GlobalValue *GV);
  Function *buildWrapperFunction(Function *F, StringRef NewFName,
                                 GlobalValue::LinkageTypes NewFLink,
                                 FunctionType *NewFT);
  Constant *getOrBuildTrampolineFunction(FunctionType *FT, StringRef FName);

  void addContextRecording(Function &F);
  void addFrameTracing(Function &F);

  void initializeRuntimeFunctions(Module &M);
  void initializeCallbackFunctions(Module &M);
  uint32_t getInstructionId(Instruction *Inst);

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

public:
  static char ID;

  Taint(
      const std::vector<std::string> &ABIListFiles = std::vector<std::string>());

  bool doInitialization(Module &M) override;
  bool runOnModule(Module &M) override;
};

struct TaintFunction {
  Taint &TT;
  Function *F;
  DominatorTree DT;
  Taint::InstrumentedABI IA;
  bool IsNativeABI;
  Value *ArgTLSPtr = nullptr;
  Value *RetvalTLSPtr = nullptr;
  AllocaInst *LabelReturnAlloca = nullptr;
  DenseMap<Value *, Value *> ValShadowMap;
  DenseMap<AllocaInst *, AllocaInst *> AllocaShadowMap;
  std::vector<std::pair<PHINode *, PHINode *>> PHIFixups;
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

  TaintFunction(Taint &TT, Function *F, bool IsNativeABI)
      : TT(TT), F(F), IA(TT.getInstrumentedABI()), IsNativeABI(IsNativeABI) {
    DT.recalculate(*F);
    // FIXME: Need to track down the register allocator issue which causes poor
    // performance in pathological cases with large numbers of basic blocks.
    AvoidNewBlocks = F->size() > 1000;
    srandom(std::hash<std::string>{}(F->getName().str()));
  }

  /// Computes the shadow address for a given function argument.
  ///
  /// Shadow = ArgTLS+ArgOffset.
  Value *getArgTLS(Type *T, unsigned ArgOffset, IRBuilder<> &IRB);

  /// Computes the shadow address for a retval.
  Value *getRetvalTLS(Type *T, IRBuilder<> &IRB);

  Value *getShadow(Value *V);
  void setShadow(Instruction *I, Value *Shadow);
  // Op Shadow
  Value *combineShadows(Value *V1, Value *V2,
                        uint16_t op, Instruction *Pos);
  Value *combineBinaryOperatorShadows(BinaryOperator *BO, uint8_t op);
  Value *combineCastInstShadows(CastInst *CI, uint8_t op);
  Value *combineCmpInstShadows(CmpInst *CI, uint8_t op);
  void visitCmpInst(CmpInst *I);
  void visitSwitchInst(SwitchInst *I);
  void visitCondition(Value *Cond, Instruction *I);
  void visitGEPInst(GetElementPtrInst *I);
  Value *visitAllocaInst(AllocaInst *I);
  void checkBounds(Value *Ptr, Value *Size, Instruction *Pos);

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
  Value *loadShadow(Type *T, Value *Addr, uint64_t Size, uint64_t Align,
                    Instruction *Pos);

  /// XXX: we do not union taint labels for aggregate types before store;
  ///      instead, we store each privimitive field individually.
  ///
  /// Store all primitive subtypes of T, using the aggrate shadow value.
  ///
  /// SS(Addr, {T1,T2, ...}) = SS(SubAddr, T1), SS(SubAddr, T2), ...
  /// SS(Addr, [T1,T2,...]) = SS(SubAddr, T1), SS(SubAddr, T2), ...
  /// SS(Addr, PS) = SS(Addr, PS)
  void storeShadow(Value *Addr, uint64_t Size, Align Alignment,
                   Value *Shadow, Instruction *Pos);

private:
  /// Loads a primitive shadow label
  Value *loadPrimitiveShadow(Value *Addr, uint64_t Size, uint64_t Align,
                             IRBuilder<> &IRB);
  /// Loads shadow recursively for aggregate types
  void loadShadowRecursive(Value *Shadow, SmallVector<unsigned, 4> &Indices,
                           Type *SubTy, Value *Addr, uint64_t Size,
                           uint64_t Align, IRBuilder<> &IRB);
  /// Stores an aggregate shadow label
  void storeShadowRecursive(Value *Shadow, SmallVector<unsigned, 4> &Indices,
                            Type *SubShadowTy, Value *ShadowAddr, uint64_t Size,
                            uint64_t Align, IRBuilder<> &IRB);
  /// Returns the shadow value of an argument A.
  Value *getShadowForTLSArgument(Argument *A);
};

class TaintVisitor : public InstVisitor<TaintVisitor> {
public:
  TaintFunction &TF;

  TaintVisitor(TaintFunction &TF) : TF(TF) {}

  const DataLayout &getDataLayout() const {
    return TF.F->getParent()->getDataLayout();
  }

  //void visitUnaryOperator(UnaryOperator &UO);
  void visitBinaryOperator(BinaryOperator &BO);
  void visitBranchInst(BranchInst &BR);
  void visitCastInst(CastInst &CI);
  void visitCmpInst(CmpInst &CI);
  void visitSwitchInst(SwitchInst &SWI);
  void visitGetElementPtrInst(GetElementPtrInst &GEPI);
  void visitLoadInst(LoadInst &LI);
  void visitStoreInst(StoreInst &SI);
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
};

} // end anonymous namespace

char Taint::ID;

#if 0
INITIALIZE_PASS(Taint, "taint",
                "Taint: dynamic taint analysis.", false, false)

ModulePass *
llvm::createTaintPass(const std::vector<std::string> &ABIListFiles,
                      void *(*getArgTLS)(),
                      void *(*getRetValTLS)()) {
  // remove default one to support FTS build
  std::vector<std::string> Files =
    const_cast<std::vector<std::string> &>(ABIListFiles);
  if (Files.size() > 1)
    Files.erase(Files.begin());
  return new Taint(Files, getArgTLS, getRetValTLS);
}
#endif

Taint::Taint(
    const std::vector<std::string> &ABIListFiles)
    : ModulePass(ID) {
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

FunctionType *Taint::getTrampolineFunctionType(FunctionType *T) {
  assert(!T->isVarArg());
  SmallVector<Type *, 4> ArgTypes;
  ArgTypes.push_back(T->getPointerTo());
  ArgTypes.append(T->param_begin(), T->param_end());
  // we keep the shadow type consistent with the arg type so we don't
  // need to collapse or expand the shadow
  for (unsigned i = 0, ie = T->getNumParams(); i != ie; ++i) {
    Type* param_type = T->getParamType(i);
    ArgTypes.push_back(getShadowTy(param_type));
  }
  // ArgTypes.append(T->getNumParams(), PrimitiveShadowTy);
  Type *RetType = T->getReturnType();
  if (!RetType->isVoidTy())
    ArgTypes.push_back(PointerType::getUnqual(getShadowTy(RetType)));
  return FunctionType::get(T->getReturnType(), ArgTypes, false);
}

TransformedFunction Taint::getCustomFunctionType(FunctionType *T) {
  SmallVector<Type *, 4> ArgTypes;

  // Some parameters of the custom function being constructed are
  // parameters of T.  Record the mapping from parameters of T to
  // parameters of the custom function, so that parameter attributes
  // at call sites can be updated.
  std::vector<unsigned> ArgumentIndexMapping;
  for (unsigned i = 0, ie = T->getNumParams(); i != ie; ++i) {
    Type* param_type = T->getParamType(i);
    FunctionType *FT;
    if (isa<PointerType>(param_type) &&
        (FT = dyn_cast<FunctionType>(
             cast<PointerType>(param_type)->getElementType()))) {
      ArgumentIndexMapping.push_back(ArgTypes.size());
      ArgTypes.push_back(getTrampolineFunctionType(FT)->getPointerTo());
      ArgTypes.push_back(Type::getInt8PtrTy(*Ctx));
    } else {
      ArgumentIndexMapping.push_back(ArgTypes.size());
      ArgTypes.push_back(param_type);
    }
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
    ArgTypes.push_back(getShadowTy(RetType));
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
  static uint32_t unamed = 0;
  auto SourceInfo = Mod->getSourceFileName();
  DILocation *Loc = Inst->getDebugLoc();
  if (Loc) {
    auto Line = Loc->getLine();
    auto Col = Loc->getColumn();
    SourceInfo += ":" + std::to_string(Line) + ":" + std::to_string(Col);
  } else {
    SourceInfo += "unamed:" + std::to_string(unamed++);
  }

  return djbHash(SourceInfo);
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
  if (FName.startswith("dfs")) {
    size_t pos = FName.find_first_of('$');
    FName = FName.drop_front(pos + 1);
  }
  // add source file name for static function
  if (!F.hasExternalLinkage()) {
    FName = StringRef(Mod->getSourceFileName() + "::" + FName.str());
  }
  uint32_t hash = djbHash(FName);

  ConstantInt *CID = ConstantInt::get(Int32Ty, hash);
  LoadInst *LCS = IRB.CreateLoad(CallStack);
  LCS->setMetadata(Mod->getMDKindID("nosanitize"), MDNode::get(*Ctx, None));
  Value *NCS = IRB.CreateXor(LCS, CID);
  StoreInst *SCS = IRB.CreateStore(NCS, CallStack);
  SCS->setMetadata(Mod->getMDKindID("nosanitize"), MDNode::get(*Ctx, None));

  // Recover ctx at the end of a function
  for (auto FI = F.begin(), FE = F.end(); FI != FE; FI++) {
    BasicBlock *BB = &*FI;
    Instruction *Inst = BB->getTerminator();
    if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {
      IRB.SetInsertPoint(Inst);
      SCS = IRB.CreateStore(LCS, CallStack);
      SCS->setMetadata(Mod->getMDKindID("nosanitize"), MDNode::get(*Ctx, None));
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

bool Taint::doInitialization(Module &M) {
  Triple TargetTriple(M.getTargetTriple());
  bool IsX86_64 = TargetTriple.getArch() == Triple::x86_64;
  bool IsMIPS64 = TargetTriple.isMIPS64();
  bool IsAArch64 = TargetTriple.getArch() == Triple::aarch64 ||
                   TargetTriple.getArch() == Triple::aarch64_be;

  const DataLayout &DL = M.getDataLayout();

  Mod = &M;
  Ctx = &M.getContext();
  Int8Ty = IntegerType::get(*Ctx, 8);
  Int16Ty = IntegerType::get(*Ctx, 16);
  Int32Ty = IntegerType::get(*Ctx, 32);
  Int64Ty = IntegerType::get(*Ctx, 64);
  PrimitiveShadowTy = IntegerType::get(*Ctx, ShadowWidthBits);
  PrimitiveShadowPtrTy = PointerType::getUnqual(PrimitiveShadowTy);
  IntptrTy = DL.getIntPtrType(*Ctx);
  ZeroPrimitiveShadow = ConstantInt::getSigned(PrimitiveShadowTy, 0);
  UninitializedPrimitiveShadow = ConstantInt::getSigned(PrimitiveShadowTy, -1);
  ShadowPtrMul = ConstantInt::getSigned(IntptrTy, ShadowWidthBytes);
  if (IsX86_64)
    ShadowPtrMask = ConstantInt::getSigned(IntptrTy, ~0x700000000000LL);
  else if (IsMIPS64)
    ShadowPtrMask = ConstantInt::getSigned(IntptrTy, ~0xF000000000LL);
  // AArch64 supports multiple VMAs and the shadow mask is set at runtime.
  else if (IsAArch64)
    TaintRuntimeShadowMask = true;
  else
    report_fatal_error("unsupported triple");

  Type *TaintUnionArgs[6] = { PrimitiveShadowTy, PrimitiveShadowTy, Int16Ty, Int16Ty, Int64Ty, Int64Ty};
  TaintUnionFnTy = FunctionType::get(
      PrimitiveShadowTy, TaintUnionArgs, /*isVarArg=*/ false);
  Type *TaintUnionLoadArgs[2] = { PrimitiveShadowPtrTy, IntptrTy };
  TaintUnionLoadFnTy = FunctionType::get(
      PrimitiveShadowTy, TaintUnionLoadArgs, /*isVarArg=*/ false);
  Type *TaintUnionStoreArgs[3] = { PrimitiveShadowTy, PrimitiveShadowPtrTy, IntptrTy };
  TaintUnionStoreFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), TaintUnionStoreArgs, /*isVarArg=*/ false);
  TaintUnimplementedFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), Type::getInt8PtrTy(*Ctx), /*isVarArg=*/false);
  Type *TaintSetLabelArgs[3] = { PrimitiveShadowTy, Type::getInt8PtrTy(*Ctx), IntptrTy };
  TaintSetLabelFnTy = FunctionType::get(Type::getVoidTy(*Ctx),
                                        TaintSetLabelArgs, /*isVarArg=*/false);
  TaintNonzeroLabelFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), None, /*isVarArg=*/false);
  TaintVarargWrapperFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), Type::getInt8PtrTy(*Ctx), /*isVarArg=*/false);
  Type *TaintTraceCmpArgs[7] = { PrimitiveShadowTy, PrimitiveShadowTy,
      PrimitiveShadowTy, PrimitiveShadowTy,
      Int64Ty, Int64Ty, Int32Ty };
  TaintTraceCmpFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), TaintTraceCmpArgs, false);
  Type *TaintTraceCondArgs[3] = { PrimitiveShadowTy, Int8Ty, Int32Ty };
  TaintTraceCondFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), TaintTraceCondArgs, false);
  TaintTraceIndirectCallFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), { PrimitiveShadowTy }, false);
  Type *TaintTraceGEPArgs[7] = { PrimitiveShadowTy, Int64Ty, PrimitiveShadowTy,
      Int64Ty, Int64Ty, Int64Ty, Int64Ty };
  TaintTraceGEPFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), TaintTraceGEPArgs, false);
  TaintPushStackFrameFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), {}, false);
  TaintPopStackFrameFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), {}, false);
  Type *TaintTraceAllocaArgs[4] = { PrimitiveShadowTy, Int64Ty, Int64Ty, Int64Ty };
  TaintTraceAllocaFnTy = FunctionType::get(
      PrimitiveShadowTy, TaintTraceAllocaArgs, false);
  TaintCheckBoundsFnTy = FunctionType::get(
      Type::getVoidTy(*Ctx), { PrimitiveShadowTy, Int64Ty, PrimitiveShadowTy, Int64Ty }, false);

  TaintMemcmpFnTy = FunctionType::get(
      PrimitiveShadowTy, { Type::getInt8PtrTy(*Ctx), Type::getInt8PtrTy(*Ctx), Int64Ty }, false);
  TaintStrcmpFnTy = FunctionType::get(
      PrimitiveShadowTy, { Type::getInt8PtrTy(*Ctx), Type::getInt8PtrTy(*Ctx) }, false);
  TaintStrncmpFnTy = FunctionType::get(
      PrimitiveShadowTy, { Type::getInt8PtrTy(*Ctx), Type::getInt8PtrTy(*Ctx), Int64Ty }, false);

  TaintDebugFnTy = FunctionType::get(Type::getVoidTy(*Ctx),
      {PrimitiveShadowTy, PrimitiveShadowTy, PrimitiveShadowTy,
       PrimitiveShadowTy, PrimitiveShadowTy}, false);

  ColdCallWeights = MDBuilder(*Ctx).createBranchWeights(1, 1000);
  return true;
}

bool Taint::isInstrumented(const Function *F) {
  return !ABIList.isIn(*F, "uninstrumented");
}

bool Taint::isInstrumented(const GlobalAlias *GA) {
  return !ABIList.isIn(*GA, "uninstrumented");
}

Taint::InstrumentedABI Taint::getInstrumentedABI() {
  return ClArgsABI ? IA_Args : IA_TLS;
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
  if (ABIList.isIn(*F, "functional"))
    return WK_Functional;
  if (ABIList.isIn(*F, "discard"))
    return WK_Discard;

  return WK_Warning;
}

void Taint::addGlobalNamePrefix(GlobalValue *GV) {
  std::string GVName = std::string(GV->getName()), Prefix = "dfs$";
  GV->setName(Prefix + GVName);

  // Try to change the name of the function in module inline asm.  We only do
  // this for specific asm directives, currently only ".symver", to try to avoid
  // corrupting asm which happens to contain the symbol name as a substring.
  // Note that the substitution for .symver assumes that the versioned symbol
  // also has an instrumented name.
  std::string Asm = GV->getParent()->getModuleInlineAsm();
  std::string SearchStr = ".symver " + GVName + ",";
  size_t Pos = Asm.find(SearchStr);
  if (Pos != std::string::npos) {
    Asm.replace(Pos, SearchStr.size(),
                ".symver " + Prefix + GVName + "," + Prefix);
    GV->getParent()->setModuleInlineAsm(Asm);
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
  NewF->removeAttributes(
      AttributeList::ReturnIndex,
      AttributeFuncs::typeIncompatible(NewFT->getReturnType()));

  BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", NewF);
  if (F->isVarArg() && getWrapperKind(F) != WK_Custom) {
    // keep the invocation if custom (e.g., open)
    NewF->removeAttributes(AttributeList::FunctionIndex,
                           AttrBuilder().addAttribute("split-stack"));
    CallInst::Create(TaintVarargWrapperFn,
                     IRBuilder<>(BB).CreateGlobalStringPtr(F->getName()), "",
                     BB);
    new UnreachableInst(*Ctx, BB);
  } else {
    std::vector<Value *> Args;
    unsigned n = FT->getNumParams();
    for (Function::arg_iterator ai = NewF->arg_begin(); n != 0; ++ai, --n)
      Args.push_back(&*ai);
    CallInst *CI = CallInst::Create(F, Args, "", BB);
    if (FT->getReturnType()->isVoidTy())
      ReturnInst::Create(*Ctx, BB);
    else
      ReturnInst::Create(*Ctx, CI, BB);
  }

  return NewF;
}

Constant *Taint::getOrBuildTrampolineFunction(FunctionType *FT,
                                              StringRef FName) {
  FunctionType *FTT = getTrampolineFunctionType(FT);
  FunctionCallee C = Mod->getOrInsertFunction(FName, FTT);
  Function *F = dyn_cast<Function>(C.getCallee());
  if (F && F->isDeclaration()) {
    F->setLinkage(GlobalValue::LinkOnceODRLinkage);
    BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", F);
    std::vector<Value *> Args;
    Function::arg_iterator AI = F->arg_begin(); ++AI;
    for (unsigned N = FT->getNumParams(); N != 0; ++AI, --N)
      Args.push_back(&*AI);
    CallInst *CI = CallInst::Create(FT, &*F->arg_begin(), Args, "", BB);
    ReturnInst *RI;
    if (FT->getReturnType()->isVoidTy())
      RI = ReturnInst::Create(*Ctx, BB);
    else
      RI = ReturnInst::Create(*Ctx, CI, BB);

    TaintFunction TF(*this, F, /*IsNativeABI=*/true);
    Function::arg_iterator ValAI = F->arg_begin(), ShadowAI = AI; ++ValAI;
    for (unsigned N = FT->getNumParams(); N != 0; ++ValAI, ++ShadowAI, --N)
      TF.ValShadowMap[&*ValAI] = &*ShadowAI;
    TaintVisitor(TF).visitCallInst(*CI);
    if (!FT->getReturnType()->isVoidTy())
      new StoreInst(TF.getShadow(RI->getReturnValue()),
                    &*std::prev(F->arg_end()), RI);
  }

  return cast<Constant>(C.getCallee());
}

// Initialize DataFlowSanitizer runtime functions and declare them in the module
void Taint::initializeRuntimeFunctions(Module &M) {
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addAttribute(M.getContext(), AttributeList::ReturnIndex,
                         Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
    TaintUnionFn =
        Mod->getOrInsertFunction("__taint_union", TaintUnionFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addAttribute(M.getContext(), AttributeList::ReturnIndex,
                         Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
    TaintCheckedUnionFn =
        Mod->getOrInsertFunction("taint_union", TaintUnionFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addAttribute(M.getContext(), AttributeList::ReturnIndex,
                         Attribute::ZExt);
    TaintUnionLoadFn =
        Mod->getOrInsertFunction("__taint_union_load", TaintUnionLoadFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintUnionStoreFn =
        Mod->getOrInsertFunction("__taint_union_store", TaintUnionStoreFnTy, AL);
  }
  {
    TaintUnimplementedFn =
        Mod->getOrInsertFunction("__dfsan_unimplemented", TaintUnimplementedFnTy);
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
}

// Initializes event callback functions and declare them in the module
void Taint::initializeCallbackFunctions(Module &M) {
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
    TaintTraceCmpFn =
        Mod->getOrInsertFunction("__taint_trace_cmp", TaintTraceCmpFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
    TaintTraceCondFn =
        Mod->getOrInsertFunction("__taint_trace_cond", TaintTraceCondFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintTraceIndirectCallFn =
        Mod->getOrInsertFunction("__taint_trace_indcall", TaintTraceIndirectCallFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 2, Attribute::ZExt);
    TaintTraceGEPFn =
        Mod->getOrInsertFunction("__taint_trace_gep", TaintTraceGEPFnTy, AL);
  }

  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    TaintPushStackFrameFn =
        Mod->getOrInsertFunction("__taint_push_stack_frame", TaintPushStackFrameFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    TaintPopStackFrameFn =
        Mod->getOrInsertFunction("__taint_pop_stack_frame", TaintPopStackFrameFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addAttribute(M.getContext(), AttributeList::ReturnIndex,
                         Attribute::ZExt);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintTraceAllocaFn =
        Mod->getOrInsertFunction("__taint_trace_alloca", TaintTraceAllocaFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
    TaintCheckBoundsFn =
        Mod->getOrInsertFunction("__taint_check_bounds", TaintCheckBoundsFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 2, Attribute::ZExt);
    TaintMemcmpFn =
        Mod->getOrInsertFunction("__taint_memcmp", TaintMemcmpFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    TaintStrcmpFn =
        Mod->getOrInsertFunction("__taint_strcmp", TaintStrcmpFnTy, AL);
  }
  {
    AttributeList AL;
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addParamAttribute(M.getContext(), 2, Attribute::ZExt);
    TaintStrncmpFn =
        Mod->getOrInsertFunction("__taint_strncmp", TaintStrncmpFnTy, AL);
  }

}

bool Taint::runOnModule(Module &M) {
  if (ABIList.isIn(M, "skip"))
    return false;

  const unsigned InitialGlobalSize = M.global_size();
  const unsigned InitialModuleSize = M.size();

  bool Changed = false;

  Type *ArgTLSTy = ArrayType::get(Int64Ty, kArgTLSSize / 8);
  ArgTLS = Mod->getOrInsertGlobal("__dfsan_arg_tls", ArgTLSTy);
  if (GlobalVariable *G = dyn_cast<GlobalVariable>(ArgTLS)) {
    Changed |= G->getThreadLocalMode() != GlobalVariable::InitialExecTLSModel;
    G->setThreadLocalMode(GlobalVariable::InitialExecTLSModel);
  }

  Type *RetvalTLSTy = ArrayType::get(Int64Ty, kRetvalTLSSize / 8);
  RetvalTLS = Mod->getOrInsertGlobal("__dfsan_retval_tls", RetvalTLSTy);
  if (GlobalVariable *G = dyn_cast<GlobalVariable>(RetvalTLS)) {
    Changed |= G->getThreadLocalMode() != GlobalVariable::InitialExecTLSModel;
    G->setThreadLocalMode(GlobalVariable::InitialExecTLSModel);
  }

  ExternalShadowMask =
      Mod->getOrInsertGlobal(kTaintExternShadowPtrMask, IntptrTy);

  TaintDebugFn =
    Mod->getOrInsertFunction("__taint_debug", TaintDebugFnTy);

  CallStack = Mod->getOrInsertGlobal("__taint_trace_callstack", Int32Ty);
  if (GlobalVariable *G = dyn_cast<GlobalVariable>(CallStack)) {
    Changed |= G->getThreadLocalMode() != GlobalVariable::InitialExecTLSModel;
    G->setThreadLocalMode(GlobalVariable::InitialExecTLSModel);
  }

  initializeCallbackFunctions(M);
  initializeRuntimeFunctions(M);

  std::vector<Function *> FnsToInstrument;
  SmallPtrSet<Function *, 2> FnsWithNativeABI;
  for (Function &i : M) {
    if (!i.isIntrinsic() &&
        &i != TaintUnionFn.getCallee()->stripPointerCasts() &&
        &i != TaintCheckedUnionFn.getCallee()->stripPointerCasts() &&
        &i != TaintUnionLoadFn.getCallee()->stripPointerCasts() &&
        &i != TaintUnionStoreFn.getCallee()->stripPointerCasts() &&
        &i != TaintUnimplementedFn.getCallee()->stripPointerCasts() &&
        &i != TaintSetLabelFn.getCallee()->stripPointerCasts() &&
        &i != TaintNonzeroLabelFn.getCallee()->stripPointerCasts() &&
        &i != TaintVarargWrapperFn.getCallee()->stripPointerCasts() &&
        &i != TaintTraceCmpFn.getCallee()->stripPointerCasts() &&
        &i != TaintTraceCondFn.getCallee()->stripPointerCasts() &&
        &i != TaintTraceIndirectCallFn.getCallee()->stripPointerCasts() &&
        &i != TaintTraceGEPFn.getCallee()->stripPointerCasts() &&
        &i != TaintPushStackFrameFn.getCallee()->stripPointerCasts() &&
        &i != TaintPopStackFrameFn.getCallee()->stripPointerCasts() &&
        &i != TaintTraceAllocaFn.getCallee()->stripPointerCasts() &&
        &i != TaintCheckBoundsFn.getCallee()->stripPointerCasts() &&
        &i != TaintMemcmpFn.getCallee()->stripPointerCasts() &&
        &i != TaintStrcmpFn.getCallee()->stripPointerCasts() &&
        &i != TaintStrncmpFn.getCallee()->stripPointerCasts() &&
        &i != TaintDebugFn.getCallee()->stripPointerCasts()) {
      FnsToInstrument.push_back(&i);
    }
  }

  // Give function aliases prefixes when necessary, and build wrappers where the
  // instrumentedness is inconsistent.
  for (Module::alias_iterator i = M.alias_begin(), e = M.alias_end(); i != e;) {
    GlobalAlias *GA = &*i;
    ++i;
    // Don't stop on weak.  We assume people aren't playing games with the
    // instrumentedness of overridden weak aliases.
    if (auto F = dyn_cast<Function>(GA->getBaseObject())) {
      bool GAInst = isInstrumented(GA), FInst = isInstrumented(F);
      if (GAInst && FInst) {
        addGlobalNamePrefix(GA);
      } else if (GAInst != FInst) {
        // Non-instrumented alias of an instrumented function, or vice versa.
        // Replace the alias with a native-ABI wrapper of the aliasee.  The pass
        // below will take care of instrumenting it.
        Function *NewF =
            buildWrapperFunction(F, "", GA->getLinkage(), F->getFunctionType());
        GA->replaceAllUsesWith(ConstantExpr::getBitCast(NewF, GA->getType()));
        NewF->takeName(GA);
        GA->eraseFromParent();
        FnsToInstrument.push_back(NewF);
      }
    }
  }

  ReadOnlyNoneAttrs.addAttribute(Attribute::ReadOnly)
      .addAttribute(Attribute::ReadNone);

  // First, change the ABI of every function in the module.  ABI-listed
  // functions keep their original ABI and get a wrapper function.
  for (std::vector<Function *>::iterator i = FnsToInstrument.begin(),
                                         e = FnsToInstrument.end();
       i != e; ++i) {
    Function &F = **i;
    FunctionType *FT = F.getFunctionType();

    bool IsZeroArgsVoidRet = (FT->getNumParams() == 0 && !FT->isVarArg() &&
                              FT->getReturnType()->isVoidTy());

    if (isInstrumented(&F)) {
      // Instrumented functions get a 'dfs$' prefix.  This allows us to more
      // easily identify cases of mismatching ABIs.
      if (getInstrumentedABI() == IA_Args && !IsZeroArgsVoidRet) {
        FunctionType *NewFT = getArgsFunctionType(FT);
        Function *NewF = Function::Create(NewFT, F.getLinkage(),
                                          F.getAddressSpace(), "", &M);
        NewF->copyAttributesFrom(&F);
        NewF->removeAttributes(
            AttributeList::ReturnIndex,
            AttributeFuncs::typeIncompatible(NewFT->getReturnType()));
        for (Function::arg_iterator FArg = F.arg_begin(),
                                    NewFArg = NewF->arg_begin(),
                                    FArgEnd = F.arg_end();
             FArg != FArgEnd; ++FArg, ++NewFArg) {
          FArg->replaceAllUsesWith(&*NewFArg);
        }
        NewF->getBasicBlockList().splice(NewF->begin(), F.getBasicBlockList());

        for (Function::user_iterator UI = F.user_begin(), UE = F.user_end();
             UI != UE;) {
          BlockAddress *BA = dyn_cast<BlockAddress>(*UI);
          ++UI;
          if (BA) {
            BA->replaceAllUsesWith(
                BlockAddress::get(NewF, BA->getBasicBlock()));
            delete BA;
          }
        }
        F.replaceAllUsesWith(
            ConstantExpr::getBitCast(NewF, PointerType::getUnqual(FT)));
        NewF->takeName(&F);
        F.eraseFromParent();
        *i = NewF;
        addGlobalNamePrefix(NewF);
      } else {
        addGlobalNamePrefix(&F);
      }
    } else if (!IsZeroArgsVoidRet || getWrapperKind(&F) == WK_Custom) {
      if (FT->isVarArg() && F.isDeclaration() && F.hasAddressTaken() && !isInstrumented(&F)) {
        // FIXME: vararg functions do used as indirect call targets
        *i = nullptr;
        continue;
      }

      // Build a wrapper function for F.  The wrapper simply calls F, and is
      // added to FnsToInstrument so that any instrumentation according to its
      // WrapperKind is done in the second pass below.
      FunctionType *NewFT = getInstrumentedABI() == IA_Args
                                ? getArgsFunctionType(FT)
                                : FT;

      // If the function being wrapped has local linkage, then preserve the
      // function's linkage in the wrapper function.
      GlobalValue::LinkageTypes wrapperLinkage =
          F.hasLocalLinkage()
              ? F.getLinkage()
              : GlobalValue::LinkOnceODRLinkage;

      Function *NewF = buildWrapperFunction(
          &F, std::string("dfsw$") + std::string(F.getName()),
          wrapperLinkage, NewFT);
      if (getInstrumentedABI() == IA_TLS)
        NewF->removeAttributes(AttributeList::FunctionIndex, ReadOnlyNoneAttrs);

      Value *WrappedFnCst =
          ConstantExpr::getBitCast(NewF, PointerType::getUnqual(FT));
      F.replaceAllUsesWith(WrappedFnCst);

      UnwrappedFnMap[WrappedFnCst] = &F;
      *i = NewF;

      if (!F.isDeclaration()) {
        // This function is probably defining an interposition of an
        // uninstrumented function and hence needs to keep the original ABI.
        // But any functions it may call need to use the instrumented ABI, so
        // we instrument it in a mode which preserves the original ABI.
        FnsWithNativeABI.insert(&F);

        // This code needs to rebuild the iterators, as they may be invalidated
        // by the push_back, taking care that the new range does not include
        // any functions added by this code.
        size_t N = i - FnsToInstrument.begin(),
               Count = e - FnsToInstrument.begin();
        FnsToInstrument.push_back(&F);
        i = FnsToInstrument.begin() + N;
        e = FnsToInstrument.begin() + Count;
      }
               // Hopefully, nobody will try to indirectly call a vararg
               // function... yet.
    } else if (FT->isVarArg()) {
      UnwrappedFnMap[&F] = &F;
      *i = nullptr;
    }
  }

  for (Function *i : FnsToInstrument) {
    if (!i || i->isDeclaration())
      continue;

    addContextRecording(*i);
    if (!i->getName().startswith("dfsw$"))
      addFrameTracing(*i);
    removeUnreachableBlocks(*i);

    TaintFunction TF(*this, i, FnsWithNativeABI.count(i));

    // TaintVisitor may create new basic blocks, which confuses df_iterator.
    // Build a copy of the list before iterating over it.
    SmallVector<BasicBlock *, 4> BBList(depth_first(&i->getEntryBlock()));

    for (BasicBlock *i : BBList) {
      Instruction *Inst = &i->front();
      while (true) {
        // TaintVisitor may split the current basic block, changing the current
        // instruction's next pointer and moving the next instruction to the
        // tail block from which we should continue.
        Instruction *Next = Inst->getNextNode();
        // TaintVisitor may delete Inst, so keep track of whether it was a
        // terminator.
        bool IsTerminator = Inst->isTerminator();
        if (!TF.SkipInsts.count(Inst))
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
    for (std::vector<std::pair<PHINode *, PHINode *>>::iterator
             i = TF.PHIFixups.begin(),
             e = TF.PHIFixups.end();
         i != e; ++i) {
      for (unsigned val = 0, n = i->first->getNumIncomingValues(); val != n;
           ++val) {
        i->second->setIncomingValue(
            val, TF.getShadow(i->first->getIncomingValue(val)));
      }
    }

  }

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
      ArgOffset += alignTo(Size, kShadowTLSAlignment);
      if (ArgOffset > kArgTLSSize)
        break; // ArgTLS overflows, uses a zero shadow.
      continue;
    }

    if (ArgOffset + Size > kArgTLSSize)
      break; // ArgTLS overflows, uses a zero shadow.

    Instruction *ArgTLSPos = &*F->getEntryBlock().begin();
    IRBuilder<> IRB(ArgTLSPos);
    Value *ArgShadowPtr = getArgTLS(FArg.getType(), ArgOffset, IRB);
    return IRB.CreateAlignedLoad(TT.getShadowTy(&FArg), ArgShadowPtr,
                                 kShadowTLSAlignment);
  }

  return TT.getZeroShadow(A);
}

Value *TaintFunction::getShadow(Value *V) {
  if (!isa<Argument>(V) && !isa<Instruction>(V))
    return TT.getZeroShadow(V);
  Value *&Shadow = ValShadowMap[V];
  if (!Shadow) {
    if (Argument *A = dyn_cast<Argument>(V)) {
      if (IsNativeABI)
        return TT.getZeroShadow(V);
      switch (IA) {
      case Taint::IA_TLS: {
        Shadow = getShadowForTLSArgument(A);
        break;
      }
      case Taint::IA_Args: {
        unsigned ArgIdx = A->getArgNo() + F->arg_size() / 2;
        Function::arg_iterator i = F->arg_begin();
        while (ArgIdx--)
          ++i;
        Shadow = &*i;
        // assert(Shadow->getType() == TT.ShadowTy);
        break;
      }
      }
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

Value *Taint::getShadowAddress(Value *Addr, IRBuilder<> &IRB) {
  assert(Addr != RetvalTLS && "Reinstrumenting?");
  Value *ShadowPtrMaskValue;
  if (TaintRuntimeShadowMask)
    ShadowPtrMaskValue = IRB.CreateLoad(IntptrTy, ExternalShadowMask);
  else
    ShadowPtrMaskValue = ShadowPtrMask;
  return IRB.CreateIntToPtr(
      IRB.CreateMul(
          IRB.CreateAnd(IRB.CreatePtrToInt(Addr, IntptrTy),
                        IRB.CreatePtrToInt(ShadowPtrMaskValue, IntptrTy)),
          ShadowPtrMul),
      PrimitiveShadowPtrTy);
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
  // FIXME: do not handle type larger than 64-bit
  if (size > 64) return TT.getZeroShadow(Pos);

  IRBuilder<> IRB(Pos);
  if (CmpInst *CI = dyn_cast<CmpInst>(Pos)) { // for both icmp and fcmp
    size = DL.getTypeSizeInBits(CI->getOperand(0)->getType());
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
    else if (Ty->isPointerTy())
      Op2 = IRB.CreatePtrToInt(Op2, TT.Int64Ty);
    Op2 = IRB.CreateZExtOrTrunc(Op2, TT.Int64Ty);
  }
  CallInst *Call = IRB.CreateCall(TT.TaintUnionFn, {V1, V2, Op, Size, Op1, Op2});
  Call->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);
  Call->addParamAttr(0, Attribute::ZExt);
  Call->addParamAttr(1, Attribute::ZExt);
  return Call;
}

Value *TaintFunction::combineCastInstShadows(CastInst *CI,
                                             uint8_t op) {
  Value *Shadow1 = getShadow(CI->getOperand(0));
  Value *Shadow2 = TT.getZeroShadow(CI);
  Value *Shadow = combineShadows(Shadow1, Shadow2, op, CI);
  return Shadow;
}

Value *TaintFunction::combineCmpInstShadows(CmpInst *CI,
                                            uint8_t op) {
  Value *Shadow1 = getShadow(CI->getOperand(0));
  Value *Shadow2 = getShadow(CI->getOperand(1));
  Value *Shadow = combineShadows(Shadow1, Shadow2, op, CI);
  return Shadow;
}

void TaintFunction::checkBounds(Value *Ptr, Value* Size, Instruction *Pos) {
  IRBuilder<> IRB(Pos);
  Value *PtrShadow = getShadow(Ptr);
  Value *SizeShadow = getShadow(Size);
  // ptr shadow only exists for array and heap object
  if (!TT.isZeroShadow(PtrShadow)) {
    Value *Addr = IRB.CreatePtrToInt(Ptr, TT.Int64Ty);
    Value *Size64 = IRB.CreateZExtOrTrunc(Size, TT.Int64Ty);
    IRB.CreateCall(TT.TaintCheckBoundsFn, {PtrShadow, Addr, SizeShadow, Size});
  }
}

// Generates IR to load shadow corresponding to bytes [Addr, Addr+Size), where
// Addr has alignment Align, and take the union of each of those shadows.
Value *TaintFunction::loadPrimitiveShadow(Value *Addr, uint64_t Size, uint64_t Align,
                                          IRBuilder<> &IRB) {
  if (Size == 0)
    return TT.ZeroPrimitiveShadow;

  Value *ShadowAddr = TT.getShadowAddress(Addr, IRB);
  CallInst *FallbackCall = IRB.CreateCall(
      TT.TaintUnionLoadFn, {ShadowAddr, ConstantInt::get(TT.IntptrTy, Size)});
  FallbackCall->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);
  return FallbackCall;
}

void TaintFunction::loadShadowRecursive(
    Value *Shadow, SmallVector<unsigned, 4> &Indices, Type *SubTy,
    Value *Addr, uint64_t Size, uint64_t Align, IRBuilder<> &IRB) {
  auto &DL = F->getParent()->getDataLayout();

  if (!isa<ArrayType>(SubTy) && !isa<StructType>(SubTy)) {
    uint64_t SubSize = DL.getTypeStoreSize(SubTy);
    assert(Size >= SubSize);
    Align = std::min(Align, (uint64_t)DL.getABITypeAlignment(SubTy));
    // load a primitive shadow from address
    Value *PrimitiveShadow = loadPrimitiveShadow(Addr, SubSize, Align, IRB);
    // then insert the primitive shadow into the sub-field
    IRB.CreateInsertValue(Shadow, PrimitiveShadow, Indices);
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
      loadShadowRecursive(Shadow, Indices, ElemTy,
                          SubAddr, Size - Offset, Align, IRB);
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
      loadShadowRecursive(Shadow, Indices, ElemTy,
                          SubAddr, Size - Offset, Align, IRB);
      Indices.pop_back();
    }
    return;
  }
  llvm_unreachable("Unexpected shadow type");
}

Value *TaintFunction::loadShadow(Type *T, Value *Addr, uint64_t Size, uint64_t Align,
                                 Instruction *Pos) {
  IRBuilder<> IRB(Pos);
  // if loading from a local variable, load label from its shadow
  if (AllocaInst *AI = dyn_cast<AllocaInst>(Addr)) {
    const auto i = AllocaShadowMap.find(AI);
    if (i != AllocaShadowMap.end()) {
      return IRB.CreateLoad(TT.PrimitiveShadowTy, i->second);
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

  // now check if we're loading an aggragate object
  if (!isa<ArrayType>(T) && !isa<StructType>(T))
    return loadPrimitiveShadow(Addr, Size, Align, IRB);

  // if loading an aggregate object, load its shadow recursively
  SmallVector<unsigned, 4> Indices;
  Type *ShadowTy = TT.getShadowTy(T);
  Value *Shadow = UndefValue::get(ShadowTy);
  loadShadowRecursive(Shadow, Indices, T, Addr, Size, Align, IRB);
  return Shadow;
}

void TaintVisitor::visitLoadInst(LoadInst &LI) {
  if (LI.getMetadata("nosanitize")) return;
  auto &DL = LI.getModule()->getDataLayout();
  uint64_t Size = DL.getTypeStoreSize(LI.getType());
  if (Size == 0) {
    TF.setShadow(&LI, TF.TT.getZeroShadow(&LI));
    return;
  }

  Align Alignment = ClPreserveAlignment ? LI.getAlign() : Align(1);
  Value *Shadow =
      TF.loadShadow(LI.getType(), LI.getPointerOperand(), Size, Alignment.value(), &LI);
#if 0
  //FIXME: tainted pointer
  if (ClCombinePointerLabelsOnLoad) {
    Value *PtrShadow = TF.getShadow(LI.getPointerOperand());
    Shadow = TF.combineShadows(Shadow, PtrShadow, &LI);
  }
#endif
  if (!TF.TT.isZeroShadow(Shadow))
    TF.NonZeroChecks.push_back(Shadow);
  if (ClTraceBound)
    TF.checkBounds(LI.getPointerOperand(), ConstantInt::get(TF.TT.Int64Ty, Size), &LI);

  TF.setShadow(&LI, Shadow);
}

void TaintFunction::storeShadowRecursive(
    Value *Shadow, SmallVector<unsigned, 4> &Indices, Type *SubShadowTy,
    Value *Addr, uint64_t Size, uint64_t Align, IRBuilder<> &IRB) {
  auto &DL = F->getParent()->getDataLayout();

  if (!isa<ArrayType>(SubShadowTy) && !isa<StructType>(SubShadowTy)) {
    uint64_t SubSize = DL.getTypeStoreSize(SubShadowTy);
    assert(Size >= SubSize);
    Align = std::min(Align, (uint64_t)DL.getABITypeAlignment(SubShadowTy));
    // load a primitive shadow from the sub-field
    Value *PrimitiveShadow = IRB.CreateExtractValue(Shadow, Indices);
    // then store the primitive shadow into the shadow address
    Value *ShadowAddr = TT.getShadowAddress(Addr, IRB);
    IRB.CreateCall(TT.TaintUnionStoreFn,
        {PrimitiveShadow, ShadowAddr, ConstantInt::get(TT.IntptrTy, SubSize)});
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

void TaintFunction::storeShadow(Value *Addr, uint64_t Size, Align Alignment,
                                Value *Shadow, Instruction *Pos) {
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
  // check if the shadow is zero, if so, clear the shadow memory regardless
  // of the shadow type
  if (TT.isZeroShadow(Shadow)) {
    const Align ShadowAlign(Alignment.value() * TT.ShadowWidthBytes);
    IntegerType *ShadowTy = IntegerType::get(*TT.Ctx, Size * TT.ShadowWidthBits);
    Value *ExtZeroShadow = ConstantInt::get(ShadowTy, 0);
    Value *ExtShadowAddr =
        IRB.CreateBitCast(ShadowAddr, PointerType::getUnqual(ShadowTy));
    IRB.CreateAlignedStore(ExtZeroShadow, ExtShadowAddr, ShadowAlign);
    return;
  }

  // now check if we're storing an aggragate shadow object
  Type *T = Shadow->getType();
  if (!isa<ArrayType>(T) && !isa<StructType>(T)) {
    IRB.CreateCall(TT.TaintUnionStoreFn,
                {Shadow, ShadowAddr, ConstantInt::get(TT.IntptrTy, Size)});
    return;
  }

  // if storing an aggregate shadow object, store its shadow recursively
  // we want to do this so union_store may have a chance to simplify some
  // constraints
  SmallVector<unsigned, 4> Indices;
  storeShadowRecursive(Shadow, Indices, T, Addr, Size, Alignment.value(), IRB);
}

void TaintVisitor::visitStoreInst(StoreInst &SI) {
  if (SI.getMetadata("nosanitize")) return;

  auto &DL = SI.getModule()->getDataLayout();
  uint64_t Size = DL.getTypeStoreSize(SI.getValueOperand()->getType());
  if (Size == 0)
    return;

  const Align Alignment = ClPreserveAlignment ? SI.getAlign() : Align(1);;

  Value* Shadow = TF.getShadow(SI.getValueOperand());
#if 0
  //FIXME: tainted pointer
  if (ClCombinePointerLabelsOnStore) {
    Value *PtrShadow = TF.getShadow(SI.getPointerOperand());
    Shadow = TF.combineShadows(Shadow, PtrShadow, &SI);
  }
#endif
  TF.storeShadow(SI.getPointerOperand(), Size, Alignment, Shadow, &SI);
  if (ClTraceBound)
    TF.checkBounds(SI.getPointerOperand(), ConstantInt::get(TF.TT.Int64Ty, Size), &SI);
}

//void TaintVisitor::visitUnaryOperator(UnaryOperator &UO) {
//}

void TaintVisitor::visitBinaryOperator(BinaryOperator &BO) {
  if (BO.getMetadata("nosanitize")) return;
  if (BO.getType()->isFloatingPointTy()) return;
  Value *CombinedShadow =
    TF.combineBinaryOperatorShadows(&BO, BO.getOpcode());
  TF.setShadow(&BO, CombinedShadow);
}

void TaintVisitor::visitCastInst(CastInst &CI) {
  if (CI.getMetadata("nosanitize")) return;
  Value *CombinedShadow =
    TF.combineCastInstShadows(&CI, CI.getOpcode());
  TF.setShadow(&CI, CombinedShadow);
}

void TaintFunction::visitCmpInst(CmpInst *I) {
  Module *M = F->getParent();
  auto &DL = M->getDataLayout();
  IRBuilder<> IRB(I);
  // get operand
  Value *Op1 = I->getOperand(0);
  unsigned size = DL.getTypeSizeInBits(Op1->getType());
  ConstantInt *Size = ConstantInt::get(TT.PrimitiveShadowTy, size);
  Value *Op2 = I->getOperand(1);
  Value *Op1Shadow = getShadow(Op1);
  Value *Op2Shadow = getShadow(Op2);
  Op1 = IRB.CreateZExtOrTrunc(Op1, TT.Int64Ty);
  Op2 = IRB.CreateZExtOrTrunc(Op2, TT.Int64Ty);
  // get predicate
  int predicate = I->getPredicate();
  ConstantInt *Predicate = ConstantInt::get(TT.PrimitiveShadowTy, predicate);

  IRB.CreateCall(TT.TaintTraceCmpFn, {Op1Shadow, Op2Shadow, Size, Predicate,
                 Op1, Op2});
}

void TaintVisitor::visitCmpInst(CmpInst &CI) {
  if (CI.getMetadata("nosanitize")) return;
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
  unsigned size = DL.getTypeSizeInBits(Cond->getType());
  ConstantInt *Size = ConstantInt::get(TT.PrimitiveShadowTy, size);
  ConstantInt *Predicate = ConstantInt::get(TT.PrimitiveShadowTy, 32); // EQ, ==
  ConstantInt *CID = ConstantInt::get(TT.Int32Ty, TT.getInstructionId(I));

  for (auto C : I->cases()) {
    Value *CV = C.getCaseValue();

    IRBuilder<> IRB(I);
    Cond = IRB.CreateZExtOrTrunc(Cond, TT.Int64Ty);
    CV = IRB.CreateZExtOrTrunc(CV, TT.Int64Ty);
    IRB.CreateCall(TT.TaintTraceCmpFn, {CondShadow, TT.ZeroPrimitiveShadow,
                    Size, Predicate, Cond, CV, CID});
  }
}

void TaintVisitor::visitSwitchInst(SwitchInst &SWI) {
  if (SWI.getMetadata("nosanitize")) return;
  TF.visitSwitchInst(&SWI);
}

void TaintFunction::visitGEPInst(GetElementPtrInst *I) {
  Module *M = F->getParent();
  auto &DL = M->getDataLayout();
  int64_t CurrentOffset = 0;

  IRBuilder<> IRB(I);
  Type *ETy = I->getPointerOperandType();
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
      if (PointerType *PTy = dyn_cast<PointerType>(ETy)) {
        ETy = PTy->getElementType();
      } else if (ArrayType *ATy = dyn_cast<ArrayType>(ETy)) {
        ETy = ATy->getElementType();
        NumElements = ATy->getNumElements();
      } else {
        // FIXME: vector type?
        break;
      }

      if (isa<ConstantInt>(Index)) {
        int64_t arrayIdx = cast<ConstantInt>(Index)->getSExtValue();
        CurrentOffset += arrayIdx * DL.getTypeAllocSize(ETy);
      } else if (Index->getType()->isIntegerTy()) { // FIXEME: handle vector type
        // non-constant index, check if it's tainted
        Value *Shadow = getShadow(Index);
        if (!TT.isZeroShadow(Shadow)) {
          Index = IRB.CreateZExtOrTrunc(Index, TT.Int64Ty);
          ConstantInt *Offset = ConstantInt::get(TT.Int64Ty, CurrentOffset);
          ConstantInt *ES = ConstantInt::get(TT.Int64Ty, DL.getTypeAllocSize(ETy));
          ConstantInt *NE = ConstantInt::get(TT.Int64Ty, NumElements);
          Value *Ptr = IRB.CreatePtrToInt(I->getPointerOperand(), TT.Int64Ty);
          Value *Bounds = getShadow(I->getPointerOperand());
          IRB.CreateCall(TT.TaintTraceGEPFn, {Bounds, Ptr, Shadow, Index, NE, ES, Offset});
        } else {
          break;
        }
      }
    }
  }
  if (ClTraceBound) {
    // propagate bounds info
    Value *Bounds = getShadow(I->getPointerOperand());
    setShadow(I, Bounds);
  }
}

void TaintVisitor::visitGetElementPtrInst(GetElementPtrInst &GEPI) {
  if (!ClTraceGEPOffset && !ClTraceBound) return;
  if (GEPI.getMetadata("nosanitize")) return;
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
  if (I.getMetadata("nosanitize")) return;

  IRBuilder<> IRB(&I);
  Value *Agg = I.getAggregateOperand();
  Value *AggShadow = TF.getShadow(Agg);
  Value *ResShadow = IRB.CreateExtractValue(AggShadow, I.getIndices());
  TF.setShadow(&I, ResShadow);
}

void TaintVisitor::visitInsertValueInst(InsertValueInst &I) {
  if (I.getMetadata("nosanitize")) return;

  IRBuilder<> IRB(&I);
  Value *AggShadow = TF.getShadow(I.getAggregateOperand());
  Value *InsShadow = TF.getShadow(I.getInsertedValueOperand());
  Value *Res = IRB.CreateInsertValue(AggShadow, InsShadow, I.getIndices());
  TF.setShadow(&I, Res);
}

Value *TaintFunction::visitAllocaInst(AllocaInst *I) {
  // insert after the instruction to get the address
  BasicBlock::iterator ip(I);
  IRBuilder<> IRB(I->getParent(), ++ip);
  // get size
  Value *Size = I->getArraySize();
  Value *SizeShadow = getShadow(Size);
  Size = IRB.CreateZExtOrTrunc(Size, TT.Int64Ty);
  // get element size
  Module *M = F->getParent();
  auto &DL = M->getDataLayout();
  uint64_t es = DL.getTypeAllocSize(I->getAllocatedType());
  ConstantInt *ElemSize = ConstantInt::get(TT.Int64Ty, es);
  // get address
  Value *Address = IRB.CreatePtrToInt(I, TT.Int64Ty);

  return IRB.CreateCall(TT.TaintTraceAllocaFn, {SizeShadow, Size, ElemSize, Address});
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
    AllocaInst *AI = IRB.CreateAlloca(TF.TT.PrimitiveShadowTy);
    TF.AllocaShadowMap[&I] = AI;
    if (ClTraceBound) {
      // set shadow to uninit
      IRB.CreateStore(TF.TT.UninitializedPrimitiveShadow, AI);
    }
  }
  if (!ClTraceBound) {
    TF.setShadow(&I, TF.TT.ZeroPrimitiveShadow);
  } else {
    Type *T = I.getAllocatedType();
    bool isArray = I.isArrayAllocation() | T->isArrayTy();
    if (isArray) {
      // array could be VLA, rely on runtime
      Value *Bounds = TF.visitAllocaInst(&I);
      TF.setShadow(&I, Bounds);
    } else {
      TF.setShadow(&I, TF.TT.ZeroPrimitiveShadow); // no bounds
      if (!AllLoadsStores) {
        // handle not all loads and stores cases here
        IRBuilder<> IRB(I.getNextNode());
        auto DL = I.getModule()->getDataLayout();
        auto size = I.getAllocationSizeInBits(DL);
        assert(size != None);
        Value *Size = ConstantInt::get(TF.TT.IntptrTy, (size->getValue() + 7) >> 3);
        IRB.CreateCall(TF.TT.TaintSetLabelFn,
                       {TF.TT.UninitializedPrimitiveShadow,
                        IRB.CreateBitCast(&I, Type::getInt8PtrTy(*TF.TT.Ctx)),
                        Size});
      }
    }
  }
}

void TaintVisitor::visitSelectInst(SelectInst &I) {
  Value *Condition = I.getCondition();
  Value *TrueShadow = TF.getShadow(I.getTrueValue());
  Value *FalseShadow = TF.getShadow(I.getFalseValue());

  if (isa<VectorType>(Condition->getType())) {
    //FIXME:
    TF.setShadow(&I, TF.TT.ZeroPrimitiveShadow);
  } else {
    Value *ShadowSel;
    if (TrueShadow == FalseShadow) {
      ShadowSel = TrueShadow;
    } else {
      ShadowSel =
          SelectInst::Create(Condition, TrueShadow, FalseShadow, "", &I);
    }
    TF.visitCondition(Condition, &I);
    TF.setShadow(&I, ShadowSel);
  }
}

void TaintVisitor::visitMemSetInst(MemSetInst &I) {
  // check bounds before memset
  if (ClTraceBound) {
    TF.checkBounds(I.getDest(), I.getLength(), &I);
  }
  IRBuilder<> IRB(&I);
  Value *ValShadow = TF.getShadow(I.getValue());
  IRB.CreateCall(TF.TT.TaintSetLabelFn,
                 {ValShadow, IRB.CreateBitCast(I.getDest(), Type::getInt8PtrTy(
                                                                *TF.TT.Ctx)),
                  IRB.CreateZExtOrTrunc(I.getLength(), TF.TT.IntptrTy)});
}

void TaintVisitor::visitMemTransferInst(MemTransferInst &I) {
  // check bounds before memcpy
  if (ClTraceBound) {
    TF.checkBounds(I.getDest(), I.getLength(), &I);
    TF.checkBounds(I.getSource(), I.getLength(), &I);
  }
  IRBuilder<> IRB(&I);
  Value *DestShadow = TF.TT.getShadowAddress(I.getDest(), IRB);
  Value *SrcShadow = TF.TT.getShadowAddress(I.getSource(), IRB);
  Value *LenShadow = IRB.CreateMul(
      I.getLength(),
      ConstantInt::get(I.getLength()->getType(), TF.TT.ShadowWidthBytes));
#if LLVM_VERSION_CODE < LLVM_VERSION(7, 0)
  Value *AlignShadow;
  if (ClPreserveAlignment) {
    AlignShadow = IRB.CreateMul(I.getAlignmentCst(),
                                ConstantInt::get(I.getAlignmentCst()->getType(),
                                                 TF.TT.ShadowWidth / 8));
  } else {
    AlignShadow = ConstantInt::get(I.getAlignmentCst()->getType(),
                                   TF.TT.ShadowWidth / 8);
  }
  Type *Int8Ptr = Type::getInt8PtrTy(*TF.TT.Ctx);
  DestShadow = IRB.CreateBitCast(DestShadow, Int8Ptr);
  SrcShadow = IRB.CreateBitCast(SrcShadow, Int8Ptr);
  IRB.CreateCall(I.getCalledValue(), {DestShadow, SrcShadow, LenShadow,
                                      AlignShadow, I.getVolatileCst()});
#else
  Type *Int8Ptr = Type::getInt8PtrTy(*TF.TT.Ctx);
  DestShadow = IRB.CreateBitCast(DestShadow, Int8Ptr);
  SrcShadow = IRB.CreateBitCast(SrcShadow, Int8Ptr);
  auto *MTI = cast<MemTransferInst>(
      IRB.CreateCall(I.getFunctionType(), I.getCalledOperand(),
                     {DestShadow, SrcShadow, LenShadow, I.getVolatileCst()}));
  if (ClPreserveAlignment) {
    MTI->setDestAlignment(I.getDestAlign() * TF.TT.ShadowWidthBytes);
    MTI->setSourceAlignment(I.getSourceAlign() * TF.TT.ShadowWidthBytes);
  } else {
    MTI->setDestAlignment(Align(TF.TT.ShadowWidthBytes));
    MTI->setSourceAlignment(Align(TF.TT.ShadowWidthBytes));
  }
#endif
}

void TaintVisitor::visitReturnInst(ReturnInst &RI) {
  if (!TF.IsNativeABI && RI.getReturnValue()) {
    switch (TF.IA) {
    case Taint::IA_TLS: {
      Value *S = TF.getShadow(RI.getReturnValue());
      IRBuilder<> IRB(&RI);
      Type *RT = TF.F->getFunctionType()->getReturnType();
      unsigned Size =
          getDataLayout().getTypeAllocSize(TF.TT.getShadowTy(RT));
      if (Size <= kRetvalTLSSize) {
        // If the size overflows, stores nothing. At callsite, oversized return
        // shadows are set to zero.
        IRB.CreateAlignedStore(S, TF.getRetvalTLS(RT, IRB),
                               kShadowTLSAlignment);
      }
      break;
    }
    case Taint::IA_Args: {
      IRBuilder<> IRB(&RI);
      Type *RT = TF.F->getFunctionType()->getReturnType();
      Value *InsVal =
          IRB.CreateInsertValue(UndefValue::get(RT), RI.getReturnValue(), 0);
      Value *InsShadow =
          IRB.CreateInsertValue(InsVal, TF.getShadow(RI.getReturnValue()), 1);
      RI.setOperand(0, InsShadow);
      break;
    }
    }
  }
}

void TaintVisitor::visitCallBase(CallBase &CB) {
  Function *F = CB.getCalledFunction();
  if (CB.isInlineAsm()) {
    // FIXME: inline asm
    return;
  }
  if (F && F->isIntrinsic()) {
    // filter some obvious ones
    StringRef FN = F->getName();
    if (FN.startswith("llvm.va_") || // varabile length
        FN.startswith("llvm.gc")  || // garbaage collection
        FN.startswith("llvm.experimental") ||
        FN.startswith("llvm.lifetime")
       ) {
      return;
    }
    // intrinsic, check argument
    bool NeedsInstrumentation = false;
    for (unsigned i = 0; i < CB.getNumArgOperands(); ++i) {
      Value *Shadow = TF.getShadow(CB.getArgOperand(i));
      if (!TF.TT.isZeroShadow(Shadow)) {
        NeedsInstrumentation = true;
        break;
      }
    }
    return;
  }

  // Calls to this function are synthesized in wrappers, and we shouldn't
  // instrument them.
  if (F == TF.TT.TaintVarargWrapperFn.getCallee()->stripPointerCasts())
    return;

  IRBuilder<> IRB(&CB);

  // trace indirect call
  if (CB.getCalledFunction() == nullptr) {
    Value *Shadow = TF.getShadow(CB.getCalledOperand());
    if (!TF.TT.isZeroShadow(Shadow))
      IRB.CreateCall(TF.TT.TaintTraceIndirectCallFn, {Shadow});
  }

  // reset IRB
  IRB.SetInsertPoint(&CB);

  DenseMap<Value *, Function *>::iterator i =
      TF.TT.UnwrappedFnMap.find(CB.getCalledOperand());
  if (i != TF.TT.UnwrappedFnMap.end()) {
    Function *F = i->second;
    Value *Shadow = nullptr;
    switch (TF.TT.getWrapperKind(F)) {
    case Taint::WK_Warning:
      CB.setCalledFunction(F);
      IRB.CreateCall(TF.TT.TaintUnimplementedFn,
                     IRB.CreateGlobalStringPtr(F->getName()));
      TF.setShadow(&CB, TF.TT.getZeroShadow(&CB));
      return;
    case Taint::WK_Discard:
      CB.setCalledFunction(F);
      TF.setShadow(&CB, TF.TT.getZeroShadow(&CB));
      return;
    case Taint::WK_Functional:
      CB.setCalledFunction(F);
      //FIXME:
      // visitOperandShadowInst(CS);
      return;
    case Taint::WK_Memcmp:
      CB.setCalledFunction(F);
      assert(CB.arg_size() == 3);
      Shadow = IRB.CreateCall(TF.TT.TaintMemcmpFn,
                             {CB.getArgOperand(0),
                              CB.getArgOperand(1),
                              CB.getArgOperand(2)});
      TF.setShadow(&CB, Shadow);
      return;
    case Taint::WK_Strcmp:
      CB.setCalledFunction(F);
      assert(CB.arg_size() == 2);
      Shadow = IRB.CreateCall(TF.TT.TaintStrcmpFn,
                             {CB.getArgOperand(0), CB.getArgOperand(1)});
      TF.setShadow(&CB, Shadow);
      return;
    case Taint::WK_Strncmp:
      CB.setCalledFunction(F);
      assert(CB.arg_size() == 3);
      Shadow = IRB.CreateCall(TF.TT.TaintStrncmpFn,
                             {CB.getArgOperand(0),
                              CB.getArgOperand(1),
                              CB.getArgOperand(2)});
      TF.setShadow(&CB, Shadow);
      return;
    case Taint::WK_Custom:
      // Don't try to handle invokes of custom functions, it's too complicated.
      // Instead, invoke the dfsw$ wrapper, which will in turn call the __dfsw_
      // wrapper.
      if (CallInst *CI = dyn_cast<CallInst>(&CB)) {
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
            CustomFn->removeAttributes(AttributeList::FunctionIndex,
                                       TF.TT.ReadOnlyNoneAttrs);
          }
        }

        std::vector<Value *> Args;

        auto i = CB.arg_begin();
        for (unsigned n = FT->getNumParams(); n != 0; ++i, --n) {
          Type *T = (*i)->getType();
          FunctionType *ParamFT;
          if (isa<PointerType>(T) &&
              (ParamFT = dyn_cast<FunctionType>(
                   cast<PointerType>(T)->getElementType()))) {
            std::string TName = "dfst";
            TName += utostr(FT->getNumParams() - n);
            TName += "$";
            TName += F->getName();
            Constant *T = TF.TT.getOrBuildTrampolineFunction(ParamFT, TName);
            Args.push_back(T);
            Args.push_back(
                IRB.CreateBitCast(*i, Type::getInt8PtrTy(*TF.TT.Ctx)));
          } else {
            Args.push_back(*i);
          }
        }

        i = CB.arg_begin();
        const unsigned ShadowArgStart = Args.size();
        for (unsigned n = FT->getNumParams(); n != 0; ++i, --n)
          Args.push_back(TF.getShadow(*i)); // we don't collapse shadow

        if (FT->isVarArg()) {
          auto *LabelVATy = ArrayType::get(TF.TT.PrimitiveShadowTy,
                                           CB.arg_size() - FT->getNumParams());
          auto *LabelVAAlloca = new AllocaInst(
              LabelVATy, getDataLayout().getAllocaAddrSpace(),
              "labelva", &TF.F->getEntryBlock().front());

          for (unsigned n = 0; i != CB.arg_end(); ++i, ++n) {
            auto LabelVAPtr = IRB.CreateStructGEP(LabelVATy, LabelVAAlloca, n);
            IRB.CreateStore(TF.getShadow(*i), LabelVAPtr);
          }

          Args.push_back(IRB.CreateStructGEP(LabelVATy, LabelVAAlloca, 0));
        }

        Type *RetTy = FT->getReturnType();
        if (!RetTy->isVoidTy()) {
          if (!TF.LabelReturnAlloca) {
            TF.LabelReturnAlloca =
              new AllocaInst(TF.TT.getShadowTy(RetTy),
                             getDataLayout().getAllocaAddrSpace(),
                             "labelreturn", &TF.F->getEntryBlock().front());
          }
          Args.push_back(TF.LabelReturnAlloca);
        }

        for (i = CB.arg_begin() + FT->getNumParams(); i != CB.arg_end(); ++i)
          Args.push_back(*i);

        CallInst *CustomCI = IRB.CreateCall(CustomF, Args);
        CustomCI->setCallingConv(CI->getCallingConv());
        CustomCI->setAttributes(TransformFunctionAttributes(
            CustomFn, CI->getContext(), CI->getAttributes()));

        // Update the parameter attributes of the custom call instruction to
        // zero extend the shadow parameters. This is required for targets
        // which consider ShadowTy an illegal type.
        for (unsigned n = 0; n < FT->getNumParams(); n++) {
          const unsigned ArgNo = ShadowArgStart + n;
          if (CustomCI->getArgOperand(ArgNo)->getType() ==
              TF.TT.PrimitiveShadowTy) {
            CustomCI->addParamAttr(ArgNo, Attribute::ZExt);
            CustomCI->removeParamAttr(ArgNo, Attribute::NonNull);
          }
        }

        if (!RetTy->isVoidTy()) {
          LoadInst *LabelLoad =
              IRB.CreateLoad(TF.TT.getShadowTy(RetTy), TF.LabelReturnAlloca);
          TF.setShadow(CustomCI, LabelLoad);
        }

        CI->replaceAllUsesWith(CustomCI);
        CI->eraseFromParent();
        return;
      }
      break;
    }
  }

  FunctionType *FT = CB.getFunctionType();
  if (TF.TT.getInstrumentedABI() == Taint::IA_TLS) {
    unsigned ArgOffset = 0;
    const DataLayout &DL = getDataLayout();
    for (unsigned I = 0, N = FT->getNumParams(); I != N; ++I) {
      unsigned Size =
          DL.getTypeAllocSize(TF.TT.getShadowTy(FT->getParamType(I)));
      // Stop storing if arguments' size overflows. Inside a function, arguments
      // after overflow have zero shadow values.
      if (ArgOffset + Size > kArgTLSSize)
        break;
      IRB.CreateAlignedStore(
          TF.getShadow(CB.getArgOperand(I)),
          TF.getArgTLS(FT->getParamType(I), ArgOffset, IRB),
          kShadowTLSAlignment);
      ArgOffset += alignTo(Size, kShadowTLSAlignment);
    }
  }

  Instruction *Next = nullptr;
  if (!CB.getType()->isVoidTy()) {
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
      Next = CB.getNextNode();
    }

    if (TF.TT.getInstrumentedABI() == Taint::IA_TLS) {
      IRBuilder<> NextIRB(Next);
      const DataLayout &DL = getDataLayout();
      unsigned Size = DL.getTypeAllocSize(TF.TT.getShadowTy(&CB));
      if (Size > kRetvalTLSSize) {
        // Set overflowed return shadow to be zero.
        TF.setShadow(&CB, TF.TT.getZeroShadow(&CB));
      } else {
        LoadInst *LI = NextIRB.CreateAlignedLoad(
            TF.TT.getShadowTy(&CB), TF.getRetvalTLS(CB.getType(), NextIRB),
            kShadowTLSAlignment, "_dfsret");
        TF.SkipInsts.insert(LI);
        TF.setShadow(&CB, LI);
        TF.NonZeroChecks.push_back(LI);
      }
    }
  }

  // Do all instrumentation for IA_Args down here to defer tampering with the
  // CFG in a way that SplitEdge may be able to detect.
  if (TF.TT.getInstrumentedABI() == Taint::IA_Args) {
    FunctionType *NewFT = TF.TT.getArgsFunctionType(FT);
    Value *Func =
        IRB.CreateBitCast(CB.getCalledOperand(), PointerType::getUnqual(NewFT));
    std::vector<Value *> Args;

    auto i = CB.arg_begin(), E = CB.arg_end();
    for (unsigned n = FT->getNumParams(); n != 0; ++i, --n)
      Args.push_back(*i);

    i = CB.arg_begin();
    for (unsigned n = FT->getNumParams(); n != 0; ++i, --n)
      Args.push_back(TF.getShadow(*i));

    if (FT->isVarArg()) {
      unsigned VarArgSize = CB.arg_size() - FT->getNumParams();
      ArrayType *VarArgArrayTy = ArrayType::get(TF.TT.PrimitiveShadowTy, VarArgSize);
      AllocaInst *VarArgShadow =
        new AllocaInst(VarArgArrayTy, getDataLayout().getAllocaAddrSpace(),
                       "", &TF.F->getEntryBlock().front());
      Args.push_back(IRB.CreateConstGEP2_32(VarArgArrayTy, VarArgShadow, 0, 0));
      for (unsigned n = 0; i != E; ++i, ++n) {
        IRB.CreateStore(
            TF.getShadow(*i),
            IRB.CreateConstGEP2_32(VarArgArrayTy, VarArgShadow, 0, n));
        Args.push_back(*i);
      }
    }

    CallBase *NewCB;
    if (InvokeInst *II = dyn_cast<InvokeInst>(&CB)) {
      NewCB = IRB.CreateInvoke(NewFT, Func, II->getNormalDest(),
                               II->getUnwindDest(), Args);
    } else {
      NewCB = IRB.CreateCall(NewFT, Func, Args);
    }
    NewCB->setCallingConv(CB.getCallingConv());
    NewCB->setAttributes(CB.getAttributes().removeAttributes(
        *TF.TT.Ctx, AttributeList::ReturnIndex,
        AttributeFuncs::typeIncompatible(NewCB->getType())));

    if (Next) {
      ExtractValueInst *ExVal = ExtractValueInst::Create(NewCB, 0, "", Next);
      TF.SkipInsts.insert(ExVal);
      ExtractValueInst *ExShadow = ExtractValueInst::Create(NewCB, 1, "", Next);
      TF.SkipInsts.insert(ExShadow);
      TF.setShadow(ExVal, ExShadow);
      TF.NonZeroChecks.push_back(ExShadow);

      CB.replaceAllUsesWith(ExVal);
    }

    CB.eraseFromParent();
  }
}

void TaintVisitor::visitPHINode(PHINode &PN) {
  Type *ShadowTy = TF.TT.getShadowTy(&PN);
  PHINode *ShadowPN =
      PHINode::Create(ShadowTy, PN.getNumIncomingValues(), "", &PN);

  // Give the shadow phi node valid predecessors to fool SplitEdge into working.
  Value *UndefShadow = UndefValue::get(ShadowTy);
  for (PHINode::block_iterator i = PN.block_begin(), e = PN.block_end(); i != e;
       ++i) {
    ShadowPN->addIncoming(UndefShadow, *i);
  }

  TF.PHIFixups.push_back(std::make_pair(&PN, ShadowPN));
  TF.setShadow(&PN, ShadowPN);
}

void TaintFunction::visitCondition(Value *Condition, Instruction *I) {
  IRBuilder<> IRB(I);
  // get operand
  Value *Shadow = getShadow(Condition);
  if (TT.isZeroShadow(Shadow))
    return;
  ConstantInt *CID = ConstantInt::get(TT.Int32Ty, TT.getInstructionId(I));
  IRB.CreateCall(TT.TaintTraceCondFn, {Shadow, Condition, CID});
}

void TaintVisitor::visitBranchInst(BranchInst &BR) {
  if (BR.getMetadata("nosanitize")) return;
  if (BR.isUnconditional()) return;
  TF.visitCondition(BR.getCondition(), &BR);
}

static RegisterPass<Taint> X("taint_pass", "Taint Pass");

static void registerTaintPass(const PassManagerBuilder &,
                              legacy::PassManagerBase &PM) {

  PM.add(new Taint());
}

static RegisterStandardPasses
    RegisterTaintPass(PassManagerBuilder::EP_OptimizerLast,
                      registerTaintPass);

static RegisterStandardPasses
    RegisterTaintPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                       registerTaintPass);
