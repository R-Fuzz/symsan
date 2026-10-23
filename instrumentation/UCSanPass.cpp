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

#include "Bitfield.h"
#include "UCSanSummary.h"

#include <optional>
#include "llvm/IR/AttributeMask.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
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
#include "llvm/Transforms/Utils/CallPromotionUtils.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Object/ModuleSymbolTable.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Demangle/Demangle.h"

#include <map>
#include <set>
#include <vector>
#include <string>
#include <fstream>

using namespace llvm;

// Demangle a C++ mangled name. If demangling fails (e.g. plain C name),
// return the original name unchanged.
//
// Use LLVM's own demangler rather than <cxxabi.h>/abi::__cxa_demangle: when
// building against the LLVM tree, -I<llvm>/include makes <cxxabi.h> resolve to
// libc++abi's copy, which clashes with the host libstdc++ headers.
static std::string demangleName(StringRef MangledName) {
  // llvm::demangle returns a copy of the input if no demangling occurred.
  return llvm::demangle(MangledName.str());
}

namespace {

// Constants for shadow memory alignment
// Must match sizeof(ucsan_label) = sizeof(i16) = 2 bytes
static const Align ShadowTLSAlignment = Align(2);
static const unsigned ArgTLSSize = 800;
static const unsigned kRetvalTLSSize = 800;

static const char *BBIDName = "dfsan.bb";
static const unsigned BBID_STEP = 100000; // Max 100k BBs per function

// Command line options
static cl::opt<bool> ClTraceBound("ucsan-trace-bound",
    cl::desc("Enable bounds checking"),
    cl::Hidden, cl::init(true));

static cl::opt<bool> ClTraceBB("ucsan-trace-bb",
    cl::desc("Enable basic block tracing"),
    cl::Hidden, cl::init(false));

static cl::opt<std::string> ClDumpCfg("ucsan-dump-cfg",
    cl::desc("Dump control flow info to file"),
    cl::Hidden);

static cl::opt<bool> ClWithTaintPass(
    "ucsan-with-taint",
    cl::desc("TaintPass will run after UCSanPass, defer taint custom functions"),
    cl::Hidden, cl::init(false));

static cl::opt<std::string> ClTypeTable("ucsan-type-table",
    cl::desc("Emit type table JSON to file (loaded/appended across modules)"),
    cl::Hidden);

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

  /// Returns whether the given function name is listed in the given category.
  bool isIn(StringRef Name, StringRef Category) const {
    if (!SCL) return false;
    return SCL->inSection("taint", "fun", Name, Category);
  }

  /// Returns the 0-indexed argument that holds the byte count for the named
  /// function, or -1 if none is listed.  Probes categories size0..size7.
  int getSizeArgIdx(StringRef Name) const {
    if (!SCL) return -1;
    for (int i = 0; i < 8; ++i) {
      std::string Cat = "size" + std::to_string(i);
      if (SCL->inSection("taint", "fun", Name, Cat))
        return i;
    }
    return -1;
  }

  // Returns the argument index whose pointer the function's return value
  // aliases (e.g. strchr/memchr return haystack+index → retptr0), or -1.
  // Used to translate the materialized return pointer back into UC space.
  int getRetPtrArgIdx(StringRef Name) const {
    if (!SCL) return -1;
    for (int i = 0; i < 8; ++i) {
      std::string Cat = "retptr" + std::to_string(i);
      if (SCL->inSection("taint", "fun", Name, Cat))
        return i;
    }
    return -1;
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
                            ArrayRef(ArgumentAttributes));
}

// YAML structures for metadata parsing
struct ArgMapEntry {
  int idx;
  int ucsan_idx;
};

struct UCSanScopeCustom {
  std::string ref_name;
  std::vector<ArgMapEntry> arg_maps;
  // If true, the wrapper returns the logical NOT of the ref's return value
  // (cast to the wrapper's return type).  Useful for adapters whose truth
  // sense is inverted from the ref's, e.g. bytesEqual→strncmp.
  bool invert_ret = false;
};

struct UCSanScope {
  std::string entry;
  std::vector<std::string> scope;
  std::vector<std::string> shims_yaml;          // parsed from YAML
  std::map<std::string, bool> shims;            // expanded: orig->true, __shim_orig->false
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
    io.mapOptional("invert_ret", c.invert_ret, false);
  }
};

template<>
struct MappingTraits<UCSanScope> {
  static void mapping(yaml::IO &io, UCSanScope &sc) {
    io.mapRequired("entry", sc.entry);
    io.mapOptional("scope", sc.scope);
    io.mapOptional("shims", sc.shims_yaml);
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
    WK_TaintCustom, // custom in dfsan abilist, defer to TaintPass if available
    WK_AutoCustom,
    WK_ShimOrig,    // original function to be replaced by __shim_ version
    WK_ShimTarget,  // LLM-generated __shim_ function, instrumented like in-scope
    WK_Uninstrumented,
    WK_Discard,
    WK_Ignore,
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
  FunctionType *UCUncheckPointerFnTy;
  FunctionType *UCCheckPointerArgFnTy;
  FunctionType *UCCheckUBIFnTy;
  FunctionType *UCCombineLabelFnTy;
  FunctionType *UCSetLabelForArgsFnTy;
  FunctionType *UCLoadPointerShadowFnTy;
  FunctionType *UCStorePointerShadowFnTy;
  FunctionType *UCStoreRMWShadowFnTy;
  FunctionType *UCResignShadowFnTy;
  FunctionType *UCWrapRetvalFnTy;
  FunctionType *UCSetLabelFnTy;
  FunctionType *UCTraceBBFnTy;
  FunctionType *UCTraceAllocaFnTy;
  FunctionType *UCTraceGlobalFnTy;
  FunctionType *UCCheckGlobalBoundsFnTy;
  FunctionType *UCTraceWarnFnTy;
  FunctionType *UCPushStackFrameFnTy;
  FunctionType *UCPopStackFrameFnTy;
  FunctionType *UCCheckCopyBoundsFnTy;

  // Runtime functions
  FunctionCallee UCCheckPointerFn;
  FunctionCallee UCUncheckPointerFn;
  FunctionCallee UCCheckPointerArgFn;
  FunctionCallee UCCheckUBIFn;
  FunctionCallee UCCombineLabelFn;
  FunctionCallee UCVmcsFieldFn;  // ptr ucsan_vmcs_field(i64): see AsmLifter
  FunctionCallee UCMaterializeRangeFn;  // void ucsan_materialize_range(ptr, i64)
  FunctionCallee UCFillPatternFn;  // void ucsan_fill_pattern(ptr, i64, i64, i64)
  // pointer differences of UC pointers: see visitBinaryOperator
  FunctionCallee UCPtrDiffRewriteFn;  // i1 ucsan_ptr_diff_rewrite(ptr, i16, ptr, i16)
  FunctionCallee UCPtrIndexFn;        // i64 __dfsw_ucsan_ptr_index(i1, i64, ptr, ptr, i16, i16)
  FunctionCallee UCSetLabelForArgsFn;
  FunctionCallee UCLoadPointerShadowFn;
  FunctionCallee UCStorePointerShadowFn;
  FunctionCallee UCStoreRMWShadowFn;
  FunctionCallee UCResignShadowFn;
  FunctionCallee UCWrapRetvalFn;
  FunctionCallee UCSetLabelFn;
  FunctionCallee UCTraceBBFn;
  FunctionCallee UCTraceAllocaFn;
  FunctionCallee UCTraceGlobalFn;
  FunctionCallee UCTraceUnsizedGlobalFn;
  FunctionCallee UCIntToPointerFn;
  FunctionCallee UCCheckGlobalBoundsFn;
  FunctionCallee UCTraceWarnFn;
  FunctionCallee UCPushStackFrameFn;
  FunctionCallee UCPopStackFrameFn;
  FunctionCallee UCCheckCopyBoundsFn;
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
  // Functions inline asm calls by name that the module did not have,
  // declared by declareAsmCallees before the scope split.
  StringMap<WeakTrackingVH> AsmCallees;

  // ABIList for custom function detection
  UCSanABIList ABIList;
  AttributeMask ReadOnlyNoneAttrs;

  // Type ID assignment for sidecar type table
  std::map<std::string, uint32_t> TypeIDMap; // type key -> type_id
  std::map<uint32_t, Type*> TypeIDToType;    // type_id -> LLVM Type*
  std::map<uint32_t, json::Object> LoadedTypes; // type_id -> JSON from previous modules
  // type_id -> real pointee type, for synthetic pointer entries minted by
  // getOrCreatePointerTypeID(). Opaque pointers make TypeIDToType[ID] just
  // "ptr" for these, so the pointee has to be tracked on the side.
  std::map<uint32_t, Type*> TypeIDPointee;
  // Builtin type IDs (fixed across modules):
  // 1=i1, 2=i8, 3=i16, 4=i32, 5=i64, 6=float, 7=double
  static const uint32_t kFirstDynamicTypeID = 16; // IDs 1-15 reserved for builtins
  uint32_t NextTypeID = kFirstDynamicTypeID;

  void initBuiltinTypeIDs();

  // Entry function arg info for type table
  struct ArgInfo {
    std::string name;
    uint32_t type_id;
  };
  std::string EntryFunctionName;
  std::vector<ArgInfo> EntryArgs;

  uint32_t getOrCreateTypeID(Type *T);
  // Mints (or reuses) a type_id for "pointer to PointeeTy". Opaque pointers
  // collapse every PointerType to the same Type object, so this can't key
  // off Type* like getOrCreateTypeID() does — it keys off the pointee's own
  // key instead, keeping distinct pointees distinguishable.
  uint32_t getOrCreatePointerTypeID(Type *PointeeTy);
  std::string getTypeKey(Type *T);
  void emitTypeTable();
  void loadTypeTable();

  void initializeRuntimeFunctions(Module &M);
  void initializeCustomFunctionTypes();
  bool loadMetadata();
  bool initializeModule(Module &M);

  Function *buildDangleFunction(Function *F);
  // the out-of-scope stubs that resign their pointer arguments (-r): a call
  // resigns the variadic ones itself (see visitCallBase)
  DenseSet<Function *> ResigningStubs;
  Function *buildDiscardFunction(Function *F);
  Function *buildDriverWrapperFunction(Function *F);
  Function *getCustomFunction(const Function *F);

  // Build the final wrapper return value, applying invert_ret if requested.
  // For invert on integer returns: returns `(ret == 0) ? 1 : 0`.  Targets are
  // comparators (memcmp/strcmp/...) whose `*ret_label` solver-side wants a
  // direct `== 0` / `!= 0` constraint anyway, so the extra icmp is desirable.
  Value *invertIntRet(Value *RetVal, Type *WrapperRetTy, bool Invert,
                      IRBuilder<> &IRB);

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
    if (I) I->setMetadata("nosanitize", MDNode::get(*Ctx, std::nullopt));
  }

  /// Marks a function as "nosanitize" so TaintPass will skip instrumenting it
  inline void markFunctionNosanitize(Function *F) {
    if (F) F->addFnAttr(Attribute::DisableSanitizerInstrumentation);
  }

  // Symbols the module's top-level asm defines (filled before instrumenting)
  StringSet<> AsmDefinedSyms;

  // An array the module declares without a size and does not define in its
  // own asm (kprobes' optprobe_template_entry[] has real bytes there)
  bool isUnsizedExternArray(GlobalVariable *GV) {
    auto *AT = dyn_cast<ArrayType>(GV->getValueType());
    return GV->isDeclaration() && AT && AT->getNumElements() == 0 &&
           !AsmDefinedSyms.contains(GV->getName());
  }

  // Memory that holds a pointer as an integer: a global, or a field of a
  // struct type, by byte offset (see collectPointerSlots)
  using PointerSlot = std::pair<const void *, int64_t>;
  DenseSet<PointerSlot> PointerSlots;
  // the integer loads from them (by the instruction: instrumenting replaces
  // a load's address with the checked pointer, which names no slot)
  DenseSet<const LoadInst *> PointerIntLoads;
  std::optional<PointerSlot> slotOf(Value *Addr);
  void collectPointerSlots(Module &M);

public:
  UCSan() = default;

  // Whether integer X is a pointer's value: a ptrtoint, or loaded from a
  // pointer slot -- through tag masks and constant offsets
  bool isPointerInt(Value *X);

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
  // Ptr -> its GEP base checks (visitGetElementPtrInst), one per region
  // they dominate
  DenseMap<Value *, SmallVector<Instruction *, 2>> GEPBaseChecks;
  SmallVector<Value *, 16> NonZeroChecks;

  struct LoadedPointerSummary {
    unsigned ArgNo;
    int64_t FieldOffset;
  };

  using MemoryAccessSummary = symsan::ucsan::MemoryAccessSummary;
  DenseMap<Value *, LoadedPointerSummary> LoadedPointerSummaries;
  SmallVector<MemoryAccessSummary, 8> MemoryAccessSummaries;

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
  /// Unread: bytes of a primitive no use reads (see Bitfield.h)
  Value *loadShadow(Value *Addr, uint64_t Size, Align Align, Type *Ty, Instruction *Pos,
                    uint64_t Unread = 0);
  
  /// XXX: we do not union taint labels for aggregate types before store;
  ///      instead, we store each privimitive field individually.
  ///
  /// Store all primitive subtypes of T, using the aggrate shadow value.
  ///
  /// SS(Addr, {T1,T2, ...}) = SS(SubAddr, T1), SS(SubAddr, T2), ...
  /// SS(Addr, [T1,T2,...]) = SS(SubAddr, T1), SS(SubAddr, T2), ...
  /// SS(Addr, PS) = SS(Addr, PS)
  void storeShadow(Value *Addr, uint64_t Size, Align Align, Value *Shadow, Type *Ty, Instruction *Pos);

  /// Whether a cached check's result (Checked) still holds at Pos: nothing
  /// between them can move a UC object (see checkPointer).
  bool reusableCheck(Instruction *Checked, Instruction *Pos);
  // Alignment: what the access assumes of the address (the IR's align),
  // which the runtime holds a UC object's real address to
  Value *checkPointer(Value *Ptr, Value *Size, bool dereference, IRBuilder<> &IRB,
                      uint32_t TypeID = 0, MaybeAlign Alignment = std::nullopt);
  void checkGlobalDest(Value *Dest, Value *Length, IRBuilder<> &IRB);
  void recordPointerLoadSummary(LoadInst &LI);
  void recordMemoryAccessSummary(Value *Ptr, uint64_t AccessSize, bool IsWrite,
                                 uint32_t TypeID, Instruction *I);
  void emitMemoryAccessSummaries();

  UCSanFunction(UCSan &UC, Function *F)
      : UC(UC), F(F) {
    DT.recalculate(*F);
  }

private:
  /// Loads a primivite shadow label
  Value *loadPrimitiveShadow(Value *Addr, uint64_t Size, Align Align,
                             Type *Ty, IRBuilder<> &IRB, uint64_t Unread = 0);
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

// (defined below, in the same unnamed namespace)
namespace {
struct AsmOp;
struct AsmInsn;
} // namespace

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
  void visitAtomicCmpXchgInst(AtomicCmpXchgInst &I);
  void visitLoadInst(LoadInst &LI);
  void visitStoreInst(StoreInst &SI);
  void visitMemCpyInst(MemCpyInst &I);
  void visitMemSetInst(MemSetInst &I);
  void visitMemMoveInst(MemMoveInst &I);
  void visitVACopyInst(VACopyInst &I);
  void visitGetElementPtrInst(GetElementPtrInst &GEPI);
  void visitSelectInst(SelectInst &I);
  void visitPHINode(PHINode &PN);
  void visitInsertValueInst(InsertValueInst &I);
  void guardAsmIndirectCall(CallBase &CB, ArrayRef<AsmOp> Ops,
                            ArrayRef<AsmInsn> Insns);
  void visitExtractValueInst(ExtractValueInst &I);
  void visitUnreachableInst(UnreachableInst &I);
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

  // Pointer checking: void* ucsan_check_pointer(void*, i16, i64, i1, i32, i32)
  UCCheckPointerFnTy = FunctionType::get(
    VoidPtrTy,
    {VoidPtrTy, PrimitiveShadowTy, Int64Ty, Int1Ty, Int32Ty, Int32Ty},
    false);
  UCCheckPointerFn = M.getOrInsertFunction("ucsan_check_pointer", UCCheckPointerFnTy);
  F = dyn_cast<Function>(UCCheckPointerFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // Inverse pointer translation: void* ucsan_uncheck_pointer(void*, i16)
  // Converts a real pointer returned by a libc call (e.g. strchr -> haystack +
  // index in the materialized buffer) back into the caller's UC pseudo space,
  // using the haystack pointer's shadow label to find the backing object.
  UCUncheckPointerFnTy = FunctionType::get(
    VoidPtrTy,
    {VoidPtrTy, PrimitiveShadowTy},
    false);
  UCUncheckPointerFn = M.getOrInsertFunction("ucsan_uncheck_pointer", UCUncheckPointerFnTy);
  F = dyn_cast<Function>(UCUncheckPointerFn.getCallee()->stripPointerCasts());
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

  // Argument initialization: void* ucsan_set_label_for_args(i32, i32, i8, i64)
  UCSetLabelForArgsFnTy = FunctionType::get(
    VoidPtrTy,
    {Int32Ty, Int32Ty, Int8Ty, Int64Ty},
    false);
  UCSetLabelForArgsFn = M.getOrInsertFunction("ucsan_set_label_for_args", UCSetLabelForArgsFnTy);
  F = dyn_cast<Function>(UCSetLabelForArgsFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // Load pointer shadow: i16 ucsan_load_pointer_shadow(i16*, i64, i1, void*, i64)
  // 4th arg: concrete source address (for make_input addr range lookup)
  // 5th arg: the bytes no use reads (see Bitfield.h)
  UCLoadPointerShadowFnTy = FunctionType::get(
    PrimitiveShadowTy,
    {PrimitiveShadowPtrTy, Int64Ty, Int1Ty, VoidPtrTy, Int64Ty},
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

  // Store a bitfield's shadow (see Bitfield.h):
  // void ucsan_store_rmw_shadow(i16, i16, i16, i16*, i64, i64)
  UCStoreRMWShadowFnTy = FunctionType::get(
    Type::getVoidTy(*Ctx),
    {PrimitiveShadowTy, PrimitiveShadowTy, PrimitiveShadowTy,
     PrimitiveShadowPtrTy, Int64Ty, Int64Ty},
    false);
  UCStoreRMWShadowFn = M.getOrInsertFunction("ucsan_store_rmw_shadow", UCStoreRMWShadowFnTy);
  F = dyn_cast<Function>(UCStoreRMWShadowFn.getCallee()->stripPointerCasts());
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

  // i16 ucsan_trace_global(i64 Address, i64 Size)
  // Returns a shadow label representing bounds for a fixed-size global object.
  UCTraceGlobalFnTy = FunctionType::get(
    PrimitiveShadowTy,
    {Int64Ty, Int64Ty},
    false);
  UCTraceGlobalFn = M.getOrInsertFunction("ucsan_trace_global", UCTraceGlobalFnTy);
  F = dyn_cast<Function>(UCTraceGlobalFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // i16 ucsan_trace_unsized_global(i64 Address)
  // The pointer label of an array declared without a size, see checkPointer.
  UCTraceUnsizedGlobalFn = M.getOrInsertFunction(
      "ucsan_trace_unsized_global",
      FunctionType::get(PrimitiveShadowTy, {Int64Ty}, false));
  F = dyn_cast<Function>(UCTraceUnsizedGlobalFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // i16 ucsan_int_to_pointer(i64 Value, i16 Label, i64 Width)
  // The pointer label of an inttoptr, see visitCastInst.
  UCIntToPointerFn = M.getOrInsertFunction(
      "ucsan_int_to_pointer",
      FunctionType::get(PrimitiveShadowTy, {Int64Ty, PrimitiveShadowTy, Int64Ty},
                        false));
  F = dyn_cast<Function>(UCIntToPointerFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // void ucsan_check_global_bounds(ptr Addr, i16 BoundsLabel, i64 Size)
  // Bounds a memory intrinsic's write into a global, see checkGlobalDest.
  UCCheckGlobalBoundsFnTy = FunctionType::get(
    Type::getVoidTy(*Ctx),
    {VoidPtrTy, PrimitiveShadowTy, Int64Ty},
    false);
  UCCheckGlobalBoundsFn =
      M.getOrInsertFunction("ucsan_check_global_bounds", UCCheckGlobalBoundsFnTy);
  F = dyn_cast<Function>(UCCheckGlobalBoundsFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // void ucsan_trace_warn(ptr File, i32 Line, i32 Flags)
  // Reports a kernel WARN() (see visitInlineAsm) and returns.
  UCTraceWarnFnTy = FunctionType::get(
    Type::getVoidTy(*Ctx),
    {VoidPtrTy, Int32Ty, Int32Ty},
    false);
  UCTraceWarnFn = M.getOrInsertFunction("ucsan_trace_warn", UCTraceWarnFnTy);
  F = dyn_cast<Function>(UCTraceWarnFn.getCallee()->stripPointerCasts());
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

  // void ucsan_check_copy_bounds(void *dst, i16 dst_label, void *src, i16 src_label, i64 dst_bound)
  // Check if a copy operation can overflow the destination buffer
  UCCheckCopyBoundsFnTy = FunctionType::get(
    Type::getVoidTy(*Ctx),
    {VoidPtrTy, PrimitiveShadowTy, VoidPtrTy, PrimitiveShadowTy, Int64Ty},
    false);
  UCCheckCopyBoundsFn = M.getOrInsertFunction("ucsan_check_copy_bounds", UCCheckCopyBoundsFnTy);
  F = dyn_cast<Function>(UCCheckCopyBoundsFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // void ucsan_materialize_range(ptr addr, i64 n): label the bytes of a
  // lazily created object that have no UCSan label yet (on-demand labels),
  // before a shadow copy reads them
  UCMaterializeRangeFn = M.getOrInsertFunction(
      "ucsan_materialize_range",
      FunctionType::get(Type::getVoidTy(*Ctx), {VoidPtrTy, Int64Ty}, false));
  F = dyn_cast<Function>(UCMaterializeRangeFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // void ucsan_fill_pattern(ptr addr, i64 value, i64 elem_size, i64 count):
  // the stores of a lowered `rep stos{w,l,q}` (see visitInlineAsm)
  UCFillPatternFn = M.getOrInsertFunction(
      "ucsan_fill_pattern",
      FunctionType::get(Type::getVoidTy(*Ctx),
                        {VoidPtrTy, Int64Ty, Int64Ty, Int64Ty}, false));
  F = dyn_cast<Function>(UCFillPatternFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // i1 ucsan_ptr_diff_rewrite(ptr p, i16 lp, ptr q, i16 lq), and
  // i64 __dfsw_ucsan_ptr_index(i1 rewrite, i64 elem, ptr p, ptr q, i16 lp,
  // i16 lq): the element index `p - q` of two UC pointers when it is not the
  // one their pseudo-pointers give, see visitBinaryOperator.  The __dfsw_ prefix is what makes
  // TaintPass take its result's SymSan label from the retval TLS.
  UCPtrDiffRewriteFn = M.getOrInsertFunction(
      "ucsan_ptr_diff_rewrite",
      FunctionType::get(Int1Ty, {VoidPtrTy, PrimitiveShadowTy, VoidPtrTy,
                                 PrimitiveShadowTy}, false));
  F = dyn_cast<Function>(UCPtrDiffRewriteFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);
  UCPtrIndexFn = M.getOrInsertFunction(
      "__dfsw_ucsan_ptr_index",
      FunctionType::get(Int64Ty, {Int1Ty, Int64Ty, VoidPtrTy, VoidPtrTy,
                                  PrimitiveShadowTy, PrimitiveShadowTy}, false));
  F = dyn_cast<Function>(UCPtrIndexFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // ptr ucsan_vmcs_field(i64 field): the VMCS slot vmread/vmwrite act on
  UCVmcsFieldFn = M.getOrInsertFunction(
      "ucsan_vmcs_field", FunctionType::get(VoidPtrTy, {Int64Ty}, false));
  F = dyn_cast<Function>(UCVmcsFieldFn.getCallee()->stripPointerCasts());
  markFunctionNosanitize(F);
  UCRuntimeFunctions.insert(F);

  // __ucsan_symbolize_input: declared in user source code, not emitted by pass.
  // Register as runtime function to prevent dangle wrapping.
  // Arg shadow is stored to __ucsan_arg_tls automatically by visitCallBase.
  if (Function *MakeInputFn = M.getFunction("__ucsan_symbolize_input")) {
    markFunctionNosanitize(MakeInputFn);
    UCRuntimeFunctions.insert(MakeInputFn);
  }
}

void UCSan::initializeCustomFunctionTypes() {
  // Custom function types will be populated based on YAML metadata
  // TODO: add more custom function prototypes here
  CustomFuncTypes["malloc"] = FunctionType::get(VoidPtrTy, {Int64Ty}, false);
  CustomFuncTypes["free"] = FunctionType::get(Type::getVoidTy(*Ctx), {VoidPtrTy}, false);
  CustomFuncTypes["realloc"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, Int64Ty}, false);
  CustomFuncTypes["calloc"] = FunctionType::get(VoidPtrTy, {Int64Ty, Int64Ty}, false);
  CustomFuncTypes["strdup"] = FunctionType::get(VoidPtrTy, {VoidPtrTy}, false);
  CustomFuncTypes["strndup"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, Int64Ty}, false);
  CustomFuncTypes["exit"] = FunctionType::get(Type::getVoidTy(*Ctx), {Int32Ty}, false);

  // String copy functions
  CustomFuncTypes["strcpy"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, VoidPtrTy}, false);
  CustomFuncTypes["stpcpy"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, VoidPtrTy}, false);
  CustomFuncTypes["strncpy"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, VoidPtrTy, Int64Ty}, false);
  CustomFuncTypes["strcat"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, VoidPtrTy}, false);
  CustomFuncTypes["strncat"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, VoidPtrTy, Int64Ty}, false);

  // Comparison functions
  CustomFuncTypes["memcmp"] = FunctionType::get(Int32Ty, {VoidPtrTy, VoidPtrTy, Int64Ty}, false);
  CustomFuncTypes["bcmp"] = FunctionType::get(Int32Ty, {VoidPtrTy, VoidPtrTy, Int64Ty}, false);
  CustomFuncTypes["strcmp"] = FunctionType::get(Int32Ty, {VoidPtrTy, VoidPtrTy}, false);
  CustomFuncTypes["strncmp"] = FunctionType::get(Int32Ty, {VoidPtrTy, VoidPtrTy, Int64Ty}, false);
  CustomFuncTypes["strcasecmp"] = FunctionType::get(Int32Ty, {VoidPtrTy, VoidPtrTy}, false);
  CustomFuncTypes["strncasecmp"] = FunctionType::get(Int32Ty, {VoidPtrTy, VoidPtrTy, Int64Ty}, false);

  // Search functions
  CustomFuncTypes["memchr"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, Int32Ty, Int64Ty}, false);
  CustomFuncTypes["memrchr"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, Int32Ty, Int64Ty}, false);
  CustomFuncTypes["strchr"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, Int32Ty}, false);
  CustomFuncTypes["strrchr"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, Int32Ty}, false);
  CustomFuncTypes["strstr"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, VoidPtrTy}, false);
  CustomFuncTypes["strnstr"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, VoidPtrTy, Int64Ty}, false);
  CustomFuncTypes["strpbrk"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, VoidPtrTy}, false);
  CustomFuncTypes["memmem"] = FunctionType::get(VoidPtrTy, {VoidPtrTy, Int64Ty, VoidPtrTy, Int64Ty}, false);

  // Length function
  CustomFuncTypes["strlen"] = FunctionType::get(Int64Ty, {VoidPtrTy}, false);
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

  // Expand shims_yaml list into shims map
  for (const auto &name : Scope.shims_yaml) {
    Scope.shims[name] = true;                    // original function
    Scope.shims["__shim_" + name] = false;       // shim replacement
  }

  return true;
}

//===----------------------------------------------------------------------===//
// Type ID assignment for sidecar type table
//===----------------------------------------------------------------------===//

void UCSan::initBuiltinTypeIDs() {
  // Reserve fixed IDs for primitive types so they're stable across modules
  auto assign = [&](uint32_t ID, Type *T) {
    std::string Key = getTypeKey(T);
    TypeIDMap[Key] = ID;
    TypeIDToType[ID] = T;
  };
  assign(1, Int1Ty);
  assign(2, Int8Ty);
  assign(3, Int16Ty);
  assign(4, Int32Ty);
  assign(5, Int64Ty);
  assign(6, Type::getFloatTy(*Ctx));
  assign(7, Type::getDoubleTy(*Ctx));
  assign(8, VoidPtrTy);
}

std::string UCSan::getTypeKey(Type *T) {
  if (auto *ST = dyn_cast<StructType>(T)) {
    if (ST->hasName())
      return ST->getName().str();
  }
  // For non-named types, use the LLVM type string
  std::string Key;
  raw_string_ostream OS(Key);
  T->print(OS);
  return Key;
}

uint32_t UCSan::getOrCreateTypeID(Type *T) {
  std::string Key = getTypeKey(T);
  auto It = TypeIDMap.find(Key);
  if (It != TypeIDMap.end())
    return It->second;
  uint32_t ID = NextTypeID++;
  TypeIDMap[Key] = ID;
  TypeIDToType[ID] = T;
  // Recursively assign IDs to embedded sub-types (struct fields, array elements)
  // Don't chase through pointers — those get their own checkPointer at runtime
  if (auto *ST = dyn_cast<StructType>(T)) {
    for (unsigned I = 0, N = ST->getNumElements(); I < N; ++I)
      getOrCreateTypeID(ST->getElementType(I));
  } else if (auto *AT = dyn_cast<ArrayType>(T)) {
    getOrCreateTypeID(AT->getElementType());
  }
  return ID;
}

// Opaque pointers erase pointee type from a pointer Value's Type, but GEP
// instructions still carry an explicit SourceElementType (they need it to
// compute the byte offset). So find the pointee type by walking forward
// through V's uses: a GEP that takes V as its base pointer operand reveals
// what V conceptually points to. Chases through PHI nodes (e.g. the loop
// variable in `for (n = head; n; n = n->next)`) since a GEP consuming a
// loaded/argument pointer is often one hop removed via a PHI rather than a
// direct use. Purely a compile-time analysis, so an exhaustive walk (bounded
// by the Visited set against PHI cycles) is affordable.
static Type *findPointeeTypeFromUses(Value *V, SmallPtrSetImpl<Value *> &Visited) {
  if (!Visited.insert(V).second)
    return nullptr;
  for (User *U : V->users()) {
    if (auto *GEP = dyn_cast<GetElementPtrInst>(U)) {
      if (GEP->getPointerOperand() == V)
        return GEP->getSourceElementType();
    } else if (auto *PN = dyn_cast<PHINode>(U)) {
      if (Type *Found = findPointeeTypeFromUses(PN, Visited))
        return Found;
    }
  }
  return nullptr;
}

static Type *findPointeeTypeFromUses(Value *V) {
  SmallPtrSet<Value *, 16> Visited;
  return findPointeeTypeFromUses(V, Visited);
}

// Opaque pointers erase pointee type going forward too: a pointer Value's own
// Type carries nothing. For call sites that need *some* size/type for a
// pointer whose uses don't reveal it (it's about to be handed to opaque code
// - an indirect call, inline asm, a custom/wrapped function), fall back to
// tracing backward to the concrete allocation it originates from. alloca and
// global declarations always carry their real allocated type regardless of
// pointer opacity. Returns nullptr (unknown) for anything else, e.g. a heap
// pointer or a plain incoming argument with no local origin.
static Type *getUnderlyingObjectType(Value *Ptr) {
  Value *Obj = getUnderlyingObject(Ptr);
  if (auto *AI = dyn_cast<AllocaInst>(Obj))
    return AI->getAllocatedType();
  if (auto *GV = dyn_cast<GlobalVariable>(Obj))
    return GV->getValueType();
  return nullptr;
}

uint32_t UCSan::getOrCreatePointerTypeID(Type *PointeeTy) {
  std::string Key = "ptr->" + getTypeKey(PointeeTy);
  auto It = TypeIDMap.find(Key);
  if (It != TypeIDMap.end())
    return It->second;
  uint32_t ID = NextTypeID++;
  TypeIDMap[Key] = ID;
  TypeIDToType[ID] = VoidPtrTy;
  TypeIDPointee[ID] = PointeeTy;
  getOrCreateTypeID(PointeeTy); // ensure the pointee itself has an entry too
  return ID;
}

void UCSan::loadTypeTable() {
  if (ClTypeTable.empty()) return;

  auto BufOrErr = llvm::MemoryBuffer::getFile(ClTypeTable);
  if (!BufOrErr) return; // file doesn't exist yet, that's ok

  auto Parsed = json::parse(BufOrErr.get()->getBuffer());
  if (!Parsed) {
    errs() << "Warning: failed to parse type table: " << ClTypeTable << "\n";
    return;
  }

  auto *Root = Parsed->getAsObject();
  if (!Root) return;

  // Load next_type_id
  if (auto NID = Root->getInteger("next_type_id"))
    NextTypeID = *NID;

  // Load existing type name->id mappings
  if (auto *Types = Root->getObject("types")) {
    for (auto &KV : *Types) {
      auto *TypeObj = KV.second.getAsObject();
      if (!TypeObj) continue;
      auto ID = TypeObj->getInteger("type_id");
      auto Name = TypeObj->getString("key");
      if (ID && Name) {
        TypeIDMap[Name->str()] = *ID;
        // Preserve the full JSON object for types we can't resolve to LLVM Type*
        LoadedTypes[*ID] = json::Object(*TypeObj);
      }
    }
  }
}

void UCSan::emitTypeTable() {
  if (ClTypeTable.empty()) return;

  const DataLayout &DL = Mod->getDataLayout();

  // Build debug info map: LLVM struct name -> DICompositeType
  // StructType::getName() returns e.g. "struct.node"
  // DICompositeType::getName() returns e.g. "node"
  std::map<std::string, DICompositeType*> DebugStructMap;
  DebugInfoFinder DIF;
  DIF.processModule(*Mod);
  for (auto *Ty : DIF.types()) {
    if (auto *CT = dyn_cast<DICompositeType>(Ty)) {
      if (CT->getTag() == dwarf::DW_TAG_structure_type && !CT->getName().empty()) {
        // Map both "struct.<name>" and just "<name>" for flexible matching
        DebugStructMap["struct." + CT->getName().str()] = CT;
      }
    }
  }

  json::Object Root;
  Root["next_type_id"] = NextTypeID;
  Root["entry_function"] = EntryFunctionName;

  // Entry args - also try to get arg names from debug info
  json::Array ArgsArr;
  // Find entry function's debug info for arg names
  std::vector<std::string> EntryArgNames;
  if (Function *EntryF = Mod->getFunction(EntryFunctionName)) {
    if (auto *SP = EntryF->getSubprogram()) {
      for (auto *N : SP->getRetainedNodes()) {
        if (auto *DV = dyn_cast<DILocalVariable>(N)) {
          if (DV->isParameter()) {
            unsigned Idx = DV->getArg() - 1; // DILocalVariable arg is 1-based
            if (Idx >= EntryArgNames.size())
              EntryArgNames.resize(Idx + 1);
            EntryArgNames[Idx] = DV->getName().str();
          }
        }
      }
    }
  }
  for (unsigned I = 0; I < EntryArgs.size(); ++I) {
    json::Object ArgObj;
    std::string Name = EntryArgs[I].name;
    if (Name.empty() && I < EntryArgNames.size())
      Name = EntryArgNames[I];
    ArgObj["name"] = Name;
    ArgObj["type_id"] = EntryArgs[I].type_id;
    ArgsArr.push_back(std::move(ArgObj));
  }
  Root["args"] = std::move(ArgsArr);

  // Types
  json::Object TypesObj;
  for (auto &KV : TypeIDToType) {
    uint32_t ID = KV.first;
    Type *T = KV.second;
    json::Object TypeObj;
    TypeObj["type_id"] = ID;
    TypeObj["key"] = getTypeKey(T);

    if (auto *ST = dyn_cast<StructType>(T)) {
      TypeObj["kind"] = "struct";
      TypeObj["name"] = ST->hasName() ? ST->getName().str() : "(anonymous)";
      if (ST->isSized()) {
        const StructLayout *SL = DL.getStructLayout(ST);
        TypeObj["size"] = (int64_t)DL.getTypeAllocSize(ST);

        // Look up field names from debug info
        DICompositeType *DCT = nullptr;
        if (ST->hasName()) {
          auto It = DebugStructMap.find(ST->getName().str());
          if (It != DebugStructMap.end())
            DCT = It->second;
        }

        json::Array Fields;
        for (unsigned I = 0, N = ST->getNumElements(); I < N; ++I) {
          json::Object Field;
          Field["index"] = I;
          Field["offset"] = (int64_t)SL->getElementOffset(I);
          Field["size"] = (int64_t)DL.getTypeAllocSize(ST->getElementType(I));
          Field["type_id"] = getOrCreateTypeID(ST->getElementType(I));

          // Extract field name from debug info
          if (DCT) {
            auto Elements = DCT->getElements();
            if (I < Elements.size()) {
              if (auto *DT = dyn_cast<DIDerivedType>(Elements[I])) {
                Field["name"] = DT->getName().str();
              }
            }
          }

          Fields.push_back(std::move(Field));
        }
        TypeObj["fields"] = std::move(Fields);
      }
    } else if (auto *AT = dyn_cast<ArrayType>(T)) {
      TypeObj["kind"] = "array";
      TypeObj["num_elements"] = (int64_t)AT->getNumElements();
      TypeObj["element_type_id"] = getOrCreateTypeID(AT->getElementType());
      if (T->isSized())
        TypeObj["size"] = (int64_t)DL.getTypeAllocSize(T);
    } else if (isa<PointerType>(T)) {
      TypeObj["kind"] = "pointer";
      TypeObj["size"] = (int64_t)DL.getTypeAllocSize(T);
      // Opaque pointers carry no pointee info in T itself. Entries minted by
      // getOrCreatePointerTypeID() record the real pointee on the side;
      // anything else is a generic/unknown pointer (pointee_type_id 0).
      auto PointeeIt = TypeIDPointee.find(ID);
      Type *PointeeTy = PointeeIt != TypeIDPointee.end() ? PointeeIt->second : nullptr;
      if (PointeeTy && PointeeTy->isSized())
        TypeObj["pointee_type_id"] = getOrCreateTypeID(PointeeTy);
      else
        TypeObj["pointee_type_id"] = 0;
    } else {
      // Primitive types (integers, floats, etc.)
      TypeObj["kind"] = "primitive";
      std::string Name;
      raw_string_ostream OS(Name);
      T->print(OS);
      TypeObj["name"] = Name;
      if (T->isSized())
        TypeObj["size"] = (int64_t)DL.getTypeAllocSize(T);
    }

    TypesObj[std::to_string(ID)] = std::move(TypeObj);
  }

  // Merge in loaded types from previous modules that weren't re-encountered
  for (auto &KV : LoadedTypes) {
    std::string Key = std::to_string(KV.first);
    if (!TypesObj.get(Key))
      TypesObj[Key] = json::Value(json::Object(KV.second));
  }

  Root["types"] = std::move(TypesObj);

  // Write to file
  std::error_code EC;
  raw_fd_ostream OS(ClTypeTable, EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "Warning: failed to write type table: " << ClTypeTable << "\n";
    return;
  }
  OS << json::Value(std::move(Root));
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

    // A byval parameter points to this function's own copy, made by the
    // call: a real object, whatever the caller's pointer was (see the
    // prologue in runOnModule, which clears the copy's shadow).
    if (FArg.hasByValAttr())
      return UC.getZeroShadow(A);

    // Insert ArgTLS load at the start of the entry block. Use the
    // (BB, iterator) overload so we handle an empty entry block (e.g. an
    // auto-custom wrapper whose first checkPointer fires before any IR has
    // been emitted) — getFirstInsertionPt() returns end() and IRBuilder then
    // appends to the block.
    BasicBlock &EntryBB = F->getEntryBlock();
    IRBuilder<> IRB(*UC.Ctx);
    IRB.SetInsertPoint(&EntryBB, EntryBB.getFirstInsertionPt());
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
                                          Type *Ty, IRBuilder<> &IRB,
                                          uint64_t Unread) {
  if (Size == 0)
    return UC.ZeroPrimitiveShadow;

  Value *ShadowAddr = UC.getShadowAddress(Addr, IRB);
  // TOOD: Optimize for non-pointer types
  Value *ConcreteAddr = IRB.CreateBitCast(Addr, UC.VoidPtrTy);
  // With opaque pointers the cast is Addr itself, the load's own address (an
  // alloca, a GEP, a loaded pointer): marked nosanitize, TaintPass skipped it,
  // and an alloca read this way was never given SymSan's uninitialized label.
  if (ConcreteAddr != Addr)
    UC.markNosanitize(ConcreteAddr);
  CallInst *FallbackCall = IRB.CreateCall(
      UC.UCLoadPointerShadowFn,
      {ShadowAddr, ConstantInt::get(UC.Int64Ty, Size),
       ConstantInt::get(UC.Int1Ty, Ty->isPointerTy()), ConcreteAddr,
       ConstantInt::get(UC.Int64Ty, Unread)});
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
    InstAlign = Align(std::min(InstAlign.value(), (uint64_t)(DL).getABITypeAlign(SubTy).value()));
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
                                 Type *Ty, Instruction *Pos, uint64_t Unread) {
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

  // Only the shadow width's own alignment, not the access's scaled up: the
  // IR's alignment is a promise about the address the program computes, and
  // under UC the address is what ucsan_check_pointer returns, which need not
  // keep it (a seed value taken as a pointer into the image can be odd --
  // unregister_nmi_handler's list walk).  x86 does the access itself
  // unaligned; a shadow access scaled to 16 bytes became a movaps, and a
  // general-protection fault.
  const llvm::Align ShadowAlign(UCSan::ShadowWidthBytes);

  // now check if we're loading an aggragate object
  if (!isa<ArrayType>(Ty) && !isa<StructType>(Ty))
    return loadPrimitiveShadow(Addr, Size, ShadowAlign, Ty, IRB, Unread);

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
                           (uint64_t)(DL).getABITypeAlign(SubTy).value()));
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

  // the shadow width's alignment only, as in loadShadow
  const Align ShadowAlign(UCSan::ShadowWidthBytes);
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

  // libc/header byte-swap helpers are often emitted as out-of-scope static
  // functions. Returning an arbitrary symbolic value here breaks protocol
  // dispatch constraints like htons(ETHERTYPE_IP6). Keep these wrappers
  // semantic and let the later TaintPass model llvm.bswap normally.
  StringRef OrigName = F->getName();
  if (OrigName == "__bswap_16" || OrigName == "__bswap_32" ||
      OrigName == "__bswap_64") {
    BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", NewF);
    IRBuilder<> IRB(BB);
    Argument *Arg = &*NewF->arg_begin();
    Type *ArgTy = Arg->getType();
    if (ArgTy->isIntegerTy() && FT->getReturnType() == ArgTy) {
      Function *Bswap = Intrinsic::getDeclaration(Mod, Intrinsic::bswap, ArgTy);
      Value *Ret = IRB.CreateCall(Bswap, {Arg});
      IRB.CreateRet(Ret);
      return NewF;
    }
    IRB.CreateRet(Constant::getNullValue(FT->getReturnType()));
    return NewF;
  }

  // Some inputs are compiled with non-standard stack alignment; force realignment
  // so calls into UCSan runtime vararg logging are always safe.
  NewF->addFnAttr(Attribute::getWithStackAlignment(*Ctx, Align(16)));
  NewF->addFnAttr("stackrealign");
  markFunctionNosanitize(NewF);  // Mark dangle wrapper so TaintPass skips it
  FunctionType *NewFT = NewF->getFunctionType();
  BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", NewF);
  IRBuilder<> IRB(BB);

  // Create UCSanFunction context for shadow memory access
  UCSanFunction UF(*this, NewF);

  const DataLayout &DL = Mod->getDataLayout();
  bool ignore_resign = getWrapperKind(F) == WK_Ignore;
  bool resign_ptrargs = getenv("KO_RESIGN_PTRARGS") != nullptr && !ignore_resign;
  bool checker_ubi = getenv("KO_CHECKER_UBI") != nullptr;
  if (resign_ptrargs)
    ResigningStubs.insert(NewF);

  // Get return address for tracking
  auto RetAddr = IRB.CreateCall(LLVMReturnAddrFn, {ConstantInt::get(Int32Ty, 0)}, "retaddr");

  // Process pointer arguments if needed
  if (resign_ptrargs || checker_ubi) {
    unsigned ArgOffset = 0;
    unsigned n = FT->getNumParams();

    for (auto arg = NewF->arg_begin(); n != 0; ++arg, --n) {
      if (arg->getType()->isPointerTy()) {
        // F is an out-of-scope declaration (that's the point of a dangle
        // wrapper) with no body, and arg is a fresh stub argument with no
        // uses of its own - there's no pointee type to recover here under
        // opaque pointers, so treat the pointed-to size as unknown.
        ConstantInt *CI = ConstantInt::get(Int64Ty, 0);

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
          Value *BCI = IRB.CreatePointerCast(&*arg, VoidPtrTy);
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
  } else if (F->doesNotReturn()) {
    NewF->addFnAttr(Attribute::NoReturn);
    auto *ExitCall = IRB.CreateCall(ExitFn, {ConstantInt::get(Int32Ty, 0)});
    markNosanitize(ExitCall);
    IRB.CreateUnreachable();
  } else {
    IRB.CreateRetVoid();
  }

  return NewF;
}

Function *UCSan::buildDiscardFunction(Function *F) {
  // Creates a trivial stub for discarded functions (e.g., kernel helpers
  // like _copy_to_user/printk that have no implementation in UC mode).
  // The stub simply returns zero/void and is marked so TaintPass skips it.

  FunctionType *FT = F->getFunctionType();
  std::string FN = "__discard$" + F->getName().str();
  Function *NewF = Function::Create(FT, GlobalValue::LinkageTypes::PrivateLinkage,
                                    F->getAddressSpace(), FN, Mod);
  markFunctionNosanitize(NewF);

  BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", NewF);
  IRBuilder<> IRB(BB);

  Type *RT = FT->getReturnType();
  if (RT->isVoidTy())
    IRB.CreateRetVoid();
  else
    IRB.CreateRet(Constant::getNullValue(RT));

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
  NewF->getArg(0)->setName("argc");
  NewF->getArg(1)->setName("argv");

  // Ensure 16-byte stack alignment for calls into sanitizer vararg code (Printf).
  NewF->addFnAttr(Attribute::getWithStackAlignment(*Ctx, Align(16)));
  NewF->addFnAttr("stackrealign");
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

  // Record entry function info for type table
  EntryFunctionName = F->getName().str();
  EntryArgs.clear();

  // Initialize arguments for the entry point
  std::vector<Value *> Args;
  for (Function::arg_iterator ai = F->arg_begin(), ae = F->arg_end(); ai != ae; ++ai) {
    ConstantInt *ArgNo = ConstantInt::get(Int32Ty, ai->getArgNo());
    ConstantInt *ArgSize = ConstantInt::get(Int32Ty, DL.getTypeSizeInBits(ai->getType()));
    ConstantInt *IsPtr = ConstantInt::get(Int8Ty, ai->getType()->isPointerTy());
    ConstantInt *InitVal = ConstantInt::get(Int64Ty, 0);

    // Record arg type info. Entry args are what unittest-style seed gen
    // needs real types for, so recover pointer args' pointee type the same
    // way as pointer-typed loads: from how the argument gets used (e.g. a
    // GEP indexing into it) rather than from its now-opaque Type.
    Type *PointeeTy = ai->getType()->isPointerTy() ? findPointeeTypeFromUses(&*ai) : nullptr;
    uint32_t TypeID = PointeeTy ? getOrCreatePointerTypeID(PointeeTy)
                                : getOrCreateTypeID(ai->getType());
    EntryArgs.push_back({ai->getName().str(), TypeID});

    // Call runtime to create symbolic argument
    // Returns a pointer that we cast to the appropriate type
    Value *ret_val = IRB.CreateCall(UCSetLabelForArgsFn, {ArgNo, ArgSize, IsPtr, InitVal});
    if (ai->hasByValAttr() && ai->getParamByValType()->isSized()) {
      // a struct passed by value: the call copies it through the pointer,
      // so the pointer must be a real object -- the UC object the argument's
      // pseudo-pointer maps to -- and the call must say byval (it did not,
      // and the entry read its copy from a stack slot nothing had written:
      // rhashtable_lookup's struct rhashtable_params)
      Type *ByValTy = ai->getParamByValType();
      Value *LabelPtr = IRB.CreateGEP(
          PrimitiveShadowTy, ArgTLS,
          ConstantInt::get(Int64Ty, ai->getArgNo()));
      Value *Label = IRB.CreateLoad(PrimitiveShadowTy, LabelPtr);
      Value *Real = IRB.CreateCall(
          UCCheckPointerFn,
          {ret_val, Label, ConstantInt::get(Int64Ty, DL.getTypeAllocSize(ByValTy)),
           ConstantInt::get(Int1Ty, true),
           ConstantInt::get(Int32Ty, getOrCreateTypeID(ByValTy)),
           ConstantInt::get(Int32Ty, ai->getParamAlign().valueOrOne().value())});
      Args.push_back(Real);
      continue;
    }
    if (ai->getType()->isFloatingPointTy()) {
      // Can't bitcast pointer directly to float; go through integer
      Type *IntTy = IntegerType::get(*Ctx, DL.getTypeSizeInBits(ai->getType()));
      Value *int_val = IRB.CreatePtrToInt(ret_val, IntTy);
      Args.push_back(IRB.CreateBitCast(int_val, ai->getType()));
    } else {
      Args.push_back(IRB.CreateBitOrPointerCast(ret_val, ai->getType()));
    }
  }

  // Call the actual entry point function
  CallInst *EntryCall = IRB.CreateCall(F, Args);
  for (Argument &A : F->args())
    if (A.hasByValAttr())
      EntryCall->addParamAttr(
          A.getArgNo(), Attribute::getWithByValType(*Ctx, A.getParamByValType()));

  // Return 0 (success)
  IRB.CreateRet(ConstantInt::get(Int32Ty, 0));

  // Add basic block tracing to entry point if enabled
  if (ClTraceBB) {
    unsigned int BBCount = BBID_STEP;
    for (Function::iterator BI = F->begin(), BE = F->end(); BI != BE; ++BI, ++BBCount) {
      ConstantInt *BBID = ConstantInt::get(Int32Ty, BBCount);

      // Add trace call at beginning of basic block.
      // Use getFirstInsertionPt() (not getFirstNonPHI): in C++ EH landing pads
      // the landingpad must remain the first non-PHI instruction, and
      // getFirstInsertionPt() advances past EH pads so we don't break the block.
      CallInst *CI = CallInst::Create(UCTraceBBFn,
                      {ConstantInt::get(Int32Ty, 0), BBID},
                      "", &*BI->getFirstInsertionPt());

      // Add metadata for BB tracking
      MDNode *MD = MDNode::get(Mod->getContext(),
                              {ConstantAsMetadata::get(BBID)});
      BI->getTerminator()->setMetadata(BBIDName, MD);
    }
  }

  return NewF;
}

Value *UCSan::invertIntRet(Value *RetVal, Type *WrapperRetTy, bool Invert,
                            IRBuilder<> &IRB) {
  if (!Invert || !RetVal->getType()->isIntegerTy() ||
      !WrapperRetTy->isIntegerTy()) {
    return IRB.CreateBitOrPointerCast(RetVal, WrapperRetTy);
  }
  Value *IsZero =
      IRB.CreateICmpEQ(RetVal, ConstantInt::get(RetVal->getType(), 0));
  return IRB.CreateZExtOrTrunc(IsZero, WrapperRetTy);
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

  // Check if ref function is a taint type (handled by TaintPass).
  // For taint refs, generate a simple forwarding wrapper that calls the ref
  // function directly with remapped args. TaintPass will instrument the
  // wrapper body and convert the inner call to __dfsw_<ref>.
  bool IsTaintRef = ABIList.isIn(CustomEntry.ref_name, "taint");

  // Create wrapper function
  auto Linkage = Function::InternalLinkage;
  auto WrappedName = "__auto_dfsw_" + Name;
  auto RefedName = IsTaintRef ? CustomEntry.ref_name
                              : ("__dfsw_" + CustomEntry.ref_name);

  FunctionType *RefedFuncType = CustomFuncTypes[CustomEntry.ref_name];
  FunctionType *WrapperType = FunctionType::get(F->getReturnType(),
                                                F->getFunctionType()->params(),
                                                F->isVarArg());

  Function *WrapperFunc = Function::Create(WrapperType, Linkage, WrappedName, *Mod);
  // Keep wrapper/runtime call ABI robust even when module stack alignment is 8.
  WrapperFunc->addFnAttr(Attribute::getWithStackAlignment(*Ctx, Align(16)));
  WrapperFunc->addFnAttr("stackrealign");
  // For ucsan custom refs, mark wrapper nosanitize so TaintPass skips its body.
  // For taint refs, leave the wrapper instrumentable so TaintPass wraps the
  // inner ref call with its proper taint-label handling.
  if (!IsTaintRef)
    markFunctionNosanitize(WrapperFunc);
  BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", WrapperFunc);
  IRBuilder<> IRB(BB);

  // Create UCSanFunction context for shadow memory access
  UCSanFunction UF(*this, WrapperFunc);

  // Build argument mapping
  std::map<unsigned int, unsigned int> ArgMap;
  std::map<unsigned int, unsigned int> ArgTLSMap;

  for (auto &ArgMapEntry : CustomEntry.arg_maps) {
    ArgMap[ArgMapEntry.ucsan_idx] = ArgMapEntry.idx;
  }

  const DataLayout &DL = Mod->getDataLayout();

  if (IsTaintRef) {
    // Simple forwarding wrapper: call the ref function directly with remapped
    // args. TaintPass will instrument this body and wrap the call with the
    // proper __dfsw_<ref> taint-label handling.
    FunctionCallee RefedFunc = Mod->getOrInsertFunction(RefedName, RefedFuncType);

    std::vector<Value *> Args;
    for (unsigned i = 0, e = RefedFuncType->getNumParams(); i != e; ++i) {
      if (ArgMap.find(i) == ArgMap.end()) {
        errs() << "Error: Argument " << i << " not in arg_maps\n";
        return nullptr;
      }
      unsigned idx = ArgMap[i];
      Value *Arg = WrapperFunc->getArg(idx);
      // Cast wrapper arg to ref function's expected param type if they differ
      // (e.g. uint8_t* -> void*).
      Type *RefParamTy = RefedFuncType->getParamType(i);
      if (Arg->getType() != RefParamTy)
        Arg = IRB.CreateBitOrPointerCast(Arg, RefParamTy);
      Args.push_back(Arg);
    }

    // Lazy-init / enlarge the symbolic object behind each pointer arg with
    // the right byte count.  The size is taken from the abilist sizeN entry
    // on the ref function (e.g. memcmp=size2 → 3rd arg holds the count);
    // for ref functions with no entry (e.g. strcmp) pass 0 (strlen-determined).
    int SizeArgIdx = ABIList.getSizeArgIdx(CustomEntry.ref_name);
    Value *SizeVal;
    if (SizeArgIdx >= 0 && (unsigned)SizeArgIdx < Args.size()) {
      SizeVal = IRB.CreateZExtOrTrunc(Args[SizeArgIdx], Int64Ty);
      markNosanitize(SizeVal);
    } else {
      SizeVal = ConstantInt::get(Int64Ty, 0);
    }
    for (unsigned i = 0, e = Args.size(); i != e; ++i) {
      if (!Args[i]->getType()->isPointerTy()) continue;
      // typeID 0 = typeless bytes (matches WK_TaintCustom convention)
      Args[i] = UF.checkPointer(Args[i], SizeVal, true, IRB, 0);
    }

    if (!F->getReturnType()->isVoidTy()) {
      Value *RetVal = IRB.CreateCall(RefedFunc, Args);
      Value *FinalRet = invertIntRet(RetVal, F->getReturnType(),
                                      CustomEntry.invert_ret, IRB);
      IRB.CreateRet(FinalRet);
    } else {
      IRB.CreateCall(RefedFunc, Args);
      IRB.CreateRetVoid();
    }

    CustomFuncs[Name] = WrapperFunc;
    return WrapperFunc;
  }

  // ucsan custom ref: use the existing __dfsw_<ref> wrapper that takes
  // extra ucsan_label shadow arguments via __ucsan_arg_tls / __ucsan_retval_tls.

  // Get or insert the referenced function with transformed type (includes shadow args)
  TransformedFunction TransformedFn = getCustomFunctionType(RefedFuncType);
  FunctionCallee RefedFunc = Mod->getOrInsertFunction(RefedName, TransformedFn.TransformedType);

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
    Value *FinalRet = invertIntRet(RetVal, F->getReturnType(),
                                    CustomEntry.invert_ret, IRB);
    IRB.CreateRet(FinalRet);
  } else {
    IRB.CreateCall(RefedFunc, Args);
    IRB.CreateRetVoid();
  }

  CustomFuncs[Name] = WrapperFunc;
  return WrapperFunc;
}

UCSan::WrapperKind UCSan::getWrapperKind(Function *F) {
  // Check ABIList for taint custom functions (handled by TaintPass if available)
  if (ABIList.isIn(*F, "taint"))
    return WK_TaintCustom;

  // Check ABIList for custom functions (priority)
  if (ABIList.isIn(*F, "custom"))
    return WK_Custom;

  // Check ABIList for discard functions (completely ignored, no wrapper)
  if (ABIList.isIn(*F, "discard"))
    return WK_Discard;

  // Check ABIList for ignored external functions. These still get an external
  // wrapper, but the wrapper must not resign pointer arguments.
  if (ABIList.isIn(*F, "ignore"))
    return WK_Ignore;

  // Check ABIList for uninstrumented functions
  if (ABIList.isIn(*F, "uninstrumented"))
    return WK_Uninstrumented;

  // Check if function is in the shims map from YAML metadata
  auto shimIt = Scope.shims.find(F->getName().str());
  if (shimIt != Scope.shims.end()) {
    return shimIt->second ? WK_ShimOrig : WK_ShimTarget;
  }

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
    ArgTypes.push_back(getShadowTy(T->getParamType(i)));
  if (T->isVarArg())
    ArgTypes.push_back(PrimitiveShadowPtrTy);
  Type *RetType = T->getReturnType();
  if (!RetType->isVoidTy())
    ArgTypes.push_back(PointerType::getUnqual(getShadowTy(RetType)));
  return TransformedFunction(
      T, FunctionType::get(T->getReturnType(), ArgTypes, T->isVarArg()),
      ArgumentIndexMapping);
}

// A memory intrinsic whose destination lies in a global skips checkPointer
// (a written destination needs no symbolizing), but its length is bounded
// by the global all the same: __early_make_pgtable memsets
// early_dynamic_pgts[i] for ptrs_per_p4d * 8 bytes, a symbolized global's
// value, and wrote gigabytes of shadow past the 256 KB array.
void UCSanFunction::checkGlobalDest(Value *Dest, Value *Length,
                                    IRBuilder<> &IRB) {
  auto *GV = dyn_cast<GlobalVariable>(
      getUnderlyingObject(Dest->stripPointerCasts()));
  // (an unsized extern array has no fixed bounds: checkPointer translates it)
  if (!GV || UC.isUnsizedExternArray(GV))
    return;
  // the fixed bounds checkPointer traces for a global
  auto &DL = F->getParent()->getDataLayout();
  Type *GTy = GV->getValueType();
  if (GV->hasInitializer())
    GTy = GV->getInitializer()->getType();
  if (!GTy->isSized() || !(GTy->isArrayTy() || GTy->isStructTy()))
    return;
  uint64_t TypeSize = DL.getTypeStoreSize(GTy);
  if (auto *CI = dyn_cast<ConstantInt>(Length))
    if (Dest->stripPointerCasts() == GV && CI->getZExtValue() <= TypeSize)
      return;
  Value *GlobalAddr = IRB.CreatePtrToInt(GV, UC.Int64Ty);
  UC.markNosanitize(GlobalAddr);
  Value *Bounds = IRB.CreateCall(UC.UCTraceGlobalFn,
      {GlobalAddr, ConstantInt::get(UC.Int64Ty, TypeSize)});
  UC.markNosanitize(Bounds);
  Value *Addr = IRB.CreatePointerCast(Dest, UC.VoidPtrTy);
  if (Addr != Dest)
    UC.markNosanitize(Addr);
  Value *CI = IRB.CreateCall(UC.UCCheckGlobalBoundsFn, {Addr, Bounds, Length});
  UC.markNosanitize(CI);
}

bool UCSanFunction::reusableCheck(Instruction *Checked, Instruction *Pos) {
  if (Checked->getParent() != Pos->getParent())
    return false;
  // the runtime's helpers that never check a pointer with an alignment, so
  // never move an object (ucsan_resign_shadow changes a pointer's state,
  // and ucsan_check_pointer is the one that moves)
  static const StringSet<> Inert = {
      "ucsan_load_pointer_shadow", "ucsan_store_pointer_shadow",
      "ucsan_store_rmw_shadow",
      "ucsan_set_label",           "ucsan_check_ubi",
      "ucsan_combine_label",       "ucsan_trace_alloca",
      "ucsan_trace_global",        "ucsan_check_global_bounds",
      "ucsan_check_copy_bounds",   "ucsan_trace_warn",
      "__taint_trace_bb"};
  for (Instruction *I = Checked->getNextNode(); I; I = I->getNextNode()) {
    if (I == Pos)
      return true;
    auto *CB = dyn_cast<CallBase>(I);
    if (!CB || isa<IntrinsicInst>(CB))
      continue;
    Function *Callee = CB->getCalledFunction();
    if (!Callee || !Inert.contains(Callee->getName()))
      return false;
  }
  return false;  // Pos is not after it
}

Value *UCSanFunction::checkPointer(Value *Ptr, Value *Size, bool dereference,
                                    IRBuilder<> &IRB, uint32_t TypeID,
                                    MaybeAlign Alignment) {
  Type *Ty = Ptr->getType();
  Value *SPtr = Ptr->stripPointerCasts();
  bool cacheable = isa<Constant>(Size);
  assert(dereference && "Must dereference pointer when calling this function");

  if (cacheable) {
    // cache is only possible if size is a constant
    auto itr = CheckedPtrMap.find(Ptr);
    // A check's result is a real address, which ucsan_check_pointer may move
    // the object away from at a later check (to place it at the alignment an
    // access needs, see align_object in ucsan.cpp), through any pointer to
    // it, or in a callee.  So it is reused only in its own block with no
    // check or call in between.  (It used to be reused wherever it dominated
    // the use, hoisted if it did not: with a check between them that moved
    // the object, a store went to the old buffer and reads were stale.)
    if (itr != CheckedPtrMap.end() &&
        !reusableCheck(itr->second, &*IRB.GetInsertPoint()))
      itr = CheckedPtrMap.end();
    if (itr != CheckedPtrMap.end()) {
      // finding related instructions created by checkPointer
      // worst case, cast(ptr) -> check_ptr -> cast(result)
      Instruction *I1 = itr->second, *I2 = nullptr, *I3 = nullptr;
      CallBase *CB = nullptr;
      if (isa<CastInst>(I1)) {
        // I1 = bitcast(result), I2 = call, I3 = bitcast(Ptr) if exists
        I2 = dyn_cast<Instruction>(I1->getOperand(0));
        CB = dyn_cast<CallBase>(I2);
        auto *AddrOp = dyn_cast<Instruction>(CB->getArgOperand(0));
        // Only track the input cast if it was created by us, not Ptr itself
        if (AddrOp && isa<CastInst>(AddrOp) && AddrOp != Ptr)
          I3 = AddrOp;
      } else {
        CB = dyn_cast<CallBase>(I1);
        // No output cast; check if there's an input cast we created
        auto *AddrOp = dyn_cast<Instruction>(CB->getArgOperand(0));
        if (AddrOp && isa<CastInst>(AddrOp) && AddrOp != Ptr)
          I2 = AddrOp;
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
      // and the alignment: the check stands for this access too
      auto *OldAlign = cast<ConstantInt>(CB->getArgOperand(5));
      if (Alignment.valueOrOne().value() > OldAlign->getZExtValue())
        CB->setArgOperand(5, ConstantInt::get(UC.Int32Ty,
                                              Alignment.valueOrOne().value()));

      // cached check pointer must dominate the new use
      auto *TBB = IRB.GetInsertBlock();
      auto *SBB = itr->second->getParent();
      if (DT.dominates(SBB, TBB)) {
        // The check is already in a dominating block, no need to move it.
        // (always, now: it is in the same block, see reusableCheck, and the
        // move below would take it across code that can move the object)
        return itr->second;
      }

      // not dominating, move the checks to a dominating basic block
      Instruction *Pos = nullptr;
      if (isa<GlobalVariable>(Ptr) || isa<Argument>(Ptr) || isa<ConstantExpr>(Ptr)) {
        Pos = F->getEntryBlock().getTerminator();
      } else if (Instruction *I = dyn_cast<Instruction>(Ptr)) {
        // Find a block that dominates both the cached check and the new use
        auto *NCD = DT.findNearestCommonDominator(SBB, TBB);
        if (I->getParent() == NCD) {
          // Ptr is in the common dominator, place after Ptr
          Pos = I->getNextNode();
          while (isa<PHINode>(Pos) || isa<AllocaInst>(Pos)) {
            Pos = Pos->getNextNode();
          }
          // handle load shadow - skip the shadow if it exists
          if (CB->getArgOperand(1) == Pos) {
            Pos = Pos->getNextNode();
          }
        } else {
          // Ptr's block dominates NCD, place at start of NCD
          Pos = &*NCD->getFirstInsertionPt();
        }
      } else {
        errs() << "Unexpected pointer type for checkPointer: " << *Ptr << "\n"
              << "\t" << *SPtr << "\n";
      }
      if (Pos) {
        I1->moveBefore(Pos);
        if (I2) I2->moveBefore(I1);
        if (I3) I3->moveBefore(I2);
        // For a global, the check's label is a ucsan_trace_global call
        // emitted right before it (see GlobalBoundsShadow below); it has to
        // move along, or the moved check uses it before its definition.  Its
        // arguments are constants, so it can go anywhere.
        Instruction *First = I3 ? I3 : (I2 ? I2 : I1);
        if (auto *Label = dyn_cast<CallInst>(CB->getArgOperand(1))) {
          if (Label->getCalledFunction() ==
                  UC.UCTraceGlobalFn.getCallee() &&
              llvm::all_of(Label->args(),
                           [](Value *A) { return isa<Constant>(A); }) &&
              !DT.dominates(Label, First))
            Label->moveBefore(First);
        }
        return itr->second;
      } else {
        cacheable = false; // do not cache if we need to move the instruction
        // fall through to insert the check pointer
      }
    }
  }

  // A stack object indexed by a variable is checked against its bounds (the
  // OP_ALLOCA label ucsan_trace_alloca gives it): SymSan's own check comes
  // after this access's UCSan shadow store, and a wild index from the seed
  // (sata_pmp_error_handler's link_tries[link->pmp]) made that store fault
  // first wherever the stack happened to sit -- exit status 1, not an OOB.
  bool VariableStackIndex = false;
  if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(SPtr)) {
    // If this is a GEP, we need to check the base pointer.
    SPtr = GEP->getPointerOperand();
    VariableStackIndex = !GEP->hasAllConstantIndices();
  }

  GlobalVariable *GV =
      dyn_cast<GlobalVariable>(getUnderlyingObject(Ptr->stripPointerCasts()));
  Value *GlobalBoundsShadow = nullptr;
  if (GV) {
    // underlying obj is a global variable, do two things:
    // 1) if size is a constant and smaller than the global obj size, and
    // 2) we're not dereferencing the pointe, then we can skip the check
    auto &DL = F->getParent()->getDataLayout();
    Type *GTy = GV->getValueType();
    if (GV->hasInitializer()) {
      GTy = GV->getInitializer()->getType();
    }
    uint64_t TypeSize = DL.getTypeStoreSize(GTy);
    bool HasFixedBounds =
        GTy->isSized() && (GTy->isArrayTy() || GTy->isStructTy());

    // An array declared without a size (`extern T x[]`, defined in another
    // file) is an under-constrained object: a pointer label for it, and
    // check_pointer gives it an object that grows with use (see
    // ucsan_trace_unsized_global).  Its weak definition has no bytes.
    if (UC.isUnsizedExternArray(GV)) {
      Value *GlobalAddr = IRB.CreatePtrToInt(GV, UC.Int64Ty);
      UC.markNosanitize(GlobalAddr);
      GlobalBoundsShadow =
          IRB.CreateCall(UC.UCTraceUnsizedGlobalFn, {GlobalAddr});
      UC.markNosanitize(GlobalBoundsShadow);
      HasFixedBounds = false;
    }

    // trace globals with fixed bounds to allow bounds checks
    if (HasFixedBounds) {
      Value *GlobalAddr = IRB.CreatePtrToInt(GV, UC.Int64Ty);
      UC.markNosanitize(GlobalAddr);
      Value *GlobalSize = ConstantInt::get(UC.Int64Ty, TypeSize);
      GlobalBoundsShadow =
          IRB.CreateCall(UC.UCTraceGlobalFn, {GlobalAddr, GlobalSize});
      UC.markNosanitize(GlobalBoundsShadow);
    }

    if (ConstantInt *CI = dyn_cast<ConstantInt>(Size)) {
      if (CI->getZExtValue() < TypeSize && !dereference) {
        return Ptr; // size is smaller than the pointed type, no check needed
      }
    }
  }

  // (and so is one written for a variable length: memzero_explicit(desc,
  // sizeof(*desc) + crypto_shash_descsize(tfm)) on a stack shash_desc, the
  // length from the seed, set the shadow of whatever followed it first --
  // jent_hash_time)
  if (!isa<AllocaInst>(SPtr) || VariableStackIndex || !isa<ConstantInt>(Size)) {
    Value *Addr = Ptr;
    if (Ty != UC.VoidPtrTy) {
      Addr = IRB.CreateBitCast(Ptr, UC.VoidPtrTy);
      UC.markNosanitize(Addr);
    }

    // Get shadow for the pointer from TLS (for arguments) or shadow memory
    Value* Shadow = GlobalBoundsShadow ? GlobalBoundsShadow : getShadow(Ptr);

    Value *ExtSize = IRB.CreateZExtOrTrunc(Size, UC.Int64Ty);
    if (ExtSize != Size) {
      UC.markNosanitize(ExtSize);
    }
    ConstantInt *Deref = ConstantInt::get(UC.Int1Ty, dereference);
    ConstantInt *TypeIDVal = ConstantInt::get(UC.Int32Ty, TypeID);
    ConstantInt *AlignVal = ConstantInt::get(UC.Int32Ty,
                                             Alignment.valueOrOne().value());

    CallInst *NewAddr = IRB.CreateCall(
      UC.UCCheckPointerFn, {Addr, Shadow, ExtSize, Deref, TypeIDVal, AlignVal});
    // UC.markNosanitize(NewAddr); // don't mark as nonsanitize

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

static Value *stripPointerCastsForSummary(Value *V) {
  while (true) {
    if (auto *BC = dyn_cast<BitCastOperator>(V)) {
      V = BC->getOperand(0);
      continue;
    }
    if (auto *ASC = dyn_cast<AddrSpaceCastOperator>(V)) {
      V = ASC->getOperand(0);
      continue;
    }
    if (auto *CI = dyn_cast<CastInst>(V)) {
      V = CI->getOperand(0);
      continue;
    }
    return V;
  }
}

static bool getArgumentBaseAndConstantOffset(Value *Ptr, const DataLayout &DL,
                                             Argument *&Arg,
                                             int64_t &Offset) {
  Ptr = stripPointerCastsForSummary(Ptr);
  APInt APOffset(DL.getIndexSizeInBits(Ptr->getType()->getPointerAddressSpace()), 0);

  if (auto *GEP = dyn_cast<GEPOperator>(Ptr)) {
    if (!GEP->accumulateConstantOffset(DL, APOffset))
      return false;
    Ptr = stripPointerCastsForSummary(GEP->getPointerOperand());
  }

  Arg = dyn_cast<Argument>(Ptr);
  if (!Arg)
    return false;

  Offset = APOffset.getSExtValue();
  return true;
}

static Value *getLoadedPointerBase(Value *Ptr, const DataLayout &DL,
                                   int64_t &AccessOffset) {
  Ptr = stripPointerCastsForSummary(Ptr);
  AccessOffset = 0;

  if (auto *GEP = dyn_cast<GEPOperator>(Ptr)) {
    APInt APOffset(DL.getIndexSizeInBits(Ptr->getType()->getPointerAddressSpace()), 0);
    if (!GEP->accumulateConstantOffset(DL, APOffset))
      return nullptr;
    AccessOffset = APOffset.getSExtValue();
    Ptr = stripPointerCastsForSummary(GEP->getPointerOperand());
  }

  return Ptr;
}

void UCSanFunction::recordPointerLoadSummary(LoadInst &LI) {
  if (!LI.getType()->isPointerTy())
    return;

  Argument *Arg = nullptr;
  int64_t FieldOffset = 0;
  if (!getArgumentBaseAndConstantOffset(LI.getPointerOperand(),
                                        F->getParent()->getDataLayout(), Arg,
                                        FieldOffset))
    return;

  LoadedPointerSummaries[&LI] = {Arg->getArgNo(), FieldOffset};
}

void UCSanFunction::recordMemoryAccessSummary(Value *Ptr, uint64_t AccessSize,
                                              bool IsWrite, uint32_t TypeID,
                                              Instruction *I) {
  int64_t AccessOffset = 0;
  Value *Base = getLoadedPointerBase(Ptr, F->getParent()->getDataLayout(),
                                     AccessOffset);
  if (!Base)
    return;

  auto It = LoadedPointerSummaries.find(Base);
  if (It == LoadedPointerSummaries.end())
    return;

  unsigned Line = 0;
  unsigned Col = 0;
  if (const DebugLoc &DL = I->getDebugLoc()) {
    Line = DL.getLine();
    Col = DL.getCol();
  }

  MemoryAccessSummary Summary{
      It->second.ArgNo,
      It->second.FieldOffset + AccessOffset,
      AccessSize,
      IsWrite,
      TypeID,
      Line,
      Col,
  };

  for (const MemoryAccessSummary &Existing : MemoryAccessSummaries) {
    if (Existing.ArgNo == Summary.ArgNo &&
        Existing.FieldOffset == Summary.FieldOffset &&
        Existing.AccessSize == Summary.AccessSize &&
        Existing.IsWrite == Summary.IsWrite &&
        Existing.TypeID == Summary.TypeID &&
        Existing.Line == Summary.Line &&
        Existing.Col == Summary.Col)
      return;
  }

  MemoryAccessSummaries.push_back(Summary);
}

void UCSanFunction::emitMemoryAccessSummaries() {
  if (MemoryAccessSummaries.empty())
    return;

  LLVMContext &C = F->getContext();
  SmallVector<Metadata *, 8> Summaries;
  if (MDNode *Existing = symsan::ucsan::getMemoryAccessSummaries(*F)) {
    for (const MDOperand &Op : Existing->operands())
      Summaries.push_back(Op.get());
  }

  for (const MemoryAccessSummary &Summary : MemoryAccessSummaries) {
    Summaries.push_back(symsan::ucsan::createMemoryAccessSummaryMD(C, Summary));
  }

  symsan::ucsan::setMemoryAccessSummaries(*F, MDNode::get(C, Summaries));
}

void UCSanVisitor::visitLoadInst(LoadInst &LI) {
  auto &DL = LI.getModule()->getDataLayout();
  Type *Ty = LI.getType();
  uint64_t StoreSize = DL.getTypeStoreSize(Ty);
  if (StoreSize == 0) return;

  Value *Ptr = LI.getPointerOperand();
  UF.recordPointerLoadSummary(LI);
  UF.recordMemoryAccessSummary(Ptr, StoreSize, false,
                               UF.UC.getOrCreateTypeID(Ty), &LI);
  Value *Base = Ptr->stripPointerCasts();

  // Check if loading from a constant global variable
  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Base)) {
    if (GV->isConstant()) {
      UF.setShadow(&LI, UF.UC.getZeroShadow(Ty));
      return;
    }
  }

  // For pointer loads, check if derived from a non-null initialized global
  if (Ty->isPointerTy()) {
    Constant *Init = nullptr;
    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Base)) {
      // Direct load from GV
      if (GV->hasInitializer()) {
        Init = GV->getInitializer();
      }
    } else if (auto *GEP = dyn_cast<GEPOperator>(Base)) {
      // Load from GEP of GV - try to extract the initialized value
      GlobalVariable *GV = dyn_cast<GlobalVariable>(
          GEP->getPointerOperand()->stripPointerCasts());
      if (GV && GV->hasInitializer() && GEP->hasAllConstantIndices()) {
        SmallVector<unsigned, 4> Indices;
        for (auto It = GEP->idx_begin(); It != GEP->idx_end(); ++It) {
          if (auto *CI = dyn_cast<ConstantInt>(*It)) {
            Indices.push_back(CI->getZExtValue());
          }
        }
        // Skip the first index (pointer offset), extract from aggregate
        if (Indices.size() > 1) {
          Constant *Agg = GV->getInitializer();
          for (unsigned I = 1; I < Indices.size() && Agg; ++I) {
            if (auto *AT = dyn_cast<ArrayType>(Agg->getType())) {
              Agg = Agg->getAggregateElement(Indices[I]);
            } else if (auto *ST = dyn_cast<StructType>(Agg->getType())) {
              Agg = Agg->getAggregateElement(Indices[I]);
            } else {
              Agg = nullptr;
            }
          }
          Init = Agg;
        }
      }
    }
    // If the initialized value is a non-null pointer, don't symbolize
    if (Init && !Init->isNullValue()) {
      UF.setShadow(&LI, UF.UC.getZeroShadow(Ty));
      return;
    }
  }
  ConstantInt *Size = ConstantInt::get(UF.UC.Int64Ty, StoreSize);
  // Opaque pointers make Ty uninformative when the loaded value is itself a
  // pointer (e.g. a linked-list `next` field) - every such load would
  // otherwise collapse onto the same generic "ptr" type_id. Recover the real
  // pointee by looking at how the loaded pointer gets used afterward (e.g. a
  // GEP indexing into it), so the lazily-created target object can be sized
  // correctly up front instead of growing it one field access at a time.
  Type *PointeeTy = Ty->isPointerTy() ? findPointeeTypeFromUses(&LI) : nullptr;
  uint32_t TypeID = PointeeTy ? UF.UC.getOrCreatePointerTypeID(PointeeTy)
                              : UF.UC.getOrCreateTypeID(Ty);

  // Check and replace pointer
  IRBuilder<> IRB(&LI);
  Ptr = UF.checkPointer(Ptr, Size, true, IRB, TypeID, LI.getAlign());
  LI.setOperand(0, Ptr);

  // a value is uninitialized when a byte its uses read is, and the bytes
  // of a bitfield's access unit outside its fields are not read (see
  // Bitfield.h)
  Value *Shadow = UF.loadShadow(Ptr, StoreSize, LI.getAlign(), Ty, &LI,
                                symsan::unreadBytes(LI));
  if (!UF.UC.isZeroShadow(Shadow))
    UF.NonZeroChecks.push_back(Shadow);

  UF.setShadow(&LI, Shadow);

  // Mark as checked for TaintPass
  LI.setMetadata("ucsan.checked",
                 MDNode::get(*UF.UC.Ctx, std::nullopt));
}

void UCSanVisitor::visitStoreInst(StoreInst &SI) {
  if (SI.getMetadata("nosanitize")) return;

  auto &DL = SI.getModule()->getDataLayout();
  uint64_t StoreSize = DL.getTypeStoreSize(SI.getValueOperand()->getType());
  if (StoreSize == 0) return;

  Value *Ptr = SI.getPointerOperand();
  ConstantInt *Size = ConstantInt::get(UF.UC.Int64Ty, StoreSize);

  Value *Val = SI.getValueOperand();
  Type *Ty = Val->getType();
  uint32_t TypeID = UF.UC.getOrCreateTypeID(Ty);

  // Check and replace pointer
  IRBuilder<> IRB(&SI);
  Ptr = UF.checkPointer(Ptr, Size, true, IRB, TypeID, SI.getAlign());
  SI.setOperand(SI.getPointerOperandIndex(), Ptr);
  Value *Shadow = UF.getShadow(Val);

  // A bitfield assignment writes only the bytes its masks touch, and those
  // are initialized whatever the load was (see Bitfield.h).  The new bits'
  // shadow is what the touched bytes take when the load was uninitialized;
  // the runtime picks.
  symsan::RMWStore RMW;
  auto *AI = dyn_cast<AllocaInst>(Ptr);
  if (!UF.UC.isZeroShadow(Shadow) &&
      !(AI && UF.AllocaShadowMap.count(AI)) &&
      symsan::matchRMWStore(
          SI,
          [](Instruction &I) { return I.getMetadata("nosanitize") != nullptr; },
          RMW)) {
    Value *NewShadow = UF.UC.ZeroPrimitiveShadow;
    for (auto [BO, Idx] : RMW.Chain) {
      if (BO->getOpcode() != Instruction::Or)
        continue;
      Value *Bits = UF.getShadow(BO->getOperand(1 - Idx));
      if (UF.UC.isZeroShadow(Bits))
        continue;
      if (UF.UC.isZeroShadow(NewShadow)) {
        NewShadow = Bits;
        continue;
      }
      CallInst *C = IRB.CreateCall(UF.UC.UCCombineLabelFn, {NewShadow, Bits});
      UF.UC.markNosanitize(C);
      NewShadow = C;
    }
    CallInst *CI = IRB.CreateCall(UF.UC.UCStoreRMWShadowFn,
        {Shadow, UF.getShadow(RMW.Load), NewShadow,
         UF.UC.getShadowAddress(Ptr, IRB), Size,
         ConstantInt::get(UF.UC.Int64Ty, RMW.Touched)});
    UF.UC.markNosanitize(CI);
  } else {
    UF.storeShadow(Ptr, StoreSize, SI.getAlign(), Shadow, Ty, &SI);
  }

  // Mark as checked
  SI.setMetadata("ucsan.checked",
                 MDNode::get(*UF.UC.Ctx, std::nullopt));
}

void UCSanVisitor::visitMemCpyInst(MemCpyInst &I) {
  IRBuilder<> IRB(&I);
  Value *Length = IRB.CreateZExtOrTrunc(I.getLength(), UF.UC.Int64Ty);
  if (Length != I.getLength()) {
    UF.UC.markNosanitize(Length);
  }

  // Check source and destination pointers
  Value *src = UF.checkPointer(I.getRawSource(), Length, true, IRB, 0,
                               I.getSourceAlign());
  // check the destination pointer, if it's a global variable,
  // no need to call check pointer to symbolize, as it's the dest.
  Value *dest = I.getRawDest();
  if (!isa<GlobalVariable>(getUnderlyingObject(dest->stripPointerCasts()))) {
    dest = UF.checkPointer(dest, Length, true, IRB, 0, I.getDestAlign());
    // the destination's check can move the object the source points into
    // (when it is the same one, see align_object in ucsan.cpp): the source
    // is checked again, with no alignment, which never moves anything
    if (I.getDestAlign().valueOrOne() > 1)
      src = UF.checkPointer(I.getRawSource(), Length, true, IRB, 0);
  } else {
    UF.checkGlobalDest(dest, Length, IRB);
  }

  I.setSource(src);
  I.setDest(dest);

  // source bytes labeled on demand get their labels before their shadow is
  // copied (a copied marker would name the source object at dest)
  CallInst *Mat = IRB.CreateCall(UF.UC.UCMaterializeRangeFn,
      {IRB.CreatePointerCast(src, UF.UC.VoidPtrTy), Length});
  UF.UC.markNosanitize(Mat);

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

  I.setMetadata("ucsan.checked", MDNode::get(*UF.UC.Ctx, std::nullopt));
}

void UCSanVisitor::visitMemSetInst(MemSetInst &I) {
  IRBuilder<> IRB(&I);
  Value *Length = IRB.CreateZExtOrTrunc(I.getLength(), UF.UC.Int64Ty);
  if (Length != I.getLength()) {
    UF.UC.markNosanitize(Length);
  }

  // check the destination pointer, if it's a global variable,
  // no need to call check pointer. stack still needs to be checked,
  // not for symbolizing, but for bounds check.
  Value *dest = I.getRawDest();
  if (!isa<GlobalVariable>(getUnderlyingObject(dest->stripPointerCasts()))) {
    // Check destination pointer
    dest = UF.checkPointer(dest, Length, true, IRB, 0, I.getDestAlign());
    I.setDest(dest);
  } else {
    UF.checkGlobalDest(dest, Length, IRB);
  }

  // update shadow
  Value *ValShadow = UF.getShadow(I.getValue());
  Value *CI = IRB.CreateCall(UF.UC.UCSetLabelFn, {ValShadow, dest, Length});
  UF.UC.markNosanitize(CI);

  I.setMetadata("ucsan.checked", MDNode::get(*UF.UC.Ctx, std::nullopt));
}

void UCSanVisitor::visitMemMoveInst(MemMoveInst &I) {
  IRBuilder<> IRB(&I);
  Value *Length = IRB.CreateZExtOrTrunc(I.getLength(), UF.UC.Int64Ty);
  if (Length != I.getLength()) {
    UF.UC.markNosanitize(Length);
  }

  // Check source and destination pointers
  Value *src = UF.checkPointer(I.getRawSource(), Length, true, IRB, 0,
                               I.getSourceAlign());
  // check the destination pointer, if it's a global variable,
  // no need to call check pointer to symbolize, as it's the dest.
  Value *dest = I.getRawDest();
  if (!isa<GlobalVariable>(getUnderlyingObject(dest->stripPointerCasts()))) {
    dest = UF.checkPointer(dest, Length, true, IRB, 0, I.getDestAlign());
    // the destination's check can move the object the source points into
    // (when it is the same one, see align_object in ucsan.cpp): the source
    // is checked again, with no alignment, which never moves anything
    if (I.getDestAlign().valueOrOne() > 1)
      src = UF.checkPointer(I.getRawSource(), Length, true, IRB, 0);
  } else {
    UF.checkGlobalDest(dest, Length, IRB);
  }

  I.setDest(dest);
  I.setSource(src);

  // on-demand labels first, as for memcpy
  CallInst *Mat = IRB.CreateCall(UF.UC.UCMaterializeRangeFn,
      {IRB.CreatePointerCast(src, UF.UC.VoidPtrTy), Length});
  UF.UC.markNosanitize(Mat);

  // memmove shadow
  Value *DestShadowAddr = UF.UC.getShadowAddress(dest, IRB);
  Value *SrcShadowAddr = UF.UC.getShadowAddress(src, IRB);
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

  I.setMetadata("ucsan.checked", MDNode::get(*UF.UC.Ctx, std::nullopt));
}

// va_copy(dst, src) reads and writes a whole va_list through its operands,
// and src is often a parameter -- a function taking a va_list, such as
// kvasprintf, gets a pointer to the caller's __va_list_tag -- so under UC a
// pseudo-pointer that faulted (0x10 off a pseudo-NULL).  Both are checked for
// the va_list's size, as memmove's operands are, and its shadow is copied.
// Only where that size is known: the SysV x86-64 __va_list_tag, 24 bytes.
void UCSanVisitor::visitVACopyInst(VACopyInst &I) {
  Triple TT(I.getModule()->getTargetTriple());
  if (TT.getArch() != Triple::x86_64 || TT.isOSWindows())
    return;
  IRBuilder<> IRB(&I);
  Value *Length = ConstantInt::get(UF.UC.Int64Ty, 24);
  Value *Src = UF.checkPointer(I.getSrc(), Length, true, IRB);
  Value *Dest = UF.checkPointer(I.getDest(), Length, true, IRB);
  I.setArgOperand(0, Dest);
  I.setArgOperand(1, Src);

  // on-demand labels first, as for memcpy
  CallInst *Mat = IRB.CreateCall(UF.UC.UCMaterializeRangeFn,
      {IRB.CreatePointerCast(Src, UF.UC.VoidPtrTy), Length});
  UF.UC.markNosanitize(Mat);

  Value *DestShadowAddr = UF.UC.getShadowAddress(Dest, IRB);
  Value *SrcShadowAddr = UF.UC.getShadowAddress(Src, IRB);
  Value *ShadowLength = ConstantInt::get(UF.UC.Int64Ty,
                                         24 * UCSan::ShadowWidthBytes);
  CallInst *MTI = IRB.CreateMemMove(DestShadowAddr,
                                    MaybeAlign(UF.UC.ShadowWidthBytes),
                                    SrcShadowAddr,
                                    MaybeAlign(UF.UC.ShadowWidthBytes),
                                    ShadowLength);
  UF.UC.markNosanitize(MTI);

  I.setMetadata("ucsan.checked", MDNode::get(*UF.UC.Ctx, std::nullopt));
}

void UCSanVisitor::visitGetElementPtrInst(GetElementPtrInst &GEPI) {
  // use the type of the pointer operand to estimate object size
  Value *Ptr = GEPI.getPointerOperand();
  // A base check only stands for the GEPs it dominates.  It is what creates
  // a lazily created object at the base, so a GEP on a path that skips it
  // created the object at the field it reaches instead: offset 0 at a field,
  // and decode_operand's switch arms other than the first put
  // ctxt->memop off its 16-byte alignment (a movaps of it faulted).
  auto &BaseChecks = UF.GEPBaseChecks[Ptr];
  bool Dominated = llvm::any_of(BaseChecks, [&](Instruction *C) {
    return UF.DT.dominates(C, &GEPI);
  });
  if (!Dominated && !isa<AllocaInst>(Ptr->stripPointerCasts())) {
    IRBuilder<> IRB(&GEPI);
    const DataLayout &DL = getDataLayout();
    Type *SrcElemTy = GEPI.getSourceElementType();
    Value *Size = ConstantInt::get(UF.UC.Int64Ty,
        DL.getTypeAllocSize(SrcElemTy));
    uint32_t TypeID = UF.UC.getOrCreateTypeID(SrcElemTy);
    Value *Addr = IRB.CreateBitCast(Ptr, UF.UC.VoidPtrTy);
    if (Addr != Ptr) UF.UC.markNosanitize(Addr);
    Value *Checked = IRB.CreateCall(UF.UC.UCCheckPointerFn,
      { Addr, UF.getShadow(Ptr), Size, ConstantInt::get(UF.UC.Int1Ty, false),
        ConstantInt::get(UF.UC.Int32Ty, TypeID),
        ConstantInt::get(UF.UC.Int32Ty, 1) });
    UF.UC.markNosanitize(Checked);
    BaseChecks.push_back(cast<Instruction>(Checked));
  }
  // Propagate shadow through GEP
  Value *Shadow = UF.getShadow(Ptr);
  UF.setShadow(&GEPI, Shadow);
}

namespace {

// Canonical name of an x86-64 general purpose register ("ax", "di", "r8",
// "sp", ...) for an inline asm constraint code ("a", "{rdi}", "{r8d}") or an
// AT&T register operand ("%rdi", "%r8d"); empty if it names none.
std::string asmRegName(StringRef S) {
  S = S.trim();
  if (S.size() == 1) {
    switch (S[0]) {
    case 'a': return "ax";
    case 'b': return "bx";
    case 'c': return "cx";
    case 'd': return "dx";
    case 'S': return "si";
    case 'D': return "di";
    default: return "";
    }
  }
  if (!S.consume_front("%")) {
    if (!S.consume_front("{") || !S.consume_back("}"))
      return "";
  }
  std::string R = S.lower();
  if (R.size() >= 2 && R[0] == 'r' && isdigit(R[1])) {
    // r8..r15, with an optional d/w/b width suffix
    while (!isdigit(R.back()))
      R.pop_back();
    return R;
  }
  static const char *Bases[] = {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"};
  auto isBase = [](StringRef B) {
    return llvm::is_contained(Bases, B);
  };
  if (isBase(R))
    return R;
  if (R.size() == 3 && (R[0] == 'e' || R[0] == 'r') && isBase(R.substr(1)))
    return R.substr(1);
  if (R.size() == 2 && R[1] == 'l' && isBase(std::string(1, R[0]) + "x"))
    return std::string(1, R[0]) + "x";                    // al, bl, cl, dl
  if (R.size() == 3 && R[2] == 'l' && isBase(R.substr(0, 2)))
    return R.substr(0, 2);                                // sil, dil, spl, bpl
  return "";
}

// Operand number of an asm operand reference `$N`, `${N}` or `${N:m}`, with
// the modifier returned in Mod; -1 if T is not one.
int asmOperandRef(StringRef T, StringRef *Mod = nullptr) {
  T = T.trim();
  if (!T.consume_front("$"))
    return -1;
  StringRef M;
  if (T.consume_front("{")) {
    if (!T.consume_back("}"))
      return -1;
    std::tie(T, M) = T.split(':');
  }
  unsigned N;
  if (T.getAsInteger(10, N))
    return -1;
  if (Mod)
    *Mod = M;
  return N;
}

struct AsmInsn {
  std::string Mnemonic;
  SmallVector<std::string, 3> Operands;
};

// The instructions an asm actually executes, in order: the template is split
// on newlines and `;`, labels, comments and directives are dropped, and
// everything between .pushsection/.section and .popsection/.previous is
// skipped -- that is where the kernel's ALTERNATIVE keeps its replacement
// code and tables, and where exception tables go.  A lone prefix (`rep;`,
// `lock;`) is joined to the instruction it prefixes.
SmallVector<AsmInsn, 4> asmExecutedInsns(StringRef Asm) {
  std::string Text = Asm.str();
  // C comments, e.g. "/* output condition code e*/"
  for (size_t P; (P = Text.find("/*")) != std::string::npos;) {
    size_t E = Text.find("*/", P);
    Text.erase(P, E == std::string::npos ? std::string::npos : E + 2 - P);
  }
  SmallVector<AsmInsn, 4> Insns;
  SmallVector<StringRef, 16> Lines;
  StringRef(Text).split(Lines, '\n');
  int Depth = 0;
  std::string Prefix;
  for (StringRef Line : Lines) {
    SmallVector<StringRef, 4> Stmts;
    Line.split(Stmts, ';');
    for (StringRef S : Stmts) {
      S = S.split('#').first.trim();
      if (S.starts_with(".pushsection") || S.starts_with(".section")) {
        ++Depth;
        continue;
      }
      if (S.starts_with(".popsection") || S.starts_with(".previous")) {
        if (Depth)
          --Depth;
        continue;
      }
      if (Depth)
        continue;
      // labels: "661:", "998:", "name:"
      while (true) {
        size_t Colon = S.find(':');
        if (Colon == StringRef::npos)
          break;
        StringRef L = S.substr(0, Colon);
        if (L.empty() || L.find_first_of(" \t$%(,") != StringRef::npos)
          break;
        S = S.substr(Colon + 1).trim();
      }
      if (S.empty() || S.starts_with("."))
        continue;
      std::string Stmt = Prefix.empty() ? S.str() : Prefix + " " + S.str();
      Prefix.clear();
      std::replace(Stmt.begin(), Stmt.end(), '\t', ' ');
      StringRef Rest(Stmt);
      StringRef Mn;
      std::tie(Mn, Rest) = Rest.split(' ');
      std::string Mnemonic = Mn.str();
      if (Mn == "rep" || Mn == "repz" || Mn == "repnz" || Mn == "repe" ||
          Mn == "repne" || Mn == "lock") {
        if (Rest.trim().empty()) {
          Prefix = Mn.str();
          continue;
        }
        StringRef Next;
        std::tie(Next, Rest) = Rest.trim().split(' ');
        Mnemonic += " " + Next.str();
      }
      AsmInsn I;
      I.Mnemonic = Mnemonic;
      // Trim leading whitespace
      Rest = Rest.trim();
      // operands, split at top-level commas
      int Paren = 0;
      std::string Cur;
      for (char C : Rest) {
        if (C == '(') ++Paren;
        if (C == ')') --Paren;
        if (C == ',' && Paren == 0) {
          I.Operands.push_back(StringRef(Cur).trim().str());
          Cur.clear();
          continue;
        }
        Cur += C;
      }
      if (!StringRef(Cur).trim().empty())
        I.Operands.push_back(StringRef(Cur).trim().str());
      Insns.push_back(I);
    }
  }
  return Insns;
}

// V converted to Ty the way a register would carry it.
Value *castAsmValue(IRBuilder<> &IRB, const DataLayout &DL, Value *V, Type *Ty,
                    bool Signed = false) {
  Type *VT = V->getType();
  if (VT == Ty)
    return V;
  if (VT->isIntegerTy() && Ty->isIntegerTy())
    return IRB.CreateIntCast(V, Ty, Signed);
  if (VT->isPointerTy() && Ty->isIntegerTy())
    return IRB.CreateZExtOrTrunc(IRB.CreatePtrToInt(V, IRB.getInt64Ty()), Ty);
  if (VT->isIntegerTy() && Ty->isPointerTy())
    return IRB.CreateIntToPtr(
        IRB.CreateIntCast(V, IRB.getInt64Ty(), Signed), Ty);
  if (VT->isPointerTy() && Ty->isPointerTy())
    return IRB.CreatePointerCast(V, Ty);
  if (VT->isSized() && Ty->isSized() &&
      DL.getTypeSizeInBits(VT) == DL.getTypeSizeInBits(Ty) &&
      !VT->isAggregateType() && !Ty->isAggregateType())
    return IRB.CreateBitCast(V, Ty);
  return Constant::getNullValue(Ty);
}

// Access size, in bytes, of an instruction by its mnemonic suffix or its
// vector register operands; 0 if unknown.
uint64_t asmAccessSize(StringRef Mnemonic, ArrayRef<std::string> Operands) {
  for (auto &O : Operands)
    if (StringRef(O).starts_with("%xmm"))
      return 16;
  if (Mnemonic.size() > 1) {
    switch (Mnemonic.back()) {
    case 'b': return 1;
    case 'w': return 2;
    case 'l': return 4;
    case 'q': return 8;
    }
  }
  return 0;
}

// Alignment, in bytes, an instruction needs of its memory operand, or 1.  The
// aligned moves fault on an address not aligned to their vector width, VEX
// encoded or not; a legacy (non-VEX) SSE instruction with a 16-byte memory
// operand faults on one not 16-byte aligned, except the explicitly unaligned
// moves and those whose memory operand is narrower (scalar, half-vector,
// insert/extract, widening converts and loads).
uint64_t asmAccessAlign(StringRef Mnemonic, ArrayRef<std::string> Operands) {
  StringRef M = Mnemonic;
  bool Vex = M.consume_front("v");
  if (M == "movaps" || M == "movapd" || M == "movdqa" || M == "movntdqa" ||
      M == "movntdq" || M == "movntps" || M == "movntpd") {
    if (Vex)
      for (auto &O : Operands) {
        if (StringRef(O).starts_with("%ymm"))
          return 32;
        if (StringRef(O).starts_with("%zmm"))
          return 64;
      }
    return 16;
  }
  if (Vex)
    return 1;
  bool Xmm = false;
  for (auto &O : Operands)
    Xmm |= StringRef(O).starts_with("%xmm");
  if (!Xmm)
    return 1;
  if (M == "movups" || M == "movupd" || M == "movdqu" || M == "lddqu" ||
      M == "movq" || M == "movd" || M == "movlps" || M == "movhps" ||
      M == "movlpd" || M == "movhpd" || M == "movddup" || M == "insertps" ||
      M == "extractps" || M.ends_with("ss") || M.ends_with("sd") ||
      M.starts_with("pinsr") || M.starts_with("pextr") ||
      M.starts_with("pmovzx") || M.starts_with("pmovsx") ||
      M.starts_with("cvt") || M.starts_with("maskmov"))
    return 1;
  return 16;
}

const char *const AsmArgRegs[] = {"di", "si", "dx", "cx", "r8", "r9"};

// The operands of an inline asm call, indexed by operand number ($N in the
// template).  Register outputs are the asm's results; every other operand but
// a label is an argument, and a memory ("*m") one is a pointer to its
// elementtype.
struct AsmOp {
  const InlineAsm::ConstraintInfo *CI = nullptr;
  int Result = -1;            // register output: index of the result
  Value *V = nullptr;         // argument operands: the argument
  Type *ElemTy = nullptr;     // memory operands: type of the memory
  int TiedTo = -1;            // input tied to output operand TiedTo
  std::string Reg;            // fixed register, if the constraint names one
  std::string Code;
  bool isInput() const { return CI->Type == InlineAsm::isInput; }
  bool isMem() const { return CI->isIndirect && V && ElemTy; }
  bool isValue() const { return isInput() && !CI->isIndirect && V; }
};

struct AsmOperands {
  SmallVector<AsmOp, 8> Ops;
  unsigned NumResults = 0;
  bool AllClobbers = true;
  bool HasMemOutput = false;

  AsmOperands(CallBase &CB, const InlineAsm::ConstraintInfoVector &Constraints) {
    unsigned ArgIdx = 0;
    for (auto &CI : Constraints) {
      // clobbers don't have corresponding arguments
      if (CI.Type == InlineAsm::isClobber)
        continue;
      AllClobbers = false;
      AsmOp Op;
      Op.CI = &CI;
      Op.Code = CI.Codes.empty() ? "" : CI.Codes[0];
      // non-indirect outputs don't have a pointer argument
      if (CI.Type == InlineAsm::isOutput && !CI.isIndirect) {
        Op.Result = NumResults++;
      } else if (CI.Type != InlineAsm::isLabel &&
                 ArgIdx < CB.arg_size()) { // bounds check
        Op.V = CB.getArgOperand(ArgIdx);
        if (CI.isIndirect)
          Op.ElemTy = CB.getParamElementType(ArgIdx);
        ++ArgIdx;
      }
      if (CI.Type == InlineAsm::isOutput && CI.isIndirect)
        HasMemOutput = true;
      // an input tied to an output ("0") lives in that output's register
      unsigned Tied;
      if (Op.isInput() && !StringRef(Op.Code).getAsInteger(10, Tied) &&
          Tied < Ops.size()) {
        Op.TiedTo = Tied;
        Op.Reg = Ops[Tied].Reg;
      } else {
        Op.Reg = asmRegName(Op.Code);
      }
      Ops.push_back(Op);
    }
  }
};

// The data an asm puts in another section, by label: `mov $1f, %0` with `1:`
// in a .section/.pushsection block of data directives is the address of that
// data (the kernel's TRACE_RESUME, a packed {u16 line; char *file} record in
// .tracedata).  Run as is, that absolute address is a 32-bit relocation a PIE
// cannot link.  Here each such block becomes a private packed global holding
// the same bytes, and each label in it the address of its offset there.  A
// block with anything but integer or constant-operand data gives no labels,
// and neither does a label defined twice (where `1f` and `1b` could differ).
StringMap<Constant *> asmSectionLabels(StringRef Asm, ArrayRef<AsmOp> Ops,
                                       Module &M) {
  StringMap<Constant *> Labels;
  StringMap<unsigned> Defs;
  LLVMContext &Ctx = M.getContext();
  int Depth = 0;
  bool Bad = false, Writable = true;
  uint64_t Offset = 0;
  SmallVector<Constant *, 4> Elems;
  SmallVector<std::pair<std::string, uint64_t>, 2> BlockLabels;
  auto dataSize = [](StringRef D) -> unsigned {
    if (D == ".byte")
      return 1;
    if (D == ".word" || D == ".short" || D == ".value" || D == ".2byte")
      return 2;
    if (D == ".long" || D == ".int" || D == ".4byte")
      return 4;
    if (D == ".quad" || D == ".8byte")
      return 8;
    return 0;
  };
  // one item of a data directive: an integer, or a constant input operand
  auto item = [&](StringRef T, unsigned Size) -> Constant * {
    T = T.trim();
    Type *IntTy = IntegerType::get(Ctx, Size * 8);
    int64_t N;
    if (!T.getAsInteger(0, N))
      return isIntN(Size * 8, N) || isUIntN(Size * 8, N)
                 ? ConstantInt::get(IntTy, N)
                 : nullptr;
    StringRef Mod;
    int Ref = asmOperandRef(T, &Mod);
    if (Ref < 0 || Ref >= (int)Ops.size() || !(Mod.empty() || Mod == "c" ||
                                               Mod == "P"))
      return nullptr;
    const AsmOp &O = Ops[Ref];
    if (!O.isValue())
      return nullptr;
    if (auto *CI = dyn_cast<ConstantInt>(O.V)) {
      const APInt &V = CI->getValue();
      if (!V.isSignedIntN(Size * 8) && !V.isIntN(Size * 8))
        return nullptr;
      return ConstantInt::get(IntTy, V.trunc(Size * 8));
    }
    if (isa<Constant>(O.V) && O.V->getType()->isPointerTy() && Size == 8)
      return cast<Constant>(O.V);
    return nullptr;
  };
  auto closeBlock = [&]() {
    if (!Bad && !Elems.empty()) {
      SmallVector<Type *, 4> Tys;
      for (Constant *C : Elems)
        Tys.push_back(C->getType());
      auto *Ty = StructType::get(Ctx, Tys, /*isPacked=*/true);
      auto *GV = new GlobalVariable(M, Ty, !Writable,
                                    GlobalValue::PrivateLinkage,
                                    ConstantStruct::get(Ty, Elems),
                                    "ucsan.asm.section");
      GV->setAlignment(Align(1));
      for (auto &[Name, Off] : BlockLabels)
        Labels[Name] = Off ? ConstantExpr::getInBoundsGetElementPtr(
                                 Type::getInt8Ty(Ctx), GV,
                                 ConstantInt::get(Type::getInt64Ty(Ctx), Off))
                           : GV;
    }
    Bad = false;
    Writable = true;
    Offset = 0;
    Elems.clear();
    BlockLabels.clear();
  };
  SmallVector<StringRef, 16> Lines;
  Asm.split(Lines, '\n');
  for (StringRef Line : Lines) {
    SmallVector<StringRef, 4> Stmts;
    Line.split(Stmts, ';');
    for (StringRef S : Stmts) {
      S = S.split('#').first.trim();
      if (S.starts_with(".pushsection") || S.starts_with(".section")) {
        if (Depth++ == 0) {
          // flags: "a" is read-only; without them, assume it is written
          size_t Q = S.find('"');
          if (Q != StringRef::npos)
            Writable = S.substr(Q + 1).split('"').first.contains('w');
        } else {
          Bad = true;
        }
        continue;
      }
      if (S.starts_with(".popsection") || S.starts_with(".previous")) {
        if (Depth && --Depth == 0)
          closeBlock();
        continue;
      }
      while (true) {
        size_t Colon = S.find(':');
        if (Colon == StringRef::npos)
          break;
        StringRef L = S.substr(0, Colon);
        if (L.empty() || L.find_first_of(" \t$%(,") != StringRef::npos)
          break;
        ++Defs[L];
        if (Depth == 1)
          BlockLabels.push_back({L.str(), Offset});
        S = S.substr(Colon + 1).trim();
      }
      if (Depth != 1 || S.empty())
        continue;
      size_t Sp = S.find_first_of(" \t");
      StringRef Dir = S.substr(0, Sp);
      StringRef Rest = Sp == StringRef::npos ? StringRef() : S.substr(Sp);
      unsigned Size = dataSize(Dir);
      if (!Size) {
        Bad = true;
        continue;
      }
      SmallVector<StringRef, 4> Items;
      Rest.split(Items, ',');
      for (StringRef T : Items) {
        Constant *C = item(T, Size);
        if (!C) {
          Bad = true;
          break;
        }
        Elems.push_back(C);
        Offset += Size;
      }
    }
  }
  for (auto &D : Defs)
    if (D.second > 1)
      Labels.erase(D.first());
  return Labels;
}

// One step of an inline asm that makes calls, followed as a small program
// over the registers (see visitInlineAsm).
struct AsmStep {
  enum { Call, SetReg, CopyReg } Kind;
  std::string Reg, Src; // SetReg/CopyReg: destination, CopyReg: source
  int Operand = -1;     // SetReg: source operand; Call: callee operand
  std::string Sym;      // Call: symbol, when not an operand
  bool Indirect = false; // Call: `call *$N`, through the memory operand N
};

// The steps of an asm made only of calls, register moves and stack switches;
// false if it has anything else.
bool planAsmCalls(ArrayRef<AsmInsn> Insns, ArrayRef<AsmOp> Ops,
                  SmallVectorImpl<AsmStep> &Steps) {
  auto isSP = [](StringRef R) { return R == "sp"; };
  for (auto &I : Insns) {
    StringRef Mn = I.Mnemonic;
    if ((Mn == "call" || Mn == "callq") && I.Operands.size() == 1) {
      StringRef T = I.Operands[0];
      AsmStep S{AsmStep::Call};
      // Strip operand modifiers like ${0:P} - if it starts with $, it's a register operand
      StringRef Mod;
      int N = asmOperandRef(T, &Mod);
      if (N >= 0) {
        // `call ${N:P}`: the callee is an "i" operand
        if (N < (int)Ops.size() && Ops[N].V &&
            isa<Function>(Ops[N].V->stripPointerCasts()))
          S.Operand = N;
        else
          return false;
      } else if (T.starts_with("*$") || T.starts_with("*${")) {
        // `call *$N` through a memory operand: a paravirt call, slow_down_io's
        // PVOP_VCALL0(cpu.io_delay) through pv_ops
        int K = asmOperandRef(T.drop_front());
        if (K < 0 || K >= (int)Ops.size() || !Ops[K].isMem())
          return false;
        S.Operand = K;
        S.Indirect = true;
      } else if (T.starts_with("*") || T.starts_with("%") || T.empty()) {
        return false;
      } else {
        // Extract symbol name after call/callq
        // Symbol name ends at whitespace, newline, or end of string
        // (the statement's only operand, see asmExecutedInsns); here it is
        // a symbol, possibly spliced with constant operands
        // (`__get_user_${4:P}`)
        std::string Name;
        while (!T.empty()) {
          size_t P = T.find('$');
          Name += T.substr(0, P).str();
          if (P == StringRef::npos)
            break;
          T = T.substr(P);
          size_t E = T.starts_with("${") ? T.find('}') + 1 : 2;
          int K = asmOperandRef(T.substr(0, E));
          auto *C = K >= 0 && K < (int)Ops.size() && Ops[K].V
                        ? dyn_cast<ConstantInt>(Ops[K].V)
                        : nullptr;
          if (!C)
            return false;
          Name += std::to_string(C->getZExtValue());
          T = T.substr(E);
        }
        S.Sym = Name;
      }
      Steps.push_back(S);
    } else if (Mn.starts_with("mov") && Mn.size() <= 4 &&
               I.Operands.size() == 2) {
      StringRef Src = I.Operands[0], Dst = I.Operands[1];
      std::string DReg = asmRegName(Dst), SReg = asmRegName(Src);
      int N = asmOperandRef(Src);
      if (isSP(DReg) || isSP(SReg)) {
        // stack switch: `movq %rsp, (%r11)`, `movq %r11, %rsp`
      } else if (!DReg.empty() && N >= 0 && N < (int)Ops.size() &&
                 Ops[N].isValue()) {
        Steps.push_back({AsmStep::SetReg, DReg, "", N});
      } else if (!DReg.empty() && !SReg.empty()) {
        Steps.push_back({AsmStep::CopyReg, DReg, SReg});
      } else {
        return false;
      }
    } else if ((Mn.starts_with("pop") || Mn.starts_with("push")) &&
               I.Operands.size() == 1 && isSP(asmRegName(I.Operands[0]))) {
      // restoring the stack switched from
    } else {
      return false;
    }
  }
  return true;
}

// Privileged instructions (kernel mode only; in a userspace run they fault).
// A read of hardware state gets a fresh symbolic value from AsmHwReadFn, an
// undefined function the pre-pass below declares, so that the stub every
// out-of-scope function gets returns it -- labeled from the seed, like any
// callee's result.  A write or a control instruction does nothing.
const char *const AsmHwReadFn = "__ucsan_hw_read";

static bool isAsmCtrlReg(StringRef T) {
  T = T.trim();
  return T.starts_with("%cr") || T.starts_with("%dr") || T.starts_with("%db");
}

// rdmsr/rdpmc (%edx:%eax), in (%al/%ax/%eax), mov from %crN/%drN
static bool isAsmHwRead(const AsmInsn &I) {
  StringRef Mn = I.Mnemonic;
  if (Mn == "rdmsr" || Mn == "rdpmc")
    return true;
  if ((Mn == "in" || Mn == "inb" || Mn == "inw" || Mn == "inl") &&
      I.Operands.size() == 2)
    return true;
  return Mn.starts_with("mov") && I.Operands.size() == 2 &&
         isAsmCtrlReg(I.Operands[0]) && !isAsmCtrlReg(I.Operands[1]);
}

// A segment register.  Loading one is not privileged as an instruction, but
// the kernel's selectors are not valid descriptors in a userspace run: the
// first `mov %eax, %ds` of machine_kexec's load_segments(__KERNEL_DS) was a
// general-protection fault (and %fs is the process's TLS).  The model is
// flat, so a load does nothing; reading one works as it is.
static bool isAsmSegReg(StringRef T) {
  T = T.trim();
  return T == "%ds" || T == "%es" || T == "%ss" || T == "%fs" ||
         T == "%gs" || T == "%cs";
}

// wrmsr, out, mov to %crN/%drN or a segment register, and the control
// instructions
// (and the FPU state restores: they load hardware state too, from memory.
// fpu__restore_sig's fxrstor64 of a signal frame from the seed was a general
// protection fault -- reserved MXCSR bits, which the kernel's exception
// table turns into an error -- and a valid one would load the seed into the
// process's own FPU state)
// (and wrfsbase/wrgsbase, which are not privileged where FSGSBASE is on, as
// Linux turns it on for userspace: do_arch_prctl_64's ARCH_SET_FS ran
// x86_fsbase_write_cpu's wrfsbase with the seed's value, which moved the
// process's own TLS, and the next TLS access -- the SIGSEGV handler's
// included -- killed it with signal 11, exit status 139)
static bool isAsmHwNoOp(const AsmInsn &I) {
  StringRef Mn = I.Mnemonic;
  if (Mn == "fxrstor" || Mn == "fxrstorq" || Mn == "fxrstor64" ||
      Mn == "frstor" || Mn == "xrstor" || Mn == "xrstor64" ||
      Mn == "xrstors" || Mn == "xrstors64")
    return true;
  if (Mn == "wrfsbase" || Mn == "wrgsbase")
    return true;
  if (Mn == "cli" || Mn == "sti" || Mn == "wbinvd" || Mn == "invd" ||
      Mn == "clts" || Mn == "swapgs" || Mn == "xsetbv" || Mn == "wrmsr" ||
      Mn == "wrmsrns" || Mn == "lgdt" || Mn == "lidt" || Mn == "lldt" ||
      Mn == "ltr" || Mn == "invlpg")
    return true;
  if (Mn == "out" || Mn == "outb" || Mn == "outw" || Mn == "outl")
    return true;
  return Mn.starts_with("mov") && I.Operands.size() == 2 &&
         ((isAsmCtrlReg(I.Operands[1]) && !isAsmCtrlReg(I.Operands[0])) ||
          isAsmSegReg(I.Operands[1]));
}

// Callees that visitInlineAsm lowers instead of calling (the kernel's
// assembly helpers with their own calling conventions), or drops (static call
// trampolines).
bool isAsmModeledCallee(StringRef Sym) {
  return Sym.starts_with("__get_user_") || Sym.starts_with("__put_user_") ||
         Sym == "this_cpu_cmpxchg16b_emu" || Sym.starts_with("__SCT__");
}

// String port I/O, `rep; ins{b,w,l}` / `rep; outs{b,w,l}` (the kernel's
// insb/outsb, behind ioread8_rep and friends), becomes the loop the kernel
// itself uses when CC_ATTR_GUEST_UNROLL_STRING_IO is set: each element in is
// a hardware read (AsmHwReadFn) stored to the buffer, each element out a load
// of it whose value goes nowhere, as for `in` and `out`.  Run as is, the
// instruction is privileged and the first one faults (ioread8_rep's port
// path was a SIGSEGV).  As a loop, the buffer accesses are checked like any
// other.  The outputs are the pointer advanced past the buffer and a zero
// count; the direction flag is clear, as the kernel keeps it.
void lowerAsmStringIO(Module &M, StringMap<WeakTrackingVH> &Callees) {
  SmallVector<CallInst *, 4> Sites;
  for (Function &F : M)
    for (Instruction &I : instructions(F))
      if (auto *CI = dyn_cast<CallInst>(&I))
        if (CI->isInlineAsm())
          Sites.push_back(CI);
  LLVMContext &Ctx = M.getContext();
  for (CallInst *CI : Sites) {
    auto *IA = cast<InlineAsm>(CI->getCalledOperand());
    SmallVector<AsmInsn, 4> Insns = asmExecutedInsns(IA->getAsmString());
    if (Insns.size() != 1 || !Insns[0].Operands.empty())
      continue;
    StringRef Mn = Insns[0].Mnemonic;
    bool In = Mn.consume_front("rep ins");
    if (!In && !Mn.consume_front("rep outs"))
      continue;
    unsigned Size = Mn == "b" ? 1 : Mn == "w" ? 2 : Mn == "l" ? 4 : 0;
    if (!Size)
      continue;
    auto Constraints = IA->ParseConstraints();
    AsmOperands AO(*CI, Constraints);
    // register outputs: the pointer (%rdi in, %rsi out) and the count (%rcx),
    // each with its starting value in a tied input
    const char *PtrReg = In ? "di" : "si";
    int PtrOut = -1, CntOut = -1;
    Value *Ptr = nullptr, *Cnt = nullptr;
    bool Other = false;
    for (unsigned N = 0; N < AO.Ops.size(); ++N) {
      const AsmOp &Op = AO.Ops[N];
      if (Op.Result >= 0) {
        if (Op.Reg == PtrReg)
          PtrOut = N;
        else if (Op.Reg == "cx")
          CntOut = N;
        else
          Other = true;
      } else if (Op.isMem() || (Op.isInput() && Op.TiedTo < 0 &&
                                Op.Reg != "dx")) {
        Other = true;
      }
    }
    if (Other || PtrOut < 0 || CntOut < 0 || AO.HasMemOutput ||
        AO.NumResults != 2)
      continue;
    auto *ResTy = dyn_cast<StructType>(CI->getType());
    if (!ResTy ||
        !ResTy->getElementType(AO.Ops[PtrOut].Result)->isPointerTy() ||
        !ResTy->getElementType(AO.Ops[CntOut].Result)->isIntegerTy(64))
      continue;
    for (const AsmOp &Op : AO.Ops) {
      if (Op.TiedTo == PtrOut)
        Ptr = Op.V;
      else if (Op.TiedTo == CntOut)
        Cnt = Op.V;
    }
    if (!Ptr || !Cnt || !Ptr->getType()->isPointerTy() ||
        !Cnt->getType()->isIntegerTy(64))
      continue;
    Type *ElemTy = IntegerType::get(Ctx, Size * 8);
    FunctionCallee HwRead;
    if (In) {
      HwRead = M.getOrInsertFunction(
          AsmHwReadFn, FunctionType::get(Type::getInt32Ty(Ctx), false));
      Callees[AsmHwReadFn] = HwRead.getCallee();
    }

    BasicBlock *Head = CI->getParent();
    BasicBlock *Exit = Head->splitBasicBlock(CI, "ucsan.strio.exit");
    BasicBlock *Loop =
        BasicBlock::Create(Ctx, "ucsan.strio.loop", Head->getParent(), Exit);
    Head->getTerminator()->eraseFromParent();
    IRBuilder<> IRB(Head);
    IRB.SetCurrentDebugLocation(CI->getDebugLoc());
    IRB.CreateCondBr(IRB.CreateICmpEQ(Cnt, IRB.getInt64(0)), Exit, Loop);
    IRB.SetInsertPoint(Loop);
    PHINode *Idx = IRB.CreatePHI(IRB.getInt64Ty(), 2);
    Idx->addIncoming(IRB.getInt64(0), Head);
    Value *P = IRB.CreateGEP(ElemTy, Ptr, Idx);
    if (In) {
      Value *V = IRB.CreateCall(HwRead);
      IRB.CreateStore(IRB.CreateZExtOrTrunc(V, ElemTy), P);
    } else {
      IRB.CreateLoad(ElemTy, P, /*isVolatile=*/true);
    }
    Value *Next = IRB.CreateAdd(Idx, IRB.getInt64(1));
    Idx->addIncoming(Next, Loop);
    IRB.CreateCondBr(IRB.CreateICmpEQ(Next, Cnt), Exit, Loop);

    IRB.SetInsertPoint(CI);
    Value *Outs[2];
    Outs[AO.Ops[PtrOut].Result] =
        IRB.CreateGEP(ElemTy, Ptr, Cnt);
    Outs[AO.Ops[CntOut].Result] = IRB.getInt64(0);
    Value *Res = PoisonValue::get(CI->getType());
    for (unsigned R = 0; R < 2; ++R)
      Res = IRB.CreateInsertValue(Res, Outs[R], R);
    CI->replaceAllUsesWith(Res);
    CI->eraseFromParent();
  }
}

// Declare the functions inline asm calls by name without the module having
// them (the kernel's ALTERNATIVE fallbacks such as __sw_hweight32), typed
// from the registers the asm passes and the %rax output.  This runs before
// functions are sorted by scope, so these get the same in-scope / external /
// custom handling as a call from C would; visitInlineAsm finds them in
// Callees (an out-of-scope one is replaced by its __external$ wrapper, which
// the value handle follows).
void declareAsmCallees(Module &M, StringMap<WeakTrackingVH> &Callees) {
  SmallVector<CallInst *, 16> Sites;
  for (Function &F : M)
    for (Instruction &I : instructions(F))
      if (auto *CI = dyn_cast<CallInst>(&I))
        if (CI->isInlineAsm())
          Sites.push_back(CI);
  for (CallInst *CI : Sites) {
    auto *IA = cast<InlineAsm>(CI->getCalledOperand());
    auto Constraints = IA->ParseConstraints();
    AsmOperands AO(*CI, Constraints);
    SmallVector<AsmInsn, 4> Insns = asmExecutedInsns(IA->getAsmString());
    // (and for a call through an operand, whose skipped results are fresh
    // symbolic values: see guardAsmIndirectCall)
    auto callsOperand = [](const AsmInsn &I) {
      StringRef Mn = I.Mnemonic;
      return (Mn == "call" || Mn == "callq" || Mn == "jmp" || Mn == "jmpq") &&
             I.Operands.size() == 1 &&
             StringRef(I.Operands[0]).trim().starts_with("*$");
    };
    if (!Callees.count(AsmHwReadFn) &&
        any_of(Insns, [&](const AsmInsn &I) {
          return isAsmHwRead(I) || callsOperand(I);
        })) {
      Type *I32 = Type::getInt32Ty(M.getContext());
      Callees[AsmHwReadFn] =
          M.getOrInsertFunction(AsmHwReadFn, FunctionType::get(I32, false))
              .getCallee();
    }
    SmallVector<AsmStep, 4> Steps;
    if (AO.HasMemOutput || !planAsmCalls(Insns, AO.Ops, Steps))
      continue;
    StringMap<Type *> RegTys;
    Type *AxTy = nullptr;
    for (auto &Op : AO.Ops) {
      if (Op.isValue() && !Op.Reg.empty())
        RegTys[Op.Reg] = Op.V->getType();
      if (Op.Result >= 0 && Op.Reg == "ax")
        AxTy = AO.NumResults == 1
                   ? CI->getType()
                   : cast<StructType>(CI->getType())->getElementType(Op.Result);
    }
    for (auto &S : Steps) {
      if (S.Kind == AsmStep::SetReg) {
        RegTys[S.Reg] = AO.Ops[S.Operand].V->getType();
        continue;
      }
      if (S.Kind == AsmStep::CopyReg) {
        RegTys[S.Reg] = RegTys.lookup(S.Src);
        continue;
      }
      Function *Fn = nullptr;
      if (S.Operand >= 0) {
        Fn = cast<Function>(AO.Ops[S.Operand].V->stripPointerCasts());
      } else if ((Fn = M.getFunction(S.Sym))) {
        // In the module already (the C next to the asm calls it too:
        // call_on_irqstack_cond's irq_enter_rcu), but an out-of-scope one is
        // replaced by its __external$ wrapper and erased before the asm is
        // visited, and then found neither by name nor here: the asm was left
        // alone, and linked against the bare symbol (sysvec_irq_work).  The
        // value handle follows the replacement.
        if (!Callees.count(S.Sym))
          Callees[S.Sym] = Fn;
      } else if (!Callees.count(S.Sym) && !isAsmModeledCallee(S.Sym)) {
        SmallVector<Type *, 6> Params;
        for (const char *R : AsmArgRegs) {
          Type *T = RegTys.lookup(R);
          if (!T)
            break;
          Params.push_back(T);
        }
        Type *RetTy = AxTy ? AxTy : Type::getVoidTy(M.getContext());
        FunctionCallee FC = M.getOrInsertFunction(
            S.Sym, FunctionType::get(RetTy, Params, false));
        Callees[S.Sym] = FC.getCallee();
        Fn = dyn_cast<Function>(FC.getCallee());
      }
      if (Fn && !Fn->getReturnType()->isVoidTy())
        RegTys["ax"] = Fn->getReturnType();
    }
  }
}

// A small x86-64 lifter for inline asm made of plain integer instructions:
// the executed instructions are interpreted over a register file, memory and
// the ZF/SF/CF flags, and emitted as the equivalent IR -- loads, stores and
// arithmetic, `lock`ed read-modify-writes as atomicrmw/cmpxchg -- which the
// visitor then checks, sizes and labels like any other code.  This is what
// gives the kernel's atomics (atomic_add_return, test_and_set_bit,
// dec_and_test), its percpu accesses and __ffs a symbolic result.
//
// It is all-or-nothing: an instruction, operand form or flag it does not
// know makes it roll back what it built, and the asm runs as is.  It is not
// meant to be complete, only exact for what it accepts.
//
// %gs: (percpu) operands are taken as plain memory, which holds while the %gs
// base is 0; the runtime checks that at startup.  %gs: memory added into a
// pointer (this_cpu_ptr: `add %gs:this_cpu_off, ptr`) is lifted as offset 0,
// the pointer itself: percpu offsets must not come from symbolized globals,
// and running the asm as is instead (what this used to do) computed the same
// value but dropped the pointer's label.
//
// Privileged instructions, which fault in a userspace run, are modeled: a read
// of hardware state (rdmsr, rdpmc, in, mov from %crN/%drN) is a fresh symbolic
// value (see AsmHwReadFn), and a write or a control instruction (wrmsr, out,
// mov to %crN, cli/sti, wbinvd, lgdt, ...) does nothing.
class AsmLifter {
  IRBuilder<> &IRB;
  const DataLayout &DL;
  ArrayRef<AsmOp> Ops;
  SmallVector<Type *, 4> ResultTys; // types of the register outputs
  bool Volatile;

  // Register values by canonical name: a fixed register ("ax", "r8") or, for
  // an operand in a register of the compiler's choosing, "v<N>" with N its
  // output (a tied input shares its output's).  A value is kept in its own
  // type -- a pointer stays a pointer, so address arithmetic keeps its base
  // -- and a 32-bit write replaces the register (x86-64 zero-extends it).
  StringMap<Value *> Regs;
  Value *ZF = nullptr, *SF = nullptr, *CF = nullptr; // i1; null: unknown
  Value *HwRead;  // i32 (), a fresh symbolic value; null: not declared
  FunctionCallee VmcsField;  // ptr (i64): the VMCS slot of a field
public:
  // Labels of the data the asm puts in other sections (asmSectionLabels).
  const StringMap<Constant *> *SectionLabels = nullptr;
  // Calls into the runtime the lifted code makes (ucsan_vmcs_field): the
  // visitor must not treat them as calls of the program.
  SmallVector<CallInst *, 2> RuntimeCalls;
private:

  struct Loc {
    enum { LNone, LReg, LMem, LImm } K = LNone;
    std::string Reg;      // Reg: register name
    unsigned Bits = 0;    // Reg/Mem: natural width, 0 if not implied
    Value *Ptr = nullptr; // Mem: address
    bool Seg = false;     // Mem: %gs: relative
    Value *Val = nullptr; // Imm
  };

public:
  AsmLifter(IRBuilder<> &IRB, const DataLayout &DL, ArrayRef<AsmOp> Ops,
            Type *ResultTy, bool Volatile, Value *HwRead,
            FunctionCallee VmcsField)
      : IRB(IRB), DL(DL), Ops(Ops), Volatile(Volatile), HwRead(HwRead),
        VmcsField(VmcsField) {
    if (auto *ST = dyn_cast<StructType>(ResultTy))
      ResultTys.append(ST->element_begin(), ST->element_end());
    else if (!ResultTy->isVoidTy())
      ResultTys.push_back(ResultTy);
    for (unsigned N = 0; N < Ops.size(); ++N)
      if (Ops[N].isValue())
        Regs[regOf(N)] = Ops[N].V;
  }

  // The register operand N lives in.
  std::string regOf(unsigned N) const {
    if (!Ops[N].Reg.empty())
      return Ops[N].Reg;
    unsigned Root = Ops[N].TiedTo >= 0 ? Ops[N].TiedTo : N;
    return "v" + std::to_string(Root);
  }

  // Lift Insns; false (with nothing built that is still used) if any of it
  // is not supported.
  bool lift(ArrayRef<AsmInsn> Insns) {
    for (auto &I : Insns)
      if (!step(I))
        return false;
    return true;
  }

  // Value of register output operand N, or its flag for a flag output.
  Value *output(unsigned N) {
    StringRef Code = Ops[N].Code;
    if (Code.consume_front("{@cc")) {
      Code.consume_back("}");
      bool Neg = false;
      Value *F = nullptr;
      if (Code == "z" || Code == "e") F = ZF;
      else if (Code == "nz" || Code == "ne") F = ZF, Neg = true;
      else if (Code == "s") F = SF;
      else if (Code == "ns") F = SF, Neg = true;
      else if (Code == "c" || Code == "b" || Code == "nae") F = CF;
      else if (Code == "nc" || Code == "ae" || Code == "nb") F = CF, Neg = true;
      if (!F)
        return nullptr;
      return Neg ? IRB.CreateNot(F) : F;
    }
    return Regs.lookup(regOf(N));
  }

  // Whether every register or flag output has a value.
  bool outputsKnown() {
    for (unsigned N = 0; N < Ops.size(); ++N)
      if (Ops[N].Result >= 0 && StringRef(Ops[N].Code).starts_with("{@cc") &&
          !output(N))
        return false;
    return true;
  }

private:
  static bool parseInt(StringRef S, int64_t &V) {
    // small constant expressions as they appear in templates: `8`, `-8`,
    // `0x10`, `0*8`, `2*8+4`
    S = S.trim();
    if (S.empty()) {
      V = 0;
      return true;
    }
    size_t P = S.find_last_of("+-");
    if (P != StringRef::npos && P > 0) {
      int64_t A, B;
      if (!parseInt(S.substr(0, P), A) || !parseInt(S.substr(P + 1), B))
        return false;
      V = S[P] == '+' ? A + B : A - B;
      return true;
    }
    P = S.find('*');
    if (P != StringRef::npos) {
      int64_t A, B;
      if (!parseInt(S.substr(0, P), A) || !parseInt(S.substr(P + 1), B))
        return false;
      V = A * B;
      return true;
    }
    bool Neg = S.consume_front("-");
    uint64_t U;
    if (S.getAsInteger(0, U))
      return false;
    V = Neg ? -(int64_t)U : (int64_t)U;
    return true;
  }

  static unsigned regBits(StringRef Name) {
    StringRef R = Name.drop_front(); // '%'
    if (R.size() >= 2 && R[0] == 'r' && isdigit(R[1])) {
      switch (R.back()) {
      case 'd': return 32;
      case 'w': return 16;
      case 'b': return 8;
      default: return 64;
      }
    }
    if (R.size() == 3 && R[0] == 'r') return 64;
    if (R.size() == 3 && R[0] == 'e') return 32;
    if (R.size() == 2 && (R[1] == 'l' || R[1] == 'h')) return 8;
    if (R.size() == 3 && R[2] == 'l') return 8;       // sil, dil, spl, bpl
    return 16;
  }

  Value *toInt(Value *V, unsigned Bits) {
    Type *Ty = IRB.getIntNTy(Bits);
    if (V->getType()->isPointerTy())
      V = IRB.CreatePtrToInt(V, IRB.getInt64Ty());
    if (!V->getType()->isIntegerTy())
      return nullptr;
    return IRB.CreateZExtOrTrunc(V, Ty);
  }

  Value *toPtr(Value *V) {
    if (V->getType()->isPointerTy())
      return V;
    if (!V->getType()->isIntegerTy())
      return nullptr;
    return IRB.CreateIntToPtr(IRB.CreateZExtOrTrunc(V, IRB.getInt64Ty()),
                              IRB.getPtrTy());
  }

  bool parseLoc(StringRef T, Loc &L) {
    T = T.trim();
    if (T.consume_front("%gs:")) {
      L.Seg = true;
    } else if (T.starts_with("%fs:") || T.starts_with("%es:") ||
               T.starts_with("%ds:") || T.starts_with("%cs:") ||
               T.starts_with("%ss:")) {
      return false;
    }
    if (!L.Seg && T.starts_with("$$")) {
      int64_t V;
      if (!parseInt(T.drop_front(2), V)) {
        // `$1f`: the address of data the asm puts in another section
        StringRef Lbl = T.drop_front(2);
        if (!Lbl.consume_back("f") && !Lbl.consume_back("b"))
          return false;
        Constant *C = SectionLabels ? SectionLabels->lookup(Lbl) : nullptr;
        if (!C)
          return false;
        L.K = Loc::LImm;
        L.Val = C;
        return true;
      }
      L.K = Loc::LImm;
      L.Val = IRB.getInt64(V);
      return true;
    }
    if (!L.Seg && T.starts_with("%")) {
      L.K = Loc::LReg;
      L.Reg = asmRegName(T);
      L.Bits = regBits(T);
      return !L.Reg.empty() && L.Reg != "sp" && L.Reg != "bp";
    }
    size_t Paren = T.find('(');
    if (Paren == StringRef::npos) {
      // an operand reference, or (after %gs:) a bare address
      StringRef Mod;
      int N = asmOperandRef(T, &Mod);
      if (N < 0 || N >= (int)Ops.size())
        return false;
      const AsmOp &O = Ops[N];
      if (O.isMem()) {
        L.K = Loc::LMem;
        L.Ptr = O.V;
        L.Bits = DL.getTypeStoreSizeInBits(O.ElemTy);
        return true;
      }
      if ((Mod == "P" || Mod == "a" || L.Seg) && O.V &&
          O.V->getType()->isPointerTy() && !O.CI->isIndirect) {
        // an address operand ("p", or an "i" symbol): memory at it
        L.K = Loc::LMem;
        L.Ptr = O.V;
        return true;
      }
      if (L.Seg)
        return false;
      // a constant is an immediate only where the constraint allows one
      // ("i", "n", "I", "e", ...); for "r" the compiler puts it in a register
      auto immOK = [&]() {
        for (auto &C : O.CI->Codes)
          if (C.size() == 1 && StringRef("inIJKLMNOeZ").contains(C[0]))
            return true;
        return false;
      };
      if (O.V && isa<ConstantInt>(O.V) && O.isInput() && immOK()) {
        L.K = Loc::LImm;
        L.Val = O.V;
        return true;
      }
      if (O.CI->isIndirect)
        return false;
      if (!(Mod.empty() || Mod == "b" || Mod == "w" || Mod == "k" ||
            Mod == "q"))
        return false;
      L.K = Loc::LReg;
      L.Reg = regOf(N);
      if (Mod == "b") L.Bits = 8;
      else if (Mod == "w") L.Bits = 16;
      else if (Mod == "k") L.Bits = 32;
      else if (Mod == "q") L.Bits = 64;
      else {
        // an output: the type of its result
        Type *Ty = O.Result >= 0 ? (O.Result < (int)ResultTys.size()
                                        ? ResultTys[O.Result]
                                        : nullptr)
                                 : O.V->getType();
        if (Ty && Ty->isIntegerTy())
          L.Bits = Ty->getIntegerBitWidth();
        else if (Ty && Ty->isPointerTy())
          L.Bits = 64;
      }
      return true;
    }
    // disp(base[,index[,scale]])
    int64_t Disp;
    if (!parseInt(T.substr(0, Paren), Disp) || !T.ends_with(")"))
      return false;
    SmallVector<StringRef, 3> Parts;
    T.substr(Paren + 1, T.size() - Paren - 2).split(Parts, ',');
    Value *Base = nullptr;
    StringRef B = Parts[0].trim();
    if (!B.empty()) {
      Loc BL;
      if (!parseLoc(B, BL) || BL.K != Loc::LReg || !Regs.lookup(BL.Reg))
        return false;
      Base = toPtr(Regs.lookup(BL.Reg));
    } else {
      Base = ConstantPointerNull::get(IRB.getPtrTy());
    }
    if (!Base)
      return false;
    Value *Off = IRB.getInt64(Disp);
    if (Parts.size() >= 2) {
      Loc IL;
      int64_t Scale = 1;
      if (!parseLoc(Parts[1], IL) || IL.K != Loc::LReg || !Regs.lookup(IL.Reg))
        return false;
      if (Parts.size() == 3 && !parseInt(Parts[2], Scale))
        return false;
      Value *Idx = toInt(Regs.lookup(IL.Reg), 64);
      if (!Idx)
        return false;
      Off = IRB.CreateAdd(Off, IRB.CreateMul(Idx, IRB.getInt64(Scale)));
    }
    L.K = Loc::LMem;
    L.Ptr = IRB.CreateGEP(IRB.getInt8Ty(), Base, Off);
    return true;
  }

  Value *read(const Loc &L, unsigned Bits) {
    switch (L.K) {
    case Loc::LImm:
      // a section label is an address, kept a pointer like a register's
      if (L.Val->getType()->isPointerTy())
        return Bits == 64 ? L.Val : toInt(L.Val, Bits);
      return IRB.CreateSExtOrTrunc(L.Val, IRB.getIntNTy(Bits));
    case Loc::LReg: {
      Value *V = Regs.lookup(L.Reg);
      if (!V)
        return nullptr;
      if (Bits == 64 && V->getType()->isPointerTy())
        return V;
      return toInt(V, Bits);
    }
    case Loc::LMem: {
      LoadInst *Ld = IRB.CreateLoad(IRB.getIntNTy(Bits), L.Ptr);
      Ld->setVolatile(Volatile);
      return Ld;
    }
    default:
      return nullptr;
    }
  }

  bool write(const Loc &L, Value *V, unsigned Bits) {
    if (L.K == Loc::LReg) {
      if (Bits >= 32 || !Regs.lookup(L.Reg)) {
        Regs[L.Reg] = V;
        return true;
      }
      // 8/16-bit writes keep the rest of the register
      Value *Old = toInt(Regs.lookup(L.Reg), 64);
      if (!Old)
        return false;
      uint64_t Mask = maskTrailingOnes<uint64_t>(Bits);
      Regs[L.Reg] = IRB.CreateOr(IRB.CreateAnd(Old, ~Mask),
                                 IRB.CreateZExt(toInt(V, Bits), IRB.getInt64Ty()));
      return true;
    }
    if (L.K == Loc::LMem) {
      Value *IV = V->getType()->isPointerTy() ? V : toInt(V, Bits);
      StoreInst *St = IRB.CreateStore(IV, L.Ptr);
      St->setVolatile(Volatile);
      return true;
    }
    return false;
  }

  void setZS(Value *R) {
    if (R->getType()->isPointerTy())
      R = IRB.CreatePtrToInt(R, IRB.getInt64Ty());
    ZF = IRB.CreateICmpEQ(R, Constant::getNullValue(R->getType()));
    SF = IRB.CreateICmpSLT(R, Constant::getNullValue(R->getType()));
  }

  static bool splitMnemonic(StringRef Mn, StringRef Base, unsigned &Bits) {
    if (Mn == Base) {
      Bits = 0;
      return true;
    }
    if (Mn.size() == Base.size() + 1 && Mn.starts_with(Base)) {
      switch (Mn.back()) {
      case 'b': Bits = 8; return true;
      case 'w': Bits = 16; return true;
      case 'l': Bits = 32; return true;
      case 'q': Bits = 64; return true;
      }
    }
    return false;
  }

  // width of an instruction: its suffix, else a register or memory operand's
  unsigned width(unsigned Suffix, ArrayRef<Loc> Ls) {
    if (Suffix)
      return Suffix;
    for (auto &L : Ls)
      if (L.K == Loc::LReg && L.Bits)
        return L.Bits;
    for (auto &L : Ls)
      if (L.K == Loc::LMem && L.Bits)
        return L.Bits;
    return 0;
  }

  AtomicRMWInst *rmw(AtomicRMWInst::BinOp Op, Value *Ptr, Value *V) {
    AtomicRMWInst *A = IRB.CreateAtomicRMW(
        Op, Ptr, V, MaybeAlign(), AtomicOrdering::SequentiallyConsistent);
    A->setVolatile(Volatile);
    return A;
  }

  // A fresh symbolic value of Bits (<= 64) bits: see AsmHwReadFn.
  Value *hwRead(unsigned Bits) {
    FunctionType *FT = FunctionType::get(IRB.getInt32Ty(), false);
    Value *Lo = IRB.CreateZExt(IRB.CreateCall(FT, HwRead), IRB.getInt64Ty());
    if (Bits > 32) {
      Value *Hi = IRB.CreateZExt(IRB.CreateCall(FT, HwRead), IRB.getInt64Ty());
      Lo = IRB.CreateOr(Lo, IRB.CreateShl(Hi, 32));
    }
    return IRB.CreateZExtOrTrunc(Lo, IRB.getIntNTy(Bits));
  }

  // Privileged instructions, matched before their operands are parsed (a
  // control register is not a register the lifter knows): see AsmHwReadFn.
  // Returns false to decline, true when done; Handled says which applies.
  bool stepPrivileged(const AsmInsn &I, bool &Handled) {
    Handled = true;
    if (isAsmHwNoOp(I))
      return true;
    Handled = isAsmHwRead(I);
    if (!Handled)
      return false;
    if (!HwRead)
      return false;
    StringRef Mn = I.Mnemonic;
    if (Mn == "rdmsr" || Mn == "rdpmc") {
      // %edx:%eax, each zero-extended into its 64-bit register
      Regs["ax"] = IRB.CreateZExt(hwRead(32), IRB.getInt64Ty());
      Regs["dx"] = IRB.CreateZExt(hwRead(32), IRB.getInt64Ty());
      CF = ZF = SF = nullptr;
      return true;
    }
    // in port, dst / mov %crN, dst: a value into the destination
    Loc D;
    StringRef DT = StringRef(I.Operands[1]).trim();
    if (DT == "%al" || DT == "%ax" || DT == "%eax") {
      D.K = Loc::LReg;
      D.Reg = "ax";
      D.Bits = DT == "%al" ? 8 : DT == "%ax" ? 16 : 32;
    } else if (!parseLoc(DT, D) || D.K != Loc::LReg) {
      return false;
    }
    unsigned W = Mn.starts_with("mov") ? 64
                 : Mn == "inb"         ? 8
                 : Mn == "inw"         ? 16
                 : Mn == "inl"         ? 32
                                       : D.Bits;
    if (!W)
      return false;
    return write(D, hwRead(W), W);
  }

  bool step(const AsmInsn &I) {
    StringRef Mn = I.Mnemonic;
    bool Lock = Mn.consume_front("lock ");
    bool Rep = Mn.consume_front("rep ");
    if (!Lock && !Rep) {
      bool Handled;
      bool OK = stepPrivileged(I, Handled);
      if (Handled)
        return OK;
    }
    // `jna ${N:l}` to an asm goto label (the VMX failure path after vmread /
    // vmwrite): only when the flags say it is not taken, since the lifted asm
    // falls through to its default destination
    if ((Mn == "jna" || Mn == "jbe") && I.Operands.size() == 1 &&
        StringRef(I.Operands[0]).ends_with(":l}")) {
      auto isFalse = [](Value *F) {
        auto *C = dyn_cast_or_null<ConstantInt>(F);
        return C && C->isZero();
      };
      return !Lock && !Rep && isFalse(CF) && isFalse(ZF);
    }
    SmallVector<Loc, 3> Ls;
    for (auto &O : I.Operands) {
      Loc L;
      if (!parseLoc(O, L))
        return false;
      Ls.push_back(L);
    }
    unsigned Suf;
    if (Mn == "nop")
      return !Lock && !Rep;
    // `sbb %0, %0`, `xor %0, %0`: the same register on both sides does not
    // depend on its old value for these idioms, which is often undefined (an
    // "=r" output read before any write); take it as 0
    if (Ls.size() == 2 && Ls[0].K == Loc::LReg && Ls[1].K == Loc::LReg &&
        Ls[0].Reg == Ls[1].Reg && !Regs.lookup(Ls[0].Reg))
      Regs[Ls[0].Reg] = IRB.getInt64(0);
    if (Rep && !(Mn.starts_with("bsf") || Mn.starts_with("bsr")))
      return false;

    // VMX: vmread field, dst / vmwrite src, field act on the runtime's VMCS
    // model (ucsan_vmcs_field), and succeed: CF = ZF = 0
    if ((Mn == "vmread" || Mn == "vmwrite") && !Lock && !Rep &&
        Ls.size() == 2 && VmcsField) {
      bool Rd = Mn == "vmread";
      const Loc &FL = Rd ? Ls[0] : Ls[1];
      const Loc &VL = Rd ? Ls[1] : Ls[0];
      if (FL.K == Loc::LMem || VL.K == Loc::LImm)
        return false;
      Value *Fld = read(FL, 64);
      if (!Fld || !(Fld = toInt(Fld, 64)))
        return false;
      CallInst *Slot = IRB.CreateCall(VmcsField, {Fld});
      RuntimeCalls.push_back(Slot);
      if (Rd) {
        LoadInst *L = IRB.CreateLoad(IRB.getInt64Ty(), Slot);
        L->setVolatile(true);
        if (!write(VL, L, 64))
          return false;
      } else {
        Value *V = read(VL, 64);
        if (!V || !(V = toInt(V, 64)))
          return false;
        IRB.CreateStore(V, Slot)->setVolatile(true);
      }
      CF = ZF = IRB.getFalse();
      SF = nullptr;
      return true;
    }

    // movnti reg, mem: a store whose non-temporal hint means nothing here
    // (__memcpy_flushcache's copy loop)
    if (splitMnemonic(Mn, "movnti", Suf)) {
      if (Lock || Ls.size() != 2 || Ls[0].K != Loc::LReg ||
          Ls[1].K != Loc::LMem)
        return false;
      unsigned W = width(Suf, Ls);
      if (W != 32 && W != 64)
        return false;
      Value *V = read(Ls[0], W);
      return V && write(Ls[1], V, W);
    }
    // mov src, dst
    if (splitMnemonic(Mn, "mov", Suf)) {
      if (Lock || Ls.size() != 2 || Ls[1].K == Loc::LImm ||
          (Ls[0].K == Loc::LMem && Ls[1].K == Loc::LMem))
        return false;
      unsigned W = width(Suf, Ls);
      if (!W)
        return false;
      Value *V = read(Ls[0], W);
      return V && write(Ls[1], V, W);
    }
    // movz/movs with two size letters: movzbl, movswq, movslq, ...
    if ((Mn.starts_with("movz") || Mn.starts_with("movs")) && Mn.size() == 6) {
      auto bits = [](char C) -> unsigned {
        return C == 'b' ? 8 : C == 'w' ? 16 : C == 'l' ? 32 : C == 'q' ? 64 : 0;
      };
      unsigned From = bits(Mn[4]), To = bits(Mn[5]);
      if (Lock || !From || !To || From >= To || Ls.size() != 2 ||
          Ls[1].K != Loc::LReg)
        return false;
      Value *V = read(Ls[0], From);
      if (!V)
        return false;
      V = Mn[3] == 'z' ? IRB.CreateZExt(V, IRB.getIntNTy(To))
                       : IRB.CreateSExt(V, IRB.getIntNTy(To));
      return write(Ls[1], V, To);
    }

    // two-operand arithmetic and logic: op src, dst
    struct BinDef {
      const char *Name;
      Instruction::BinaryOps Op;
      AtomicRMWInst::BinOp RMW;
      bool WritesDst;
    };
    static const BinDef Bins[] = {
        {"add", Instruction::Add, AtomicRMWInst::Add, true},
        {"sub", Instruction::Sub, AtomicRMWInst::Sub, true},
        {"and", Instruction::And, AtomicRMWInst::And, true},
        {"or", Instruction::Or, AtomicRMWInst::Or, true},
        {"xor", Instruction::Xor, AtomicRMWInst::Xor, true},
        {"cmp", Instruction::Sub, AtomicRMWInst::BAD_BINOP, false},
        {"test", Instruction::And, AtomicRMWInst::BAD_BINOP, false},
    };
    for (auto &B : Bins) {
      if (!splitMnemonic(Mn, B.Name, Suf))
        continue;
      if (Ls.size() != 2 || Ls[1].K == Loc::LImm ||
          (Ls[0].K == Loc::LMem && Ls[1].K == Loc::LMem))
        return false;
      unsigned W = width(Suf, Ls);
      if (!W)
        return false;
      // this_cpu_ptr, `add %gs:this_cpu_off, ptr`: the percpu offset is 0 (see
      // the class comment).  Decided before reading the source, which would
      // otherwise load -- and symbolize -- this_cpu_off for nothing.
      if (B.Op == Instruction::Add && B.WritesDst && !Lock && W == 64 &&
          Ls[0].K == Loc::LMem && Ls[0].Seg && Ls[1].K == Loc::LReg) {
        Value *P = Regs.lookup(Ls[1].Reg);
        if (P && P->getType()->isPointerTy()) {
          setZS(P);
          CF = nullptr;
          return true;
        }
      }
      Value *Src = read(Ls[0], W);
      if (!Src)
        return false;
      bool IsAddSub = B.Op == Instruction::Add || B.Op == Instruction::Sub;
      if (Lock) {
        if (!B.WritesDst || Ls[1].K != Loc::LMem)
          return false;
        Src = toInt(Src, W);
        Value *Old = rmw(B.RMW, Ls[1].Ptr, Src);
        Value *R = IRB.CreateBinOp(B.Op, Old, Src);
        setZS(R);
        CF = !IsAddSub ? IRB.getFalse()
             : B.Op == Instruction::Add ? IRB.CreateICmpULT(R, Old)
                                        : IRB.CreateICmpULT(Old, Src);
        return true;
      }
      // pointer arithmetic keeps its base: add/sub of an integer to a
      // pointer register is a GEP
      Value *DstV = Ls[1].K == Loc::LReg ? Regs.lookup(Ls[1].Reg) : nullptr;
      if (IsAddSub && B.WritesDst && W == 64 && DstV &&
          DstV->getType()->isPointerTy() && !Src->getType()->isPointerTy()) {
        if (Ls[0].Seg)
          return false; // this_cpu_ptr is handled before the read, above
        Value *Off = B.Op == Instruction::Add ? Src : IRB.CreateNeg(Src);
        Value *R = IRB.CreateGEP(IRB.getInt8Ty(), DstV, Off);
        Regs[Ls[1].Reg] = R;
        setZS(R);
        CF = nullptr;
        return true;
      }
      Value *Dst = read(Ls[1], W);
      if (!Dst)
        return false;
      Value *A = toInt(Dst, W), *S = toInt(Src, W);
      Value *R = IRB.CreateBinOp(B.Op, A, S);
      setZS(R);
      CF = !IsAddSub ? IRB.getFalse()
           : B.Op == Instruction::Add ? IRB.CreateICmpULT(R, A)
                                      : IRB.CreateICmpULT(A, S);
      return !B.WritesDst || write(Ls[1], R, W);
    }

    // adc/sbb src, dst: add/sub with the carry flag, which must be known
    // (array_index_mask_nospec's `cmp; sbb`, the checksum `add; adc` chains)
    for (const char *S : {"adc", "sbb"}) {
      if (!splitMnemonic(Mn, S, Suf))
        continue;
      if (Lock || !CF || Ls.size() != 2 || Ls[1].K == Loc::LImm ||
          (Ls[0].K == Loc::LMem && Ls[1].K == Loc::LMem))
        return false;
      unsigned W = width(Suf, Ls);
      Value *Src = W ? read(Ls[0], W) : nullptr;
      Value *Dst = W ? read(Ls[1], W) : nullptr;
      if (!Src || !Dst)
        return false;
      Value *A = toInt(Dst, W), *B = toInt(Src, W);
      Value *C = IRB.CreateZExt(CF, A->getType());
      Value *R;
      if (StringRef(S) == "adc") {
        R = IRB.CreateAdd(IRB.CreateAdd(A, B), C);
        // carry out: the sum wrapped, or it equals a with a carry in
        CF = IRB.CreateOr(IRB.CreateICmpULT(R, A),
                          IRB.CreateAnd(IRB.CreateICmpEQ(R, A), CF));
      } else {
        R = IRB.CreateSub(IRB.CreateSub(A, B), C);
        // borrow: a < b + carry, without overflowing b + carry
        CF = IRB.CreateOr(IRB.CreateICmpULT(A, B),
                          IRB.CreateAnd(IRB.CreateICmpEQ(A, B), CF));
      }
      setZS(R);
      return write(Ls[1], R, W);
    }

    // one-operand: inc, dec, neg, not
    bool Inc = splitMnemonic(Mn, "inc", Suf), Dec = !Inc && splitMnemonic(Mn, "dec", Suf);
    bool NegI = !Inc && !Dec && splitMnemonic(Mn, "neg", Suf);
    bool NotI = !Inc && !Dec && !NegI && splitMnemonic(Mn, "not", Suf);
    if (Inc || Dec || NegI || NotI) {
      if (Ls.size() != 1 || Ls[0].K == Loc::LImm)
        return false;
      unsigned W = width(Suf, Ls);
      if (!W)
        return false;
      Value *One = IRB.getIntN(W, 1);
      if (Lock) {
        if (Ls[0].K != Loc::LMem || !(Inc || Dec))
          return false;
        Value *Old = rmw(Inc ? AtomicRMWInst::Add : AtomicRMWInst::Sub,
                         Ls[0].Ptr, One);
        setZS(Inc ? IRB.CreateAdd(Old, One) : IRB.CreateSub(Old, One));
        return true; // CF unchanged
      }
      Value *V = read(Ls[0], W);
      if (!V)
        return false;
      V = toInt(V, W);
      Value *R;
      if (Inc) R = IRB.CreateAdd(V, One);
      else if (Dec) R = IRB.CreateSub(V, One);
      else if (NegI) R = IRB.CreateNeg(V);
      else R = IRB.CreateNot(V);
      if (!NotI)
        setZS(R);
      if (NegI)
        CF = IRB.CreateICmpNE(V, Constant::getNullValue(V->getType()));
      return write(Ls[0], R, W);
    }

    // shifts: shl/sal/shr/sar [count,] dst
    for (const char *S : {"shl", "sal", "shr", "sar"}) {
      if (!splitMnemonic(Mn, S, Suf))
        continue;
      if (Lock || Ls.empty() || Ls.size() > 2)
        return false;
      const Loc &Dst = Ls.back();
      unsigned W = width(Suf, {Dst});
      if (!W || Dst.K == Loc::LImm)
        return false;
      Value *Cnt;
      int64_t C = -1;
      if (Ls.size() == 1) {
        C = 1;
      } else if (Ls[0].K == Loc::LImm) {
        auto *CI = dyn_cast<ConstantInt>(Ls[0].Val);
        if (!CI)
          return false;
        C = CI->getSExtValue();
      } else if (Ls[0].K != Loc::LReg || Ls[0].Reg != "cx") {
        return false;
      }
      unsigned Mask = W == 64 ? 63 : 31;
      Value *V = read(Dst, W);
      if (!V)
        return false;
      V = toInt(V, W);
      if (C >= 0) {
        C &= Mask;
        if (C == 0 || (unsigned)C >= W)
          return C == 0; // flags and value unchanged / out of range
        Cnt = IRB.getIntN(W, C);
      } else {
        Value *Cx = read(Ls[0], 8);
        if (!Cx)
          return false;
        Cnt = IRB.CreateAnd(IRB.CreateZExt(Cx, IRB.getIntNTy(W)), Mask);
      }
      bool Left = StringRef(S) == "shl" || StringRef(S) == "sal";
      Value *R = Left ? IRB.CreateShl(V, Cnt)
                 : StringRef(S) == "shr" ? IRB.CreateLShr(V, Cnt)
                                         : IRB.CreateAShr(V, Cnt);
      if (C > 0) {
        setZS(R);
        unsigned Bit = Left ? W - C : C - 1;
        CF = IRB.CreateTrunc(IRB.CreateLShr(V, Bit), IRB.getInt1Ty());
      } else {
        ZF = SF = CF = nullptr; // a zero count leaves them unchanged
      }
      return write(Dst, R, W);
    }

    // xadd src(reg), dst: dst += src, src = old dst
    if (splitMnemonic(Mn, "xadd", Suf)) {
      if (Ls.size() != 2 || Ls[0].K != Loc::LReg || Ls[1].K == Loc::LImm)
        return false;
      unsigned W = width(Suf, Ls);
      Value *Src = W ? read(Ls[0], W) : nullptr;
      if (!Src)
        return false;
      Src = toInt(Src, W);
      Value *Old;
      if (Lock) {
        if (Ls[1].K != Loc::LMem)
          return false;
        Old = rmw(AtomicRMWInst::Add, Ls[1].Ptr, Src);
      } else {
        Old = read(Ls[1], W);
        if (!Old)
          return false;
        Old = toInt(Old, W);
        if (!write(Ls[1], IRB.CreateAdd(Old, Src), W))
          return false;
      }
      Value *Sum = IRB.CreateAdd(Old, Src);
      setZS(Sum);
      CF = IRB.CreateICmpULT(Sum, Old);
      return write(Ls[0], Old, W);
    }

    // xchg a, b (implicitly locked with a memory operand)
    if (splitMnemonic(Mn, "xchg", Suf)) {
      if (Ls.size() != 2 || Ls[0].K == Loc::LImm || Ls[1].K == Loc::LImm)
        return false;
      unsigned W = width(Suf, Ls);
      if (!W)
        return false;
      const Loc *R = &Ls[0], *M = &Ls[1];
      if (R->K == Loc::LMem)
        std::swap(R, M);
      Value *RV = read(*R, W);
      if (!RV || R->K != Loc::LReg)
        return false;
      if (M->K == Loc::LMem) {
        Value *Old = rmw(AtomicRMWInst::Xchg, M->Ptr,
                         RV->getType()->isPointerTy() ? RV : toInt(RV, W));
        return write(*R, Old, W);
      }
      Value *MV = read(*M, W);
      return MV && write(*M, RV, W) && write(*R, MV, W);
    }

    // cmpxchg src(reg), dst: if (ax == dst) dst = src; ax = old dst
    if (splitMnemonic(Mn, "cmpxchg", Suf)) {
      if (Ls.size() != 2 || Ls[0].K != Loc::LReg || Ls[1].K == Loc::LImm)
        return false;
      unsigned W = width(Suf, Ls);
      Loc Ax;
      Ax.K = Loc::LReg;
      Ax.Reg = "ax";
      Value *Src = W ? read(Ls[0], W) : nullptr;
      Value *Cmp = W ? read(Ax, W) : nullptr;
      if (!Src || !Cmp)
        return false;
      Src = toInt(Src, W);
      Cmp = toInt(Cmp, W);
      Value *Old, *Eq;
      if (Lock) {
        if (Ls[1].K != Loc::LMem)
          return false;
        AtomicCmpXchgInst *X = IRB.CreateAtomicCmpXchg(
            Ls[1].Ptr, Cmp, Src, MaybeAlign(),
            AtomicOrdering::SequentiallyConsistent,
            AtomicOrdering::SequentiallyConsistent);
        X->setVolatile(Volatile);
        Old = IRB.CreateExtractValue(X, 0);
        Eq = IRB.CreateExtractValue(X, 1);
      } else {
        Old = read(Ls[1], W);
        if (!Old)
          return false;
        Old = toInt(Old, W);
        Eq = IRB.CreateICmpEQ(Old, Cmp);
        if (!write(Ls[1], IRB.CreateSelect(Eq, Src, Old), W))
          return false;
      }
      ZF = Eq;
      Value *D = IRB.CreateSub(Cmp, Old);
      SF = IRB.CreateICmpSLT(D, Constant::getNullValue(D->getType()));
      CF = IRB.CreateICmpULT(Cmp, Old);
      return write(Ax, Old, W);
    }

    // bt/bts/btr/btc bit, base: CF = the old bit
    for (const char *S : {"bt", "bts", "btr", "btc"}) {
      if (!splitMnemonic(Mn, S, Suf))
        continue;
      StringRef Op(S);
      if (Ls.size() != 2 || Ls[1].K == Loc::LImm || (Lock && Op == "bt") ||
          (Lock && Ls[1].K != Loc::LMem))
        return false;
      unsigned W = width(Suf, {Ls[1]});
      if (!W && Ls[0].K == Loc::LReg)
        W = Ls[0].Bits;
      if (W != 16 && W != 32 && W != 64)
        return false;
      Value *Nr = read(Ls[0], 64);
      if (!Nr)
        return false;
      Nr = Ls[0].K == Loc::LImm ? Nr : toInt(Nr, 64);
      Loc Word = Ls[1];
      if (Ls[1].K == Loc::LMem && Ls[0].K != Loc::LImm) {
        // a register bit offset addresses a bit string
        Value *Idx = IRB.CreateAShr(Nr, Log2_32(W));
        Word.Ptr = IRB.CreateGEP(IRB.getIntNTy(W), Ls[1].Ptr, Idx);
      }
      Value *Bit = IRB.CreateAnd(IRB.CreateTrunc(Nr, IRB.getIntNTy(W)), W - 1);
      Value *Mask = IRB.CreateShl(IRB.getIntN(W, 1), Bit);
      Value *Old;
      if (Lock) {
        AtomicRMWInst::BinOp RMW = Op == "bts" ? AtomicRMWInst::Or
                                   : Op == "btr" ? AtomicRMWInst::And
                                                 : AtomicRMWInst::Xor;
        Old = rmw(RMW, Word.Ptr, Op == "btr" ? IRB.CreateNot(Mask) : Mask);
      } else {
        Old = read(Word, W);
        if (!Old)
          return false;
        Old = toInt(Old, W);
        if (Op != "bt") {
          Value *New = Op == "bts" ? IRB.CreateOr(Old, Mask)
                       : Op == "btr" ? IRB.CreateAnd(Old, IRB.CreateNot(Mask))
                                     : IRB.CreateXor(Old, Mask);
          if (!write(Word, New, W))
            return false;
        }
      }
      CF = IRB.CreateICmpNE(IRB.CreateAnd(Old, Mask),
                            Constant::getNullValue(Old->getType()));
      ZF = SF = nullptr;
      return true;
    }

    // bit scans and counts: op src, dst
    for (const char *S : {"bsf", "bsr", "tzcnt", "lzcnt", "popcnt"}) {
      if (!splitMnemonic(Mn, S, Suf))
        continue;
      StringRef Op(S);
      if (Lock || Ls.size() != 2 || Ls[1].K != Loc::LReg || Ls[0].K == Loc::LImm)
        return false;
      unsigned W = width(Suf, Ls);
      if (!W)
        return false;
      Value *Src = read(Ls[0], W);
      if (!Src)
        return false;
      Src = toInt(Src, W);
      Type *Ty = Src->getType();
      Value *IsZero = IRB.CreateICmpEQ(Src, Constant::getNullValue(Ty));
      Value *R;
      // `rep; bsf` is how the kernel writes tzcnt; the two agree on every
      // non-zero input, and __ffs is undefined for zero
      if (Op == "bsf" || Op == "tzcnt")
        R = IRB.CreateBinaryIntrinsic(Intrinsic::cttz, Src, IRB.getFalse());
      else if (Op == "lzcnt")
        R = IRB.CreateBinaryIntrinsic(Intrinsic::ctlz, Src, IRB.getFalse());
      else if (Op == "bsr")
        R = IRB.CreateSub(IRB.getIntN(W, W - 1),
                          IRB.CreateBinaryIntrinsic(Intrinsic::ctlz, Src,
                                                    IRB.getFalse()));
      else
        R = IRB.CreateUnaryIntrinsic(Intrinsic::ctpop, Src);
      if (Op == "bsf" || Op == "bsr" || Op == "popcnt") {
        ZF = IsZero;
        CF = Op == "popcnt" ? IRB.getFalse() : nullptr;
      } else {
        CF = IsZero;
        ZF = IRB.CreateICmpEQ(R, Constant::getNullValue(Ty));
      }
      SF = nullptr;
      return write(Ls[1], R, W);
    }

    // lea mem, dst: the address itself
    if (splitMnemonic(Mn, "lea", Suf)) {
      if (Lock || Ls.size() != 2 || Ls[0].K != Loc::LMem || Ls[0].Seg ||
          Ls[1].K != Loc::LReg || I.Operands[0].find("%rip") != std::string::npos)
        return false;
      return write(Ls[1], Ls[0].Ptr, 64);
    }

    return false;
  }
};
} // namespace

void UCSanVisitor::visitInlineAsm(InlineAsm *IA, CallBase &CB) {
  IRBuilder<> IRB(&CB);
  Module *M = CB.getModule();
  const DataLayout &DL = M->getDataLayout();

  // Use ParseConstraints to identify memory operands and check their pointers
  auto Constraints = IA->ParseConstraints();
  auto AsmStr = IA->getAsmString();

  AsmOperands AO(CB, Constraints);
  auto &Ops = AO.Ops;
  unsigned NumResults = AO.NumResults;
  // Check if all constraints are clobbers (no inputs/outputs)
  bool allClobbers = AO.AllClobbers;
  bool HasMemOutput = AO.HasMemOutput;
  auto resultTy = [&](unsigned I) -> Type * {
    if (NumResults == 1)
      return CB.getType();
    return cast<StructType>(CB.getType())->getElementType(I);
  };
  // the value an output register holds on entry: its tied input, if any
  auto tiedInput = [&](unsigned OpNo) -> Value * {
    for (auto &Op : Ops)
      if (Op.TiedTo == (int)OpNo)
        return Op.V;
    return nullptr;
  };
  auto memSize = [&](const AsmOp &Op) -> uint64_t {
    return Op.ElemTy && Op.ElemTy->isSized() ? DL.getTypeStoreSize(Op.ElemTy)
                                             : 0;
  };

  // Replace the asm by IR built in front of it; Results[I] is the value of
  // its I-th register output (null for zero).  The visitor has already moved
  // past the new instructions, so they are visited here, in order.
  Instruction *Before = CB.getPrevNode();
  auto replaceWith = [&](ArrayRef<Value *> Results) {
    Value *Res = nullptr;
    auto result = [&](unsigned I) -> Value * {
      Type *Ty = resultTy(I);
      Value *V = I < Results.size() ? Results[I] : nullptr;
      return V ? castAsmValue(IRB, DL, V, Ty) : Constant::getNullValue(Ty);
    };
    // Handle return value: replace all uses of the inline asm result
    if (NumResults == 1) {
      Res = result(0);
    } else if (NumResults > 1) {
      // Inline asm may return a struct; replace ExtractValue uses
      // First element is typically the return value
      // Other elements get zero/null
      // (now: the struct is rebuilt, each element from its own register --
      // the return value is the %rax element, wherever it is -- so the
      // ExtractValue uses read it unchanged, and one with no value gets
      // zero/null)
      Res = PoisonValue::get(CB.getType());
      for (unsigned I = 0; I < NumResults; ++I)
        Res = IRB.CreateInsertValue(Res, result(I), I);
    }
    // Handle shadow propagation for the new call through visitCallBase;
    // Check if the callee has a wrapper (custom or auto-custom)
    // Now handle the new call through the normal wrapped call path
    // For in-scope or normal out-of-scope functions, replace with direct call
    // (visitCallBase does all three: for a callee with a wrapper,
    // visitWrappedCallBase will redirect to the wrapper)
    Instruction *I = Before ? Before->getNextNode() : &CB.getParent()->front();
    while (I != &CB) {
      Instruction *Next = I->getNextNode();
      if (!UF.SkipInsts.count(I))
        visit(*I);
      I = Next;
    }
    if (Res)
      CB.replaceAllUsesWith(Res);
    // An asm goto (the kernel's unsafe_get_user/unsafe_put_user, whose label
    // is the fault fixup) falls through to its default destination: the
    // lowered access does not fault the way the asm's exception table
    // expects.  The other edges are kept, as dead cases of a switch on a
    // constant, so the PHIs and the dominator tree stay as they are (removing
    // a predecessor under PHIs already given shadow PHIs breaks the fixups).
    if (auto *CBr = dyn_cast<CallBrInst>(&CB)) {
      SwitchInst *Sw = SwitchInst::Create(IRB.getInt32(0), CBr->getDefaultDest(),
                                          CBr->getNumIndirectDests(), CBr);
      for (unsigned I = 0; I < CBr->getNumIndirectDests(); ++I)
        Sw->addCase(IRB.getInt32(I + 1), CBr->getIndirectDest(I));
      Sw->copyMetadata(*CBr);
    }
    CB.eraseFromParent();
  };

  SmallVector<AsmInsn, 4> Insns = asmExecutedInsns(AsmStr);
  bool Volatile = IA->hasSideEffects();
  bool IsCall = isa<CallInst>(CB);

  // Asm whose effect is known is lowered to the equivalent IR, which is then
  // checked, sized and labeled like any other code.

  // `mov` between two operands: a register-to-register move, a load from a
  // memory input (readl), or a store to a memory operand (writel).  A segment
  // prefix (%gs: percpu) is not an operand reference and is not lowered.
  if (IsCall && Insns.size() == 1 && Ops.size() == 2 &&
      StringRef(Insns[0].Mnemonic).starts_with("mov") &&
      Insns[0].Mnemonic.size() <= 4 && Insns[0].Operands.size() == 2) {
    StringRef SMod, DMod;
    int S = asmOperandRef(Insns[0].Operands[0], &SMod);
    int D = asmOperandRef(Insns[0].Operands[1], &DMod);
    uint64_t Width = asmAccessSize(Insns[0].Mnemonic, {});
    if (Insns[0].Mnemonic == "mov" || Width) {
      // register-width modifiers only; ${N:P} / ${N:c} are not a value
      auto widthMod = [](StringRef Mod) {
        return Mod.empty() || Mod == "b" || Mod == "h" || Mod == "w" ||
               Mod == "k" || Mod == "q";
      };
      if (S >= 0 && D >= 0 && S != D && Ops[S].isInput() && widthMod(SMod) &&
          widthMod(DMod)) {
        AsmOp &SO = Ops[S], &DO = Ops[D];
        if (DO.Result >= 0 && NumResults == 1) {
          uint64_t Size = DL.getTypeStoreSize(resultTy(0));
          if (!Width || Width == Size) {
            if (SO.isValue()) {
              replaceWith({SO.V});
              return;
            }
            if (SO.isMem()) {
              LoadInst *L = IRB.CreateLoad(resultTy(0), SO.V);
              L->setVolatile(Volatile);
              replaceWith({L});
              return;
            }
          }
        } else if (DO.isMem() && SO.isValue() && NumResults == 0 &&
                   (!Width || Width == memSize(DO))) {
          StoreInst *St = IRB.CreateStore(
              castAsmValue(IRB, DL, SO.V, DO.ElemTy), DO.V);
          St->setVolatile(Volatile);
          replaceWith({});
          return;
        }
      }
    }
  }

  // `bt bit, base` into a carry-flag output (variable_test_bit).  A memory
  // base is a bit string: a register bit offset is signed and may address
  // past the first word.
  if (IsCall && Insns.size() == 1 && Ops.size() == 3 && NumResults == 1 &&
      (Insns[0].Mnemonic == "bt" || Insns[0].Mnemonic == "btw" ||
       Insns[0].Mnemonic == "btl" || Insns[0].Mnemonic == "btq") &&
      Insns[0].Operands.size() == 2) {
    int B = asmOperandRef(Insns[0].Operands[0]);
    int W = asmOperandRef(Insns[0].Operands[1]);
    int Out = -1;
    for (unsigned I = 0; I < Ops.size(); ++I)
      if (Ops[I].Result == 0 && Ops[I].Code == "{@ccc}")
        Out = I;
    if (Out >= 0 && B >= 0 && W >= 0 && Ops[B].isValue() &&
        (Ops[W].isValue() || (Ops[W].isInput() && Ops[W].isMem()))) {
      uint64_t Bytes = asmAccessSize(Insns[0].Mnemonic, {});
      if (!Bytes)
        Bytes = Ops[W].isMem() ? memSize(Ops[W])
                               : DL.getTypeStoreSize(Ops[W].V->getType());
      if (Bytes == 2 || Bytes == 4 || Bytes == 8) {
        unsigned Bits = Bytes * 8;
        Type *WordTy = IRB.getIntNTy(Bits);
        Value *Nr = castAsmValue(IRB, DL, Ops[B].V, IRB.getInt64Ty(), true);
        Value *Word;
        if (Ops[W].isMem()) {
          Value *Idx = IRB.CreateAShr(Nr, Log2_32(Bits));
          Value *Ptr = IRB.CreateGEP(WordTy, Ops[W].V, Idx);
          LoadInst *L = IRB.CreateLoad(WordTy, Ptr);
          L->setVolatile(Volatile);
          Word = L;
        } else {
          Word = castAsmValue(IRB, DL, Ops[W].V, WordTy);
        }
        Value *Sh = IRB.CreateAnd(IRB.CreateTrunc(Nr, WordTy), Bits - 1);
        Value *Bit = IRB.CreateAnd(IRB.CreateLShr(Word, Sh), 1);
        replaceWith({Bit});
        return;
      }
    }
  }

  // Build input args from parsed constraints
  // Values of the input registers, by register name.
  auto inputRegs = [&]() {
    StringMap<Value *> Regs;
    for (auto &Op : Ops)
      if (Op.isValue() && !Op.Reg.empty())
        Regs[Op.Reg] = Op.V;
    return Regs;
  };
  // Results from the final register values; an output without a named
  // register keeps its tied input.
  // No return value or no uses — safe to just delete
  // Has uses — try to find a type-matching input as passthrough
  // (now: the input in the same register, or tied to the output)
  // e.g., "={rsp},{rsp}" means rsp is passed through unchanged
  auto regResults = [&](StringMap<Value *> &Regs) {
    SmallVector<Value *, 4> Results(NumResults, nullptr);
    for (unsigned I = 0; I < Ops.size(); ++I) {
      if (Ops[I].Result < 0)
        continue;
      Value *V = Ops[I].Reg.empty() ? nullptr : Regs.lookup(Ops[I].Reg);
      Results[Ops[I].Result] = V ? V : tiedInput(I);
    }
    return Results;
  };

  // `rep movsb` / `rep stosb` on (%rdi, %rsi, %rcx): the kernel's
  // copy_user_generic and clear_user, whose ALTERNATIVE fallback is a call
  // to rep_movs_alternative / rep_stos_alternative.  Lowered to memcpy /
  // memset, which leaves the count at 0 and the pointers past the end.
  if (IsCall && Insns.size() == 1 &&
      (Insns[0].Mnemonic == "rep movsb" || Insns[0].Mnemonic == "rep stosb") &&
      !HasMemOutput) {
    bool Movs = Insns[0].Mnemonic == "rep movsb";
    StringMap<Value *> Regs = inputRegs();
    Value *Len = Regs.lookup("cx"), *Dst = Regs.lookup("di");
    Value *Src = Movs ? Regs.lookup("si") : Regs.lookup("ax");
    if (Len && Dst && Src) {
      Len = castAsmValue(IRB, DL, Len, IRB.getInt64Ty());
      Value *DstP = castAsmValue(IRB, DL, Dst, IRB.getPtrTy());
      if (Movs) {
        Value *SrcP = castAsmValue(IRB, DL, Src, IRB.getPtrTy());
        IRB.CreateMemCpy(DstP, MaybeAlign(1), SrcP, MaybeAlign(1), Len,
                         Volatile);
        Regs["si"] = IRB.CreateGEP(IRB.getInt8Ty(), SrcP, Len);
      } else {
        IRB.CreateMemSet(DstP, castAsmValue(IRB, DL, Src, IRB.getInt8Ty()),
                         Len, MaybeAlign(1), Volatile);
      }
      Regs["di"] = IRB.CreateGEP(IRB.getInt8Ty(), DstP, Len);
      Regs["cx"] = ConstantInt::get(IRB.getInt64Ty(), 0);
      replaceWith(regResults(Regs));
      return;
    }
  }

  // `rep stos{w,l,q}`: %rcx elements of %ax/%eax/%rax at (%rdi), the
  // kernel's memset16/32/64 (gen6_ppgtt_clear_range's memset32 ran as is on
  // a pseudo-pointer).  Lowered to a memset of the range, which checks the
  // pointer and sets the shadow (from the value's low byte), and then the
  // element pattern written through the checked pointer by
  // ucsan_fill_pattern; %rdi ends past the range and %rcx at 0.
  if (IsCall && Insns.size() == 1 && !HasMemOutput &&
      Insns[0].Operands.empty()) {
    StringRef Mn = Insns[0].Mnemonic;
    unsigned K = Mn == "rep stosw" ? 2 : Mn == "rep stosl" ? 4
               : Mn == "rep stosq" ? 8 : 0;
    StringMap<Value *> Regs = inputRegs();
    Value *Cnt = Regs.lookup("cx"), *Dst = Regs.lookup("di"),
          *Val = Regs.lookup("ax");
    if (K && Cnt && Dst && Val) {
      Cnt = castAsmValue(IRB, DL, Cnt, IRB.getInt64Ty());
      Val = castAsmValue(IRB, DL, Val, IRB.getIntNTy(K * 8));
      Value *Bytes = IRB.CreateMul(Cnt, IRB.getInt64(K));
      Value *DstP = castAsmValue(IRB, DL, Dst, IRB.getPtrTy());
      auto *MS = cast<MemSetInst>(IRB.CreateMemSet(
          DstP, IRB.CreateTrunc(Val, IRB.getInt8Ty()), Bytes, MaybeAlign(1),
          Volatile));
      CallInst *Fill = IRB.CreateCall(
          UF.UC.UCFillPatternFn,
          {DstP, IRB.CreateZExt(Val, IRB.getInt64Ty()), IRB.getInt64(K), Cnt});
      UF.UC.markNosanitize(Fill);
      Regs["di"] = IRB.CreateGEP(IRB.getInt8Ty(), DstP, Bytes);
      Regs["cx"] = ConstantInt::get(IRB.getInt64Ty(), 0);
      replaceWith(regResults(Regs));
      // the memset's destination is now the checked pointer
      Fill->setArgOperand(0, MS->getRawDest());
      return;
    }
  }

  // String moves through (%rsi) to (%rdi), which in a userspace run would
  // copy through the operands unchecked (a pseudo-pointer faulted:
  // arch/x86/lib/iomem.c's memcpy_toio/memcpy_fromio).  Lowered to memcpy,
  // advancing %rsi and %rdi past what was copied:
  // - one `movs{b,w,l,q}`, or `rep movs{b,w,l,q}` of %rcx elements, which
  //   leaves %rcx at 0 (the kernel's movs() and rep_movs pieces);
  // - iomem.c's rep_movs(): `rep movsl`, then a movsw if bit 1 of n is set
  //   and a movsb if bit 0 is, which together copy exactly n bytes -- n is
  //   the operand the two testb read.
  if (IsCall && !HasMemOutput) {
    auto movsSize = [](StringRef Mn) -> unsigned {
      if (!Mn.consume_front("movs") || Mn.size() != 1)
        return 0;
      switch (Mn[0]) {
      case 'b': return 1;
      case 'w': return 2;
      case 'l': return 4;
      case 'q': return 8;
      }
      return 0;
    };
    Value *Bytes = nullptr;
    bool Rep = false;
    StringMap<Value *> Regs = inputRegs();
    if (Insns.size() == 1) {
      StringRef Mn = Insns[0].Mnemonic;
      Rep = Mn.consume_front("rep ");
      unsigned K = movsSize(Mn);
      if (K && Insns[0].Operands.empty()) {
        if (!Rep) {
          Bytes = IRB.getInt64(K);
        } else if (Value *Cx = Regs.lookup("cx")) {
          Bytes = IRB.CreateMul(castAsmValue(IRB, DL, Cx, IRB.getInt64Ty()),
                                IRB.getInt64(K));
        }
      }
    } else if (Insns.size() == 7 && Insns[0].Mnemonic == "rep movsl" &&
               Insns[1].Mnemonic == "testb" && Insns[2].Mnemonic == "je" &&
               Insns[3].Mnemonic == "movsw" && Insns[4].Mnemonic == "testb" &&
               Insns[5].Mnemonic == "je" && Insns[6].Mnemonic == "movsb" &&
               Insns[1].Operands.size() == 2 && Insns[4].Operands.size() == 2 &&
               StringRef(Insns[1].Operands[0]).trim() == "$$2" &&
               StringRef(Insns[4].Operands[0]).trim() == "$$1" &&
               Insns[1].Operands[1] == Insns[4].Operands[1]) {
      int N = asmOperandRef(Insns[1].Operands[1]);
      if (N >= 0 && N < (int)Ops.size() && Ops[N].V &&
          Ops[N].V->getType()->isIntegerTy()) {
        Rep = true;
        Bytes = castAsmValue(IRB, DL, Ops[N].V, IRB.getInt64Ty());
      }
    }
    Value *Dst = Regs.lookup("di"), *Src = Regs.lookup("si");
    if (Bytes && Dst && Src) {
      Value *DstP = castAsmValue(IRB, DL, Dst, IRB.getPtrTy());
      Value *SrcP = castAsmValue(IRB, DL, Src, IRB.getPtrTy());
      IRB.CreateMemCpy(DstP, MaybeAlign(1), SrcP, MaybeAlign(1), Bytes,
                       Volatile);
      Regs["di"] = IRB.CreateGEP(IRB.getInt8Ty(), DstP, Bytes);
      Regs["si"] = IRB.CreateGEP(IRB.getInt8Ty(), SrcP, Bytes);
      if (Rep)
        Regs["cx"] = ConstantInt::get(IRB.getInt64Ty(), 0);
      replaceWith(regResults(Regs));
      return;
    }
  }

  // Calls into the kernel's assembly helpers, which have their own calling
  // conventions and so cannot become calls:
  // - __get_user_N / __get_user_nocheck_N: pointer in %rax, value out in
  //   %rdx, error out in %rax;
  // - __put_user_N / __put_user_nocheck_N: pointer in %rcx, value in %rax,
  //   error out in %rcx;
  // - this_cpu_cmpxchg16b_emu: cmpxchg16b of %rdx:%rax against the memory
  //   operand, with %rcx:%rbx as the new value (percpu; the harness's %gs
  //   base is 0, so the operand is the memory itself).
  if (IsCall && Insns.size() == 1 &&
      (Insns[0].Mnemonic == "call" || Insns[0].Mnemonic == "callq") &&
      Insns[0].Operands.size() == 1) {
    StringRef Sym = Insns[0].Operands[0];
    bool Get = Sym.consume_front("__get_user_");
    bool Put = !Get && Sym.consume_front("__put_user_");
    if (Get || Put) {
      Sym.consume_front("nocheck_");
      int N = asmOperandRef(Sym);
      ConstantInt *Size = N >= 0 && N < (int)Ops.size() && Ops[N].V
                              ? dyn_cast<ConstantInt>(Ops[N].V)
                              : nullptr;
      StringMap<Value *> Regs = inputRegs();
      Value *Ptr = Regs.lookup(Get ? "ax" : "cx");
      Value *Val = Put ? Regs.lookup("ax") : nullptr;
      if (Size && Ptr && (Get || Val)) {
        Type *Ty = IRB.getIntNTy(Size->getZExtValue() * 8);
        Value *P = castAsmValue(IRB, DL, Ptr, IRB.getPtrTy());
        if (Get) {
          LoadInst *L = IRB.CreateLoad(Ty, P);
          L->setVolatile(Volatile);
          Regs["dx"] = L;
          Regs["ax"] = ConstantInt::get(IRB.getInt64Ty(), 0);
        } else {
          StoreInst *St = IRB.CreateStore(castAsmValue(IRB, DL, Val, Ty), P);
          St->setVolatile(Volatile);
          Regs["cx"] = ConstantInt::get(IRB.getInt64Ty(), 0);
        }
        replaceWith(regResults(Regs));
        return;
      }
    }
    if (Sym == "this_cpu_cmpxchg16b_emu") {
      StringMap<Value *> Regs = inputRegs();
      int Mem = -1, Flag = -1;
      for (unsigned I = 0; I < Ops.size(); ++I) {
        if (Ops[I].CI->Type == InlineAsm::isOutput && Ops[I].isMem())
          Mem = I;
        if (Ops[I].Code == "{@ccz}")
          Flag = I;
      }
      Value *Ax = Regs.lookup("ax"), *Dx = Regs.lookup("dx");
      Value *Bx = Regs.lookup("bx"), *Cx = Regs.lookup("cx");
      if (Mem >= 0 && Flag >= 0 && Ax && Dx && Bx && Cx) {
        Type *I128 = IRB.getInt128Ty();
        auto pair = [&](Value *Hi, Value *Lo) {
          return IRB.CreateOr(
              IRB.CreateShl(castAsmValue(IRB, DL, Hi, I128), 64),
              castAsmValue(IRB, DL, Lo, I128));
        };
        // An atomic cmpxchg i128 needs cmpxchg16b in the target (+cx16);
        // without it LLVM would call a libatomic helper the kernel does not
        // link, and a load/compare/store is equivalent for the single thread
        // a UCSan run has.
        Value *Old, *Eq;
        StringRef Features =
            CB.getFunction()->getFnAttribute("target-features").getValueAsString();
        if (Features.contains("+cx16")) {
          AtomicCmpXchgInst *X = IRB.CreateAtomicCmpXchg(
              Ops[Mem].V, pair(Dx, Ax), pair(Cx, Bx), MaybeAlign(16),
              AtomicOrdering::SequentiallyConsistent,
              AtomicOrdering::SequentiallyConsistent);
          X->setVolatile(Volatile);
          Old = IRB.CreateExtractValue(X, 0);
          Eq = IRB.CreateExtractValue(X, 1);
        } else {
          LoadInst *L = IRB.CreateLoad(I128, Ops[Mem].V);
          L->setVolatile(Volatile);
          Old = L;
          Eq = IRB.CreateICmpEQ(Old, pair(Dx, Ax));
          StoreInst *St = IRB.CreateStore(
              IRB.CreateSelect(Eq, pair(Cx, Bx), Old), Ops[Mem].V);
          St->setVolatile(Volatile);
        }
        Regs["ax"] = IRB.CreateTrunc(Old, IRB.getInt64Ty());
        Regs["dx"] = IRB.CreateTrunc(IRB.CreateLShr(Old, 64), IRB.getInt64Ty());
        SmallVector<Value *, 4> Results = regResults(Regs);
        Results[Ops[Flag].Result] = Eq;
        replaceWith(Results);
        return;
      }
    }
  }

  // Next, handle inline assembly patterns using parsed constraints

  // Handle trap/crash instructions: ud2, int3, .byte 0x0f,0x0b, etc.
  // These have only clobber constraints and should be replaced with exit()
  bool IsTrap = AsmStr.find("ud2") != std::string::npos ||
                AsmStr.find(".byte 0x0f, 0x0b") != std::string::npos ||
                AsmStr.find("int3") != std::string::npos ||
                AsmStr.find("int $3") != std::string::npos ||
                AsmStr.find("hlt") != std::string::npos;
  // The kernel's BUG() and WARN() are a ud2 plus a __bug_table entry built
  // from "i" operands (_BUG_FLAGS: file, line, flags, entry size), so they
  // are never clobber-only.  With BUGFLAG_WARNING (bit 0 of flags) it is a
  // WARN, which the kernel's trap handler resumes from: the trap is dropped.
  // Anything else is a BUG and exits like the other traps.
  // (The WARN is not dropped silently: it becomes a call to ucsan_trace_warn
  // with its file, line and flags, which reports an EVENT_WARN and returns.)
  if (IsTrap && !allClobbers && IsCall &&
      AsmStr.find("__bug_table") != std::string::npos && Ops.size() >= 3 &&
      NumResults == 0) {
    auto *Flags = dyn_cast_or_null<ConstantInt>(Ops[2].V);
    if (Flags && (Flags->getZExtValue() & 1)) {
      Value *File = Ops[0].V && Ops[0].V->getType()->isPointerTy()
                        ? Ops[0].V
                        : Constant::getNullValue(UF.UC.VoidPtrTy);
      Value *Line = Ops[1].V && Ops[1].V->getType()->isIntegerTy()
                        ? IRB.CreateZExtOrTrunc(Ops[1].V, UF.UC.Int32Ty)
                        : ConstantInt::get(UF.UC.Int32Ty, 0);
      CallInst *Warn = IRB.CreateCall(
          UF.UC.UCTraceWarnFn,
          {File, Line, IRB.CreateZExtOrTrunc(Flags, UF.UC.Int32Ty)});
      UF.UC.markNosanitize(Warn);
      CB.eraseFromParent();
      return;
    }
    allClobbers = true;
  }
  if (allClobbers && IsTrap) {
    Value *Result = IRB.CreateCall(UF.UC.ExitFn,
                                   {ConstantInt::get(UF.UC.Int32Ty, 180)});
    UF.UC.markNosanitize(Result);
    CB.replaceAllUsesWith(Result);
    CB.eraseFromParent();
    return;
  }

  // An indirect far jump leaves the kernel for good: machine_real_restart's
  // "ljmpl *%0" into the real-mode trampoline.  Run natively it is a GP
  // fault; the run ends here instead, normally, since it is no bug.
  {
    SmallVector<AsmInsn, 4> Insns = asmExecutedInsns(AsmStr);
    if (Insns.size() == 1 && NumResults == 0 &&
        (Insns[0].Mnemonic == "ljmp" || Insns[0].Mnemonic == "ljmpl" ||
         Insns[0].Mnemonic == "ljmpq") &&
        Insns[0].Operands.size() == 1 &&
        StringRef(Insns[0].Operands[0]).trim().starts_with("*")) {
      Value *Result = IRB.CreateCall(UF.UC.ExitFn,
                                     {ConstantInt::get(UF.UC.Int32Ty, 0)});
      UF.UC.markNosanitize(Result);
      CB.replaceAllUsesWith(Result);
      CB.eraseFromParent();
      return;
    }
  }

  // sync_core()'s iret to self -- push %ss, %rsp, flags and %cs, `pushq $1f`,
  // iretq, `1:` -- only serializes the CPU, a control instruction with no
  // data flow, as cli or wbinvd are (see isAsmHwNoOp); its `pushq $1f` was
  // an R_X86_64_32S the PIE link refused (every function of
  // arch/x86/kernel/alternative.o).  It does nothing: an output tied to an
  // input -- %rsp, its ASM_CALL_CONSTRAINT -- keeps the input's value (zeroed,
  // the stack pointer was 0 after it), and its scratch output gets none.
  {
    SmallVector<AsmInsn, 8> Insns = asmExecutedInsns(AsmStr);
    if (any_of(Insns, [](const AsmInsn &I) {
          return I.Mnemonic == "iretq" || I.Mnemonic == "iret";
        }) &&
        !HasMemOutput) {
      StringMap<Value *> Regs = inputRegs();
      replaceWith(regResults(Regs));
      return;
    }
  }

  // Handle call/callq instructions in inline asm
  // Extract the callee symbol and route through normal call handling
  //
  // The executed instructions are followed as a small program over the
  // registers: `mov` into a register sets it, `call` becomes a call whose
  // arguments are read from the SysV argument registers (not from the order
  // the constraints happen to be written in) and whose result lands in %rax,
  // and moves of %rsp (switching to another stack, as call_on_irqstack does)
  // are ignored.  The asm's outputs are then the final register values.  The
  // new calls are ordinary calls, not nosanitize, so their argument and
  // return labels propagate.  An asm with anything else in it (an indirect
  // `call *$N`, other instructions, memory outputs) is left alone.
  bool HasCall = llvm::any_of(Insns, [](const AsmInsn &I) {
    return I.Mnemonic == "call" || I.Mnemonic == "callq";
  });
  SmallVector<AsmStep, 4> Steps;
  if (HasCall && IsCall && !HasMemOutput && planAsmCalls(Insns, Ops, Steps)) {
    // Resolve every callee before building anything: a symbol that is
    // neither in the module nor declared for the asm by declareAsmCallees
    // leaves the asm alone.
    SmallVector<FunctionCallee, 4> Callees;
    bool OK = true;
    for (auto &S : Steps) {
      if (S.Kind != AsmStep::Call)
        continue;
      FunctionCallee Callee;
      if (S.Indirect) {
        // typed when it is built, from the registers set by then
      } else if (S.Operand >= 0) {
        auto *Fn = cast<Function>(Ops[S.Operand].V->stripPointerCasts());
        Callee = FunctionCallee(Fn->getFunctionType(), Fn);
      } else if (Function *Fn = M->getFunction(S.Sym)) {
        // Look up the function in the module
        Callee = FunctionCallee(Fn->getFunctionType(), Fn);
      } else if (auto It = UF.UC.AsmCallees.find(S.Sym);
                 It != UF.UC.AsmCallees.end() && It->second) {
        // If not found, the symbol is only referenced in inline asm (the
        // kernel's ALTERNATIVE fallbacks such as __sw_hweight32), and was
        // declared for it by declareAsmCallees -- possibly replaced since by
        // its __external$ wrapper.
        auto *Fn = cast<Function>(&*It->second);
        Callee = FunctionCallee(Fn->getFunctionType(), Fn);
      } else if (!StringRef(S.Sym).starts_with("__SCT__")) {
        OK = false;
        break;
      }
      // A static call trampoline (preempt_enable's __SCT__preempt_schedule)
      // is emitted in assembly by the static call machinery and has no
      // definition to call: the call is dropped, as before (null callee).
      Callees.push_back(Callee);
    }

    if (OK) {
      StringMap<Value *> Regs = inputRegs();
      bool Emitted = false;
      unsigned NextCallee = 0;
      for (auto &S : Steps) {
        if (S.Kind == AsmStep::SetReg) {
          Regs[S.Reg] = Ops[S.Operand].V;
          continue;
        }
        if (S.Kind == AsmStep::CopyReg) {
          Regs[S.Reg] = Regs.lookup(S.Src);
          continue;
        }
        FunctionCallee Callee = Callees[NextCallee++];
        if (S.Indirect) {
          // The arguments are the argument registers set so far, in order,
          // and the result is %rax if the asm has it as an output.  The
          // pointer is loaded in IR, so an out-of-scope pv_ops is symbolized
          // and its slot called the way any indirect call is.
          SmallVector<Type *, 6> Params;
          for (const char *R : AsmArgRegs) {
            if (!Regs.lookup(R))
              break;
            Params.push_back(IRB.getInt64Ty());
          }
          bool HasRet = llvm::any_of(Ops, [](const AsmOp &O) {
            return O.Result >= 0 && O.Reg == "ax";
          });
          auto *FT = FunctionType::get(
              HasRet ? IRB.getInt64Ty() : IRB.getVoidTy(), Params, false);
          Value *FPtr = IRB.CreateLoad(IRB.getPtrTy(), Ops[S.Operand].V);
          Callee = FunctionCallee(FT, FPtr);
        }
        if (!Callee)
          continue;
        // Adjust args to match function signature
        FunctionType *FT = Callee.getFunctionType();
        SmallVector<Value *, 6> Args;
        for (unsigned I = 0; I < FT->getNumParams(); ++I) {
          Type *PT = FT->getParamType(I);
          Value *V = I < std::size(AsmArgRegs) ? Regs.lookup(AsmArgRegs[I])
                                               : nullptr;
          Args.push_back(V ? castAsmValue(IRB, DL, V, PT)
                           : Constant::getNullValue(PT));
        }
        // Replace inline asm with a direct call to the callee
        CallInst *NewCall = IRB.CreateCall(Callee, Args);
        Emitted = true;
        if (!NewCall->getType()->isVoidTy())
          Regs["ax"] = NewCall;
      }
      // If the inline asm has side effects (volatile), insert a compiler
      // barrier to preserve ordering before removing it
      if (!Emitted && Volatile) {
        auto *Barrier = InlineAsm::get(
            FunctionType::get(Type::getVoidTy(*UF.UC.Ctx), false),
            "", "~{memory}", true);
        auto *BarrierCall = IRB.CreateCall(Barrier);
        UF.UC.markNosanitize(BarrierCall);
      }
      replaceWith(regResults(Regs));
      return;
    }
  }

  // Lift what is left if it is plain integer code (see AsmLifter); what the
  // lifter does not accept is rolled back and runs as is.
  if ((IsCall || isa<CallBrInst>(CB)) && !Insns.empty() && !IsTrap) {
    Value *HwRead = UF.UC.AsmCallees.lookup(AsmHwReadFn);
    AsmLifter Lifter(IRB, DL, Ops, CB.getType(), Volatile, HwRead,
                     UF.UC.UCVmcsFieldFn);
    // section data, only for an asm that takes a label's address (`$1f`)
    StringMap<Constant *> SectionLabels;
    if (any_of(Insns, [](const AsmInsn &I) {
          return any_of(I.Operands, [](StringRef O) {
            return O.starts_with("$$") && O.size() > 3 &&
                   isDigit(O[2]) && (O.back() == 'f' || O.back() == 'b');
          });
        }))
      SectionLabels = asmSectionLabels(AsmStr, Ops, *M);
    Lifter.SectionLabels = &SectionLabels;
    // the globals of a lift that is rolled back
    auto dropSectionData = [&]() {
      SmallPtrSet<GlobalVariable *, 2> GVs;
      for (auto &L : SectionLabels)
        if (auto *GV = dyn_cast<GlobalVariable>(
                L.second->stripInBoundsConstantOffsets()))
          GVs.insert(GV);
      for (GlobalVariable *GV : GVs) {
        GV->removeDeadConstantUsers();
        if (GV->use_empty())
          GV->eraseFromParent();
      }
    };
    if (Lifter.lift(Insns) && Lifter.outputsKnown()) {
      // runtime calls: skipped by both passes, their pointer unlabeled (a
      // VMCS slot is a global, which check_pointer symbolizes)
      for (CallInst *RC : Lifter.RuntimeCalls) {
        UF.UC.markNosanitize(RC);
        UF.SkipInsts.insert(RC);
        UF.setShadow(RC, UF.UC.getZeroShadow(RC));
      }
      SmallVector<Value *, 4> Results(NumResults, nullptr);
      for (unsigned N = 0; N < Ops.size(); ++N)
        if (Ops[N].Result >= 0)
          Results[Ops[N].Result] = Lifter.output(N);
      replaceWith(Results);
      return;
    }
    while (CB.getPrevNode() != Before)
      CB.getPrevNode()->eraseFromParent();
    dropSectionData();
  }

  // What is left runs as is.  Its memory operands are checked like a load or
  // store of their elementtype: globals and allocas included, since
  // checkPointer is where a global is symbolized (before the asm, so its seed
  // value is in place when the asm reads it) and where an alloca is skipped.
  // The rule here used to be:
  // skip compile time constants and allocas
  // AllocaInst is excluded above, so this traces heap/global origins;
  // opaque pointers carry no pointee type on Arg itself.
  // which left globals unsymbolized until after the asm had written them,
  // and sized every other operand 0; the size is now the elementtype's.
  for (unsigned N = 0; N < Ops.size(); ++N) {
    AsmOp &Op = Ops[N];
    // only check indirect (memory) operands that are pointers
    if (!Op.isMem() || !Op.V->getType()->isPointerTy())
      continue;
    Value *Size = ConstantInt::get(UF.UC.Int64Ty, memSize(Op));
    uint32_t TypeID = UF.UC.getOrCreateTypeID(Op.ElemTy);
    // the alignment the instructions naming the operand need of it, as for a
    // register pointer below: `movaps %1, %%xmm0` with "m"(*p)
    uint64_t AlignBytes = 1;
    std::string Plain = "$" + std::to_string(N);
    std::string Braced = "${" + std::to_string(N) + ":";
    for (auto &I : Insns)
      for (auto &O : I.Operands)
        if (O == Plain || StringRef(O).starts_with(Braced))
          AlignBytes = std::max(AlignBytes, asmAccessAlign(I.Mnemonic, I.Operands));
    Value *Ptr = UF.checkPointer(Op.V, Size, true, IRB, TypeID,
                                 Align(AlignBytes)); // dereference pointer
    for (unsigned I = 0; I < CB.arg_size(); ++I)
      if (CB.getArgOperand(I) == Op.V)
        CB.setArgOperand(I, Ptr);
    Op.V = Ptr;
  }
  // A pointer passed in a register and dereferenced by the template itself,
  // `movl (%1), %0`, is checked too: the asm would otherwise see the
  // unmaterialized pointer.  Its size comes from the dereferencing
  // instruction.
  for (unsigned N = 0; N < Ops.size(); ++N) {
    AsmOp &Op = Ops[N];
    if (!Op.isValue() || !Op.V->getType()->isPointerTy() ||
        isa<Constant>(Op.V))
      continue;
    // An input tied to an output is named by the output's number in the
    // template: ip_fast_csum's "movl (%1), %0" with "1" (iph).  The size
    // reaches past the largest displacement, "adcl 16(%1), %0" reading
    // bytes 16..19.
    SmallVector<unsigned, 2> Names = {N};
    if (Op.TiedTo >= 0)
      Names.push_back(Op.TiedTo);
    uint64_t Size = 0;
    // the alignment the pointer itself needs: an aligned move at a
    // displacement that is a multiple of what it needs, else none.  The
    // runtime places the object for it (align_object in ucsan.cpp):
    // i915_unaligned_memcpy_from_wc rounds src up to 16 bytes by its pseudo
    // value and reads it with movntdqa.
    uint64_t AlignBytes = 1;
    bool Deref = false;
    for (unsigned Name : Names) {
      std::string Plain = "($" + std::to_string(Name) + ")";
      std::string Braced = "(${" + std::to_string(Name) + ":";
      // (and as the base of a base+index address, `($N,%rax)`:
      // vmx_l1d_flush's `movzbl (%[flush_pages], %rax), %ecx` read 64 KB at
      // the unchecked value of a pointer global.  The index is a register,
      // so the size is the access's at the base; the object grows as used.)
      std::string Indexed = "($" + std::to_string(Name) + ",";
      for (auto &I : Insns)
        for (auto &O : I.Operands) {
          size_t P = O.find(Plain);
          if (P == std::string::npos)
            P = O.find(Indexed);
          if (P == std::string::npos)
            P = O.find(Braced);
          if (P == std::string::npos)
            continue;
          Deref = true;
          uint64_t Disp = 0;  // none, or a negative one: 0
          if (StringRef(O).substr(0, P).trim().getAsInteger(0, Disp))
            Disp = 0;
          Size = std::max(Size, Disp + asmAccessSize(I.Mnemonic, I.Operands));
          uint64_t A = asmAccessAlign(I.Mnemonic, I.Operands);
          if (Disp % A == 0)
            AlignBytes = std::max(AlignBytes, A);
        }
    }
    if (!Deref)
      continue;
    Value *Ptr = UF.checkPointer(Op.V, ConstantInt::get(UF.UC.Int64Ty, Size),
                                 true, IRB, 0, Align(AlignBytes));
    for (unsigned I = 0; I < CB.arg_size(); ++I)
      if (CB.getArgOperand(I) == Op.V)
        CB.setArgOperand(I, Ptr);
    Op.V = Ptr;
  }

  // The asm writes its memory outputs concretely: whatever label the memory
  // held is stale afterwards, so its shadow is cleared, as a store of a
  // concrete value would.  (TaintPass does the same for the symbolic labels.)
  if (HasMemOutput) {
    SmallVector<Instruction *, 2> Positions;
    if (auto *CBr = dyn_cast<CallBrInst>(&CB)) {
      for (BasicBlock *Succ : successors(CBr))
        if (Succ->getSinglePredecessor())
          Positions.push_back(&*Succ->getFirstInsertionPt());
    } else if (CB.getNextNode()) {
      Positions.push_back(CB.getNextNode());
    }
    for (auto &Op : Ops) {
      if (Op.CI->Type != InlineAsm::isOutput || !Op.isMem() || !memSize(Op))
        continue;
      for (Instruction *Pos : Positions)
        UF.storeShadow(Op.V, memSize(Op), Align(1),
                       UF.UC.getZeroShadow(Op.ElemTy), Op.ElemTy, Pos);
    }
  }

  guardAsmIndirectCall(CB, Ops, Insns);
}

// `call *$N` through a register operand runs whatever the operand holds, and
// a symbolic one -- a function pointer the seed gave, which the C call
// through it would not make (visitIndirectCallBase) -- is the seed's value:
// x86_emulate_insn's fastop(ctxt, ctxt->fop) jumped to 0x4ff.  Such an asm
// runs only when the pointer has no UCSan label; otherwise it is skipped as
// an out-of-scope callee would be: its outputs in callee-saved registers
// (%rsp, %rbx, %rbp, %r12-%r15) and its pointer outputs keep their inputs,
// and the others take fresh symbolic values (AsmHwReadFn, as for a read of
// hardware state).
void UCSanVisitor::guardAsmIndirectCall(CallBase &CB, ArrayRef<AsmOp> Ops,
                                        ArrayRef<AsmInsn> Insns) {
  auto *Call = dyn_cast<CallInst>(&CB);
  if (!Call || !Call->getParent())
    return;
  int Target = -1;
  for (auto &I : Insns) {
    StringRef Mn = I.Mnemonic;
    if (!(Mn == "call" || Mn == "callq" || Mn == "jmp" || Mn == "jmpq") ||
        I.Operands.size() != 1)
      continue;
    StringRef O = StringRef(I.Operands[0]).trim();
    if (!O.consume_front("*"))
      continue;
    int N = asmOperandRef(O);
    if (N < 0 || N >= (int)Ops.size())
      continue;
    // `"+S"(fop)` names the output; its value is the input tied to it
    if (Ops[N].Result >= 0) {
      int In = -1;
      for (unsigned K = 0; K < Ops.size(); ++K)
        if (Ops[K].TiedTo == N)
          In = K;
      if (In < 0)
        continue;
      N = In;
    }
    if (Ops[N].isValue() && Ops[N].V->getType()->isPointerTy())
      Target = N;
  }
  if (Target < 0)
    return;
  Value *Shadow = UF.getShadow(Ops[Target].V);
  Value *HwRead = UF.UC.AsmCallees.lookup(AsmHwReadFn);
  if (UF.UC.isZeroShadow(Shadow) || !HwRead)
    return;

  Type *RT = Call->getType();
  SmallVector<Type *, 4> ResultTys;
  if (auto *ST = dyn_cast<StructType>(RT))
    ResultTys.append(ST->element_begin(), ST->element_end());
  else if (!RT->isVoidTy())
    ResultTys.push_back(RT);
  for (Type *T : ResultTys)
    if (!T->isIntegerTy() && !T->isPointerTy())
      return;

  auto *BBID = Call->getParent()->getTerminator()->getMetadata(BBIDName);
  IRBuilder<> IRB(Call);
  Value *Real = IRB.CreateICmpEQ(Shadow, UF.UC.ZeroPrimitiveShadow);
  UF.UC.markNosanitize(Real);
  Instruction *TB, *EB;
  SplitBlockAndInsertIfThenElse(Real, Call, &TB, &EB);
  Call->moveBefore(TB);
  BasicBlock *Tail = TB->getParent()->getSingleSuccessor();
  if (BBID) {
    TB->getParent()->getTerminator()->setMetadata(BBIDName, nullptr);
    EB->getParent()->getTerminator()->setMetadata(BBIDName, nullptr);
    Tail->getTerminator()->setMetadata(BBIDName, BBID);
  }

  // the skipped asm's results, visited here: the visitor has moved past them
  IRBuilder<> EIRB(EB);
  Instruction *Before = EB->getPrevNode();
  auto fresh = [&](Type *T) -> Value * {
    auto *FT = FunctionType::get(EIRB.getInt32Ty(), false);
    Value *Lo = EIRB.CreateZExt(EIRB.CreateCall(FT, HwRead), EIRB.getInt64Ty());
    Value *Hi = EIRB.CreateZExt(EIRB.CreateCall(FT, HwRead), EIRB.getInt64Ty());
    Value *V = EIRB.CreateOr(Lo, EIRB.CreateShl(Hi, 32));
    return EIRB.CreateTrunc(V, T);
  };
  auto calleeSaved = [](StringRef R) {
    return R == "sp" || R == "bx" || R == "bp" || R == "r12" || R == "r13" ||
           R == "r14" || R == "r15";
  };
  SmallVector<Value *, 4> Results(ResultTys.size(), nullptr);
  for (unsigned N = 0; N < Ops.size(); ++N) {
    int R = Ops[N].Result;
    if (R < 0)
      continue;
    Value *Tied = nullptr;
    for (auto &Op : Ops)
      if (Op.TiedTo == (int)N)
        Tied = Op.V;
    // or the input in the same register: fastop's ASM_CALL_CONSTRAINT is
    // "={rsp}" with a separate "{rsp}" input, and a fresh value there was
    // the stack pointer the kernel writes back (x86_emulate_insn hung)
    if (!Tied && !Ops[N].Reg.empty())
      for (auto &Op : Ops)
        if (Op.isValue() && Op.Result < 0 && Op.Reg == Ops[N].Reg)
          Tied = Op.V;
    Type *T = ResultTys[R];
    if ((calleeSaved(Ops[N].Reg) || T->isPointerTy()) && Tied &&
        Tied->getType() == T)
      Results[R] = Tied;
    else if (T->isPointerTy())
      Results[R] = Constant::getNullValue(T);
    else
      Results[R] = fresh(T);
  }
  Value *Skipped = nullptr;
  if (isa<StructType>(RT)) {
    Skipped = PoisonValue::get(RT);
    for (unsigned R = 0; R < Results.size(); ++R)
      Skipped = EIRB.CreateInsertValue(Skipped, Results[R], R);
  } else if (!RT->isVoidTy()) {
    Skipped = Results[0];
  }
  for (Instruction *I = Before ? Before->getNextNode() : &EB->getParent()->front();
       I && I != EB;) {
    Instruction *Next = I->getNextNode();
    visit(*I);
    I = Next;
  }
  if (Skipped) {
    PHINode *PN = PHINode::Create(RT, 2, "", &Tail->front());
    Call->replaceAllUsesWith(PN);
    PN->addIncoming(Call, Call->getParent());
    PN->addIncoming(Skipped, EB->getParent());
    visit(*PN);
  }
  UF.DT.recalculate(*UF.F);
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
  // Update dominator tree after block split
  UF.DT.recalculate(*UF.F);
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
        // Resign the whole underlying object (alloca/global) the pointer
        // points into, since opaque pointers no longer carry pointee type.
        Type *PointeeTy = getUnderlyingObjectType(Arg);
        uint64_t ObjSize = (PointeeTy && PointeeTy->isSized())
                                ? DL.getTypeAllocSize(PointeeTy) : 0;
        ConstantInt *CI = ConstantInt::get(UF.UC.Int64Ty, ObjSize);
        auto BCI = IRB_EB.CreateBitCast(Arg, UF.UC.VoidPtrTy); // FIXME: cast to i32* (defined as void *)
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
      // A pointer is loaded from the buffer like any other value, as the
      // dangle wrapper does (wrapRetvalRecursive).  The buffer's own address
      // used to stand in for it: never NULL, while the pointer's SymSan label
      // names the seed's bytes, so every NULL check on the result of a call
      // through an invalid function pointer was a value mismatch
      // (x86_pmu_event_init's x86_pmu.hw_config), and the NULL path was never
      // taken.
      Type *PRT = RT->getPointerTo();
      Ret = IRB_EB.CreatePointerCast(Ret, PRT);
      UF.UC.markNosanitize(Ret);
      Ret = IRB_EB.CreateLoad(RT, Ret);
      UF.UC.markNosanitize(Ret);
      retEB = Ret;
      if (RetPhiNode) RetPhiNode->addIncoming(retEB, IRB_EB.GetInsertBlock());
    }
  }

  if (RetPhiNode) {
    // Load return shadow from RetvalTLS at the merge point.
    // Both branches write their return shadow to RetvalTLS:
    //   then-block: callee writes it normally
    //   else-block: ucsan_wrap_retval writes it
    IRB.SetInsertPoint(RetPhiNode->getNextNonDebugInstruction());
    unsigned Size = DL.getTypeAllocSize(UF.UC.getShadowTy(RT));
    if (Size > kRetvalTLSSize) {
      UF.ValShadowMap[RetPhiNode] = UF.UC.getZeroShadow(RT);
    } else {
      LoadInst *LI = IRB.CreateAlignedLoad(
          UF.UC.getShadowTy(RT), UF.getRetvalTLS(RT, IRB),
          ShadowTLSAlignment, "_dfsret");
      UF.UC.markNosanitize(LI);
      UF.SkipInsts.insert(LI);
      UF.ValShadowMap[RetPhiNode] = LI;
      UF.NonZeroChecks.push_back(LI);
    }
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
  case UCSan::WK_ShimTarget:
    llvm_unreachable("WK_ShimTarget should not be in UnwrappedFnMap");
    return false;
  case UCSan::WK_ShimOrig:
  {
    // Redirect call to __shim_ function, let normal TLS path handle shadows
    std::string ShimName = "__shim_" + F->getName().str();
    FunctionCallee ShimF = UF.UC.Mod->getOrInsertFunction(ShimName, F->getFunctionType());
    CB.setCalledFunction(ShimF);
    return false;  // let caller handle arg/retval TLS
  }
  case UCSan::WK_AutoCustom:
    // invoke the custom function
    {
      // Only store shadows for fixed parameters, varargs are not tracked in TLS
      // FIXME: add vararg shadow tracking support
      unsigned NumFixedParams = FT->getNumParams();
      unsigned ArgOffset = 0;

      for (unsigned I = 0; I < NumFixedParams; ++I) {
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

      // For taint ref_names, the wrapper just forwards to the ref function
      // and TaintPass will handle the __dfsw_ wrapping via its own dfsan TLS.
      // Skip reading retval TLS in that case
      auto It = UF.UC.Scope.custom.find(F->getName().str());
      bool IsTaintRef = (It != UF.UC.Scope.custom.end()) &&
                        UF.UC.ABIList.isIn(It->second.ref_name, "taint");

      CB.setCalledFunction(UF.UC.getCustomFunction(F));
      if (!FT->getReturnType()->isVoidTy()) {
        if (IsTaintRef) {
          // No ucsan return shadow from the wrapper; set zero.
          UF.setShadow(&CB, UF.UC.getZeroShadow(&CB));
        } else {
          IRB.SetInsertPoint(CB.getNextNode());
          LoadInst *LI = IRB.CreateAlignedLoad(UF.UC.getShadowTy(&CB),
              UF.getRetvalTLS(CB.getType(), IRB),
              ShadowTLSAlignment, "_autoret");
          UF.UC.markNosanitize(LI);
          Shadow = LI;
          UF.setShadow(&CB, Shadow);
        }
      }
    }
    return true;

  case UCSan::WK_Discard:
    // Completely discarded, nothing to do
    return true;

  case UCSan::WK_Ignore:
    llvm_unreachable("WK_Ignore should be handled by external wrapper");
    return false;

  case UCSan::WK_TaintCustom:
  case UCSan::WK_Uninstrumented:
  {
    // TaintPass will handle the __dfsw_ wrapping with proper taint labels.
    // Just check pointer arguments here, skip ucsan arg/retval TLS.
    //
    // For memory/string functions, use type_id=0 (typeless bytes) and pass
    // the actual byte count to checkPointer so lazy init allocates enough.
    StringRef FName = F->getName();
    // Determine the length argument index from the abilist (sizeN category).
    // -1 means no explicit length (string functions: use size=0).
    int LenArgIdx = UF.UC.ABIList.getSizeArgIdx(FName);
    if (LenArgIdx == -1 && FName == "memmem") {
      LenArgIdx = -2;  // special: arg1 is len for arg0, arg3 is len for arg2
    }
    // All taint-listed functions are byte-typed mem/str fns; non-mem taint
    // fns like assert_cond/assume_cond have no pointer args so the predicate
    // is only consulted on pointer-arg paths anyway.
    bool IsMemOrStrFn = UF.UC.ABIList.isIn(*F, "taint");

    // Functions whose return value is a pointer into a pointer argument
    // (e.g. strchr/memchr return base+index). Capture the base arg's UC shadow
    // so we can translate the materialized result pointer back into UC pseudo
    // space after the call (see below).
    int RetPtrIdx = UF.UC.ABIList.getRetPtrArgIdx(FName);
    Value *RetPtrBaseShadow = nullptr;

    Value *LenVal = nullptr;
    if (LenArgIdx >= 0 && (unsigned)LenArgIdx < CB.arg_size()) {
      LenVal = IRB.CreateZExtOrTrunc(CB.getArgOperand(LenArgIdx), UF.UC.Int64Ty);
      UF.UC.markNosanitize(LenVal);
    }

    // Check copy semantics from abilist: copystr is unbounded (size determined
    // by strlen at runtime), so we need check_copy_bounds to enlarge the dst
    // symbolic obj. Bounded copies (memcpy/memmove/strncpy/strncat) have their
    // size in a sizeN entry; check_pointer handles enlargement directly.
    bool IsCopyStr = UF.UC.ABIList.isIn(*F, "copystr");

    Value *ResolvedDst = nullptr, *ResolvedSrc = nullptr;
    Value *DstShadow = nullptr, *SrcShadow = nullptr;
    Value *DstBound = ConstantInt::get(UF.UC.Int64Ty, 0);

    auto *I = CB.arg_begin();
    for (unsigned N = FT->getNumParams(); N != 0; ++I, --N) {
      unsigned ArgIdx = FT->getNumParams() - N;
      // skip nullptr
      if ((*I)->getType()->isPointerTy() && !isa<ConstantPointerNull>(*I)) {
        Value *sizeArg;
        uint32_t TypeID;
        if (IsMemOrStrFn) {
          TypeID = 0;  // typeless bytes
          if (LenArgIdx == -2) {
            // memmem: arg0 uses arg1 as len, arg2 uses arg3 as len
            unsigned MyLenIdx = (ArgIdx == 0) ? 1 : 3;
            if (MyLenIdx < CB.arg_size()) {
              sizeArg = IRB.CreateZExtOrTrunc(CB.getArgOperand(MyLenIdx), UF.UC.Int64Ty);
              UF.UC.markNosanitize(sizeArg);
            } else {
              sizeArg = ConstantInt::get(UF.UC.Int64Ty, 0);
            }
          } else if (LenVal) {
            sizeArg = LenVal;
          } else {
            sizeArg = ConstantInt::get(UF.UC.Int64Ty, 0);  // string fn, unknown length
          }
        } else {
          // Opaque pointers carry no pointee type on (*I) itself; trace back
          // to its underlying allocation instead.
          Type *PointeeTy = getUnderlyingObjectType(*I);
          if (PointeeTy && PointeeTy->isSized()) {
            sizeArg = ConstantInt::get(UF.UC.Int64Ty, DL.getTypeAllocSize(PointeeTy));
            TypeID = UF.UC.getOrCreateTypeID(PointeeTy);
          } else {
            sizeArg = ConstantInt::get(UF.UC.Int64Ty, 0);
          }
        }

        // Capture shadow before checkPointer resolves the pointer
        bool skipCheckPointer = false;
        if ((IsCopyStr || LenVal) && ArgIdx <= 1) {
          Value *Shadow = UF.getShadow(*I);
          if (ArgIdx == 0) {
            DstShadow = Shadow;
            // For GV destinations, shadow is zero but we know the size at compile time
            if (auto *GV = dyn_cast<GlobalVariable>((*I)->stripPointerCasts())) {
              Type *T = GV->getValueType();
              if (T && (T->isArrayTy() || T->isStructTy()) && T->isSized()) {
                DstBound = ConstantInt::get(UF.UC.Int64Ty, DL.getTypeAllocSize(T));
              }
            }
            if (isa<GlobalVariable>(getUnderlyingObject((*I)->stripPointerCasts()))) {
              // destination is part of aglobal variable, skip
              skipCheckPointer = true;
            }
          } else if (ArgIdx == 1) {
            SrcShadow = Shadow;
          }
        }

        // Capture the UC shadow of the base arg (before checkPointer resolves
        // the pointer) for return-pointer translation.
        if ((int)ArgIdx == RetPtrIdx)
          RetPtrBaseShadow = UF.getShadow(*I);

        Value *rptr = *I;
        if (!skipCheckPointer) {
          rptr = UF.checkPointer(*I, sizeArg, true, IRB, TypeID);
        }
        CB.setArgOperand(ArgIdx, rptr);

        // Capture resolved pointers for copy bounds check
        if (IsCopyStr && ArgIdx <= 1) {
          if (ArgIdx == 0) ResolvedDst = rptr;
          else if (ArgIdx == 1) ResolvedSrc = rptr;
        }
      }
    }

    // Emit copy bounds check for unbounded copies (size=strlen(src)).
    if (IsCopyStr && ResolvedDst && ResolvedSrc &&
        DstShadow && SrcShadow) {
      Value *DstAddr = IRB.CreateBitCast(ResolvedDst, UF.UC.VoidPtrTy);
      Value *SrcAddr = IRB.CreateBitCast(ResolvedSrc, UF.UC.VoidPtrTy);
      // (the casts are the ucsan_check_pointer calls themselves under opaque
      // pointers, and TaintPass must visit those; see RetArg below)
      if (DstAddr != ResolvedDst)
        UF.UC.markNosanitize(DstAddr);
      if (SrcAddr != ResolvedSrc)
        UF.UC.markNosanitize(SrcAddr);
      IRB.CreateCall(UF.UC.UCCheckCopyBoundsFn,
                     {DstAddr, DstShadow, SrcAddr, SrcShadow, DstBound});
    }

    if (!FT->getReturnType()->isVoidTy()) {
      if (RetPtrIdx >= 0 && FT->getReturnType()->isPointerTy() &&
          RetPtrBaseShadow) {
        // The result points into the materialized buffer (base+index in np).
        // Translate it back into the caller's UC pseudo space using the base
        // arg's UC shadow, so pointer arithmetic against the original arg
        // (e.g. p - c == index) is preserved. The symsan taint label is
        // carried separately through the __dfsw_ retval TLS (different shadow
        // memory), so rewriting the pointer value here does not affect it.
        IRBuilder<> AfterIRB(CB.getNextNode());
        // Only emit (and mark nosanitize) a cast when one is actually needed.
        // CreateBitCast returns &CB unchanged when the types already match, and
        // marking that nosanitize would suppress TaintPass on the real call.
        Value *RetArg = &CB;
        if (CB.getType() != UF.UC.VoidPtrTy) {
          RetArg = AfterIRB.CreateBitCast(&CB, UF.UC.VoidPtrTy);
          UF.UC.markNosanitize(RetArg);
        }
        CallInst *Unchecked = AfterIRB.CreateCall(
            UF.UC.UCUncheckPointerFn, {RetArg, RetPtrBaseShadow});
        // Do NOT mark the uncheck call nosanitize: TaintPass must visit it to
        // propagate the symsan taint label from arg 0 (mirrors how it treats
        // ucsan_check_pointer). nosanitize would suppress that propagation.
        Value *RetFixed = Unchecked;
        if (CB.getType() != Unchecked->getType()) {
          RetFixed = AfterIRB.CreateBitCast(Unchecked, CB.getType());
          UF.UC.markNosanitize(RetFixed);
        }
        // Redirect downstream uses to the UC pointer, but not the
        // bitcast/uncheck chain we just created.
        CB.replaceUsesWithIf(RetFixed, [&](Use &U) {
          User *user = U.getUser();
          return user != RetArg && user != Unchecked && user != RetFixed;
        });
        // The returned pointer aliases the base object and carries its UC shadow.
        if (Instruction *RetFixedI = dyn_cast<Instruction>(RetFixed))
          if (RetFixedI != &CB)
            UF.setShadow(RetFixedI, RetPtrBaseShadow);
        UF.setShadow(&CB, RetPtrBaseShadow);
      } else {
        // Set zero ucsan shadow for the return value; TaintPass sets the taint label.
        UF.setShadow(&CB, UF.UC.getZeroShadow(&CB));
      }
    }
    return true; // fully handled, skip normal arg/retval TLS stores
  }
  case UCSan::WK_Custom:
  {
    // Call the __dfsw_ wrapper with shadow arguments
    CallInst *CI = dyn_cast<CallInst>(&CB);
    if (!CI)
      return false;

    auto FName = F->getName();
    bool IsContractPrim = (FName).starts_with("assume_") || (FName).starts_with("assert_");

    TransformedFunction CustomFn = UF.UC.getCustomFunctionType(FT);
    std::string CustomFName = "__dfsw_" + FName.str();
    FunctionCallee CustomF =
        UF.UC.Mod->getOrInsertFunction(CustomFName, CustomFn.TransformedType);
    if (Function *CustomFnPtr = dyn_cast<Function>(CustomF.getCallee())) {
      CustomFnPtr->copyAttributesFrom(F);

      // Custom functions returning non-void will write to the return label.
      if (!FT->getReturnType()->isVoidTy()) {
        CustomFnPtr->removeFnAttrs(UF.UC.ReadOnlyNoneAttrs);
      }
      // mark as nosanitize
      UF.UC.markFunctionNosanitize(CustomFnPtr);
    }

    std::vector<Value *> Args;

    // A wrapper with a byte count (the abilist's sizeN: memcpy, memset,
    // _copy_from_user, ...) touches that many bytes behind each pointer
    // argument, so they are checked for it, as typeless bytes, like the
    // WK_TaintCustom case does.  With the pointee's size instead (0 for a
    // void * buffer) the size limit never saw the count, and the wrapper
    // copied it, data and both shadows: i915_gem_execbuffer2_ioctl's
    // copy_from_user of 1147569976 bytes from the seed went over 6 GB.
    int LenArgIdx = UF.UC.ABIList.getSizeArgIdx(FName);
    Value *LenVal = nullptr;
    if (LenArgIdx >= 0 && (unsigned)LenArgIdx < CB.arg_size()) {
      LenVal = IRB.CreateZExtOrTrunc(CB.getArgOperand(LenArgIdx),
                                     UF.UC.Int64Ty);
      if (LenVal != CB.getArgOperand(LenArgIdx))
        UF.UC.markNosanitize(LenVal);
    }

    // Adds non-variable arguments.
    auto *I = CB.arg_begin();
    for (unsigned N = FT->getNumParams(); N != 0; ++I, --N) {
      Type *T = (*I)->getType();
      if (isa<PointerType>(T) && !IsContractPrim) {
        // Check pointer arguments before passing to custom function.
        // Opaque pointers carry no pointee type on T itself; trace back
        // to the underlying allocation instead.
        auto DL = getDataLayout();
        Type *PointeeTy = getUnderlyingObjectType(*I);
        uint32_t TypeID = 0;
        uint64_t PointeeSize = 0;
        if (PointeeTy && PointeeTy->isSized()) {
          PointeeSize = DL.getTypeAllocSize(PointeeTy);
          TypeID = UF.UC.getOrCreateTypeID(PointeeTy);
        }
        Value *sizeArg = ConstantInt::get(UF.UC.Int64Ty, PointeeSize);
        if (LenVal) {
          sizeArg = LenVal;
          TypeID = 0;
        }
        Value *rptr = UF.checkPointer(*I, sizeArg, true, IRB, TypeID);
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

  // intrinsics are handled elsewhere
  if (F && F->isIntrinsic()) {
    return;
  }

  // A byval argument is copied by the caller, through the pointer: under UC a
  // pseudo-pointer, which faulted (mr_mfc_find_parent passes
  // *mrt->ops.rht_params, a struct rhashtable_params, by value).  Checked
  // for the copied type's size, as a memcpy source is, before the call and
  // before the copy.
  for (unsigned I = 0, N = CB.arg_size(); I != N; ++I) {
    if (!CB.isByValArgument(I))
      continue;
    Value *Arg = CB.getArgOperand(I);
    if (isa<AllocaInst>(Arg->stripPointerCasts()))
      continue;
    Type *Ty = CB.getParamByValType(I);
    if (!Ty || !Ty->isSized())
      continue;
    IRBuilder<> IRB(&CB);
    Value *Size = ConstantInt::get(UF.UC.Int64Ty,
                                   getDataLayout().getTypeAllocSize(Ty));
    CB.setArgOperand(I, UF.checkPointer(Arg, Size, true, IRB));
  }

  // Callee may call ucsan_resign_shadow which changes pointer state;
  // invalidate all cached check_pointer results so subsequent accesses
  // go through ucsan_check_pointer again for lazy re-initialization.
  UF.CheckedPtrMap.clear();

  if (!F) {
    // An indirect call may reach a function that has a wrapper, whose
    // pointer arguments the wrapped call path checks and an indirect call
    // does not: __write_relocate_add's write(loc, &val, size) with write =
    // memcpy handed __dfsw_memcpy the unmaterialized loc.  So each wrapped
    // function the module takes the address of, of the call's type, gets a
    // direct call of its own, taken when the pointer is it.
    SmallVector<Function *, 2> Wrapped;
    for (auto &KV : UF.UC.UnwrappedFnMap)
      if (auto *W = dyn_cast<Function>(KV.first))
        if (W->getFunctionType() == CB.getFunctionType() &&
            W->hasAddressTaken(nullptr, /*IgnoreCallbackUses=*/false,
                               /*IgnoreAssumeLikeCalls=*/true,
                               /*IgnoreLLVMUsed=*/true) &&
            isLegalToPromote(CB, W))
          Wrapped.push_back(W);
    llvm::sort(Wrapped, [](Function *A, Function *B) {
      return A->getName() < B->getName();
    });
    for (Function *W : Wrapped) {
      CallBase &Direct = promoteCallWithIfThenElse(CB, W);
      UF.DT.recalculate(*UF.F);
      SmallVector<PHINode *, 1> Phis;
      for (User *U : Direct.users())
        if (auto *Phi = dyn_cast<PHINode>(U))
          Phis.push_back(Phi);
      visit(Direct);
      for (PHINode *Phi : Phis)
        visit(*Phi);
    }
    // indirect call
    visitIndirectCallBase(CB.getCalledOperand(), CB);
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
  if (F && F->hasName() && !(F->getName()).starts_with("__dfsan") &&
      !(F->getName()).starts_with("__taint")) {
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

  // An out-of-scope callee resigns its pointer arguments (-r, see
  // buildDangleFunction), but its stub sees only the fixed ones: a variadic
  // argument's type and shadow do not reach it.  So a pointer passed as one
  // is resigned here, after the call, which is where the stub's resigning
  // happens from the caller's view.  sld_state_setup's
  // sscanf(arg, "ratelimit:%d", &ratelimit) == 1 left ratelimit marked
  // uninitialized, and its read was a UBI report on every seed taking it.
  if (F && FT->isVarArg() && UF.UC.ResigningStubs.count(F) &&
      !(isa<CallInst>(CB) && cast<CallInst>(CB).isMustTailCall())) {
    // after the return value's shadow load, if any (it is right before Next)
    Instruction *After = Next;
    if (!After) {
      if (auto *II = dyn_cast<InvokeInst>(&CB)) {
        if (II->getNormalDest()->getSinglePredecessor())
          After = &*II->getNormalDest()->getFirstInsertionPt();
      } else {
        After = CB.getNextNode();
      }
    }
    for (unsigned I = FT->getNumParams(), N = CB.arg_size();
         After && I != N; ++I) {
      Value *Arg = CB.getArgOperand(I);
      if (!Arg->getType()->isPointerTy() || isa<Constant>(Arg))
        continue;
      IRBuilder<> AfterIRB(After);
      Type *PointeeTy = getUnderlyingObjectType(Arg);
      uint64_t ObjSize = (PointeeTy && PointeeTy->isSized())
                             ? DL.getTypeAllocSize(PointeeTy) : 0;
      // the shadow is handed over in the (free, after the call) arg TLS
      Value *ArgTLS = UF.getArgTLS(Arg->getType(), 0, AfterIRB);
      StoreInst *SI = AfterIRB.CreateAlignedStore(UF.getShadow(Arg), ArgTLS,
                                                  ShadowTLSAlignment);
      UF.UC.markNosanitize(SI);
      CallInst *Call = AfterIRB.CreateCall(
          UF.UC.UCResignShadowFn,
          {AfterIRB.CreatePointerCast(Arg, UF.UC.VoidPtrTy), ArgTLS,
           ConstantInt::get(UF.UC.Int64Ty, ObjSize),
           ConstantPointerNull::get(UF.UC.VoidPtrTy)});
      UF.UC.markNosanitize(Call);
    }
  }
}

void UCSanVisitor::visitCastInst(CastInst &CI) {
  // Propagate shadow through cast
  Value *Shadow = UF.getShadow(CI.getOperand(0));
  // A pointer made of an integer is one the program could have loaded: the
  // runtime makes a pointer label of seed bytes, as a pointer load does, or
  // of an unlabeled address that is no memory of ours (ucsan_int_to_pointer).
  // Not of a constant: the kernel's are sentinels (ERR_PTR, LIST_POISON),
  // which must fault when dereferenced, not become objects.
  Value *Op = CI.getOperand(0);
  if (isa<IntToPtrInst>(CI) && !isa<Constant>(Op) &&
      Op->getType()->isIntegerTy() &&
      Op->getType()->getIntegerBitWidth() <= 64) {
    IRBuilder<> IRB(&CI);
    Value *V = IRB.CreateZExtOrTrunc(Op, UF.UC.Int64Ty);
    if (V != Op)
      UF.UC.markNosanitize(V);
    unsigned Width = (Op->getType()->getIntegerBitWidth() + 7) / 8;
    CallInst *Label = IRB.CreateCall(
        UF.UC.UCIntToPointerFn,
        {V, Shadow, ConstantInt::get(UF.UC.Int64Ty, Width)});
    Label->addRetAttr(Attribute::ZExt);
    UF.UC.markNosanitize(Label);
    Shadow = Label;
  }
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
  } else {
    // for void return, clean the tls return value shadow to zero
    // store void* enough?
    Type *RT = UF.UC.VoidPtrTy;
    unsigned Size = getDataLayout().getTypeAllocSize(UF.UC.getShadowTy(RT));
    if (Size <= kRetvalTLSSize) {
      StoreInst *SI = IRB.CreateAlignedStore(UF.UC.getZeroShadow(RT),
          UF.getRetvalTLS(RT, IRB), ShadowTLSAlignment);
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
  uint32_t TypeID = UF.UC.getOrCreateTypeID(Ty);

  IRBuilder<> IRB(&I);
  Ptr = UF.checkPointer(Ptr, Size, true, IRB, TypeID, I.getAlign());
  I.setOperand(0, Ptr);

  // FIXME: AtomicRMWInst should not operate on ptrs
  UF.setShadow(&I, UF.UC.ZeroPrimitiveShadow);

  I.setMetadata("ucsan.checked", MDNode::get(*UF.UC.Ctx, std::nullopt));
}

void UCSanVisitor::visitAtomicCmpXchgInst(AtomicCmpXchgInst &I) {
  auto &DL = I.getModule()->getDataLayout();
  Value *Ptr = I.getPointerOperand();
  Type *Ty = I.getNewValOperand()->getType();
  unsigned StoreSize = DL.getTypeStoreSize(Ty);
  ConstantInt *Size = ConstantInt::get(UF.UC.Int64Ty, StoreSize);
  uint32_t TypeID = UF.UC.getOrCreateTypeID(Ty);

  IRBuilder<> IRB(&I);
  Ptr = UF.checkPointer(Ptr, Size, true, IRB, TypeID, I.getAlign());
  I.setOperand(0, Ptr);

  // The result is { Ty old_value, i1 success }; like AtomicRMWInst we only
  // bounds-check the pointer here and do not propagate a symbolic result.
  UF.setShadow(&I, UF.UC.getZeroShadow(&I));

  I.setMetadata("ucsan.checked", MDNode::get(*UF.UC.Ctx, std::nullopt));
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
      if (allocaSizeInBits) {
        int allocaSizeInBytes = (allocaSizeInBits->getFixedValue() + 7) >> 3;
        Value* Size = ConstantInt::get(UF.UC.Int64Ty, allocaSizeInBytes);
        Value* Ptr = IRB.CreateBitOrPointerCast(&I, UF.UC.VoidPtrTy);
        if (Ptr != &I) { UF.UC.markNosanitize(Ptr); }
        CallInst *CI = IRB.CreateCall(UF.UC.UCSetLabelFn, {UF.UC.UninitPrimitiveShadow, Ptr, Size});
        UF.UC.markNosanitize(CI);
      }
    }
  }

  // Due to opaque ptrs, track bounds for all allocations
  {
    // Insert after the alloca instruction to get the address
    BasicBlock::iterator ip(&I);
    IRBuilder<> IRB(I.getParent(), ++ip);

    // Get array size, if any
    Value *Size = IRB.CreateZExtOrTrunc(I.getArraySize(), UF.UC.Int64Ty);
    if (Size != I.getArraySize()) {
      UF.UC.markNosanitize(Size);
    }

    // Get element size, if known
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

// `p - q` for T *p, *q: clang emits sdiv exact (sub (ptrtoint p),
// (ptrtoint q)), sizeof(T) -- ashr exact for a power of two -- because C
// defines it only for pointers into the same array, which makes the byte
// difference a multiple of sizeof(T).  Matches that, giving p, q and
// sizeof(T).
static bool matchPointerDiffIndex(BinaryOperator &BO, Value *&P, Value *&Q,
                                  uint64_t &Elem) {
  if (!BO.isExact() || !BO.getType()->isIntegerTy(64))
    return false;
  auto *C = dyn_cast<ConstantInt>(BO.getOperand(1));
  if (!C)
    return false;
  if (BO.getOpcode() == Instruction::SDiv) {
    if (C->isNegative() || C->isZero() || C->isOne())
      return false;
    Elem = C->getZExtValue();
  } else if (BO.getOpcode() == Instruction::AShr) {
    if (C->getZExtValue() == 0 || C->getZExtValue() >= 63)
      return false;
    Elem = 1ULL << C->getZExtValue();
  } else {
    return false;
  }
  auto *Sub = dyn_cast<BinaryOperator>(BO.getOperand(0));
  if (!Sub || Sub->getOpcode() != Instruction::Sub)
    return false;
  // (now: gives the subtraction's operands, the integers of p and q, which
  // visitBinaryOperator checks are pointers' -- a ptrtoint, or loaded from
  // where the module keeps pointers, UCSan::isPointerInt -- since the
  // optimizer folds ptrtoint (inttoptr x) to x)
  P = Sub->getOperand(0);
  Q = Sub->getOperand(1);
  return true;
}

void UCSanVisitor::visitBinaryOperator(BinaryOperator &BO) {
  // The element index of two UC pointers that are not known to be related.
  // Under UC that is the common case where the program assumes they are:
  // counter_show's `attr - counter_attrs` gets attr, an argument, and
  // counter_attrs, a global, as two independent roots, though attr is
  // &counter_attrs[i] in every real call.  Their pseudo-pointers then have
  // a difference that is any number, and sdiv exact of a non-multiple is
  // poison -- codegen multiplies by the divisor's inverse, the solver
  // divides, and every branch on the index was a value mismatch.  What the
  // program means is i, the element index: a fresh symbolic value, and the
  // runtime binds p into q's object at element i (__dfsw_ucsan_ptr_index).
  // Once bound, p and q are two pointer labels of one object, whose
  // pseudo-pointers still have unrelated bases: their index is the
  // difference of their offsets in the object, i again, and the runtime
  // gives that too.  Pointers that are related -- real ones, or the same
  // label -- keep the index the program computes, and its SymSan label: the
  // select.
  // A difference whose integers are not ptrtoints but come from where the
  // module keeps pointers is one too (see UCSan::collectPointerSlots): i915's
  // `(page_link & ~3) - vmemmap_base`, sg_page() then page_to_pfn() once
  // the optimizer has folded the pointers away.  Its pointers are the
  // integers, labeled as an inttoptr labels them (ucsan_int_to_pointer) --
  // before BO: that records them as a placement, which BO's poison check
  // asks about.
  Value *P, *Q;
  uint64_t Elem;
  if (matchPointerDiffIndex(BO, P, Q, Elem) && UF.UC.isPointerInt(P) &&
      UF.UC.isPointerInt(Q)) {
    Value *LP, *LQ;
    auto PointerOf = [&](Value *&V, Value *&L) {
      if (auto *PI = dyn_cast<PtrToIntOperator>(V)) {
        V = PI->getPointerOperand();
        L = UF.getShadow(V);
        return;
      }
      IRBuilder<> Before(&BO);
      CallInst *Label = Before.CreateCall(
          UF.UC.UCIntToPointerFn,
          {V, UF.getShadow(V), ConstantInt::get(UF.UC.Int64Ty, 8)});
      Label->addRetAttr(Attribute::ZExt);
      UF.UC.markNosanitize(Label);
      UF.setShadow(Label, UF.UC.getZeroShadow(Label));
      Value *Ptr = Before.CreateIntToPtr(V, UF.UC.VoidPtrTy);
      if (auto *PtrI = dyn_cast<Instruction>(Ptr)) {
        UF.UC.markNosanitize(PtrI);
        UF.setShadow(PtrI, Label);
      }
      V = Ptr;
      L = Label;
    };
    PointerOf(P, LP);
    PointerOf(Q, LQ);
    IRBuilder<> IRB(BO.getNextNode());
    Value *PV = IRB.CreatePointerCast(P, UF.UC.VoidPtrTy);
    Value *QV = IRB.CreatePointerCast(Q, UF.UC.VoidPtrTy);
    if (PV != P) UF.UC.markNosanitize(PV);
    if (QV != Q) UF.UC.markNosanitize(QV);
    CallInst *Rewrite =
        IRB.CreateCall(UF.UC.UCPtrDiffRewriteFn, {PV, LP, QV, LQ});
    UF.UC.markNosanitize(Rewrite);
    CallInst *Fresh = IRB.CreateCall(
        UF.UC.UCPtrIndexFn,
        {Rewrite, ConstantInt::get(UF.UC.Int64Ty, Elem), PV, QV, LP, LQ});
    UF.UC.markNosanitize(Fresh);
    Value *Index = IRB.CreateSelect(Rewrite, Fresh, &BO);
    BO.replaceUsesWithIf(Index, [Index](Use &U) { return U.getUser() != Index; });
    // the visitor does not reach what is inserted after BO
    UF.setShadow(Rewrite, UF.UC.getZeroShadow(Rewrite));
    UF.setShadow(Fresh, UF.UC.getZeroShadow(Fresh));
    if (auto *SI = dyn_cast<Instruction>(Index))
      UF.setShadow(SI, UF.UC.getZeroShadow(SI));
  }

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

// An aggregate's shadow has its shape (getShadowTy), element by element.
// Without these an extractvalue's shadow was zero: get_user's lowered load
// (rseq_get_rseq_cs's `ptr`, the seed's bytes) lost its label in the
// { ptr, i64, i64 } the lowering rebuilds the asm's results in, and the
// pointer later made of it was taken for a real one.
void UCSanVisitor::visitInsertValueInst(InsertValueInst &I) {
  Value *AggShadow = UF.getShadow(I.getAggregateOperand());
  Value *ElemShadow = UF.getShadow(I.getInsertedValueOperand());
  if (UF.UC.isZeroShadow(AggShadow) && UF.UC.isZeroShadow(ElemShadow)) {
    UF.setShadow(&I, UF.UC.getZeroShadow(&I));
    return;
  }
  IRBuilder<> IRB(&I);
  Value *S = IRB.CreateInsertValue(AggShadow, ElemShadow, I.getIndices());
  if (auto *SI = dyn_cast<Instruction>(S))
    UF.UC.markNosanitize(SI);
  UF.setShadow(&I, S);
}

void UCSanVisitor::visitExtractValueInst(ExtractValueInst &I) {
  Value *AggShadow = UF.getShadow(I.getAggregateOperand());
  if (UF.UC.isZeroShadow(AggShadow)) {
    UF.setShadow(&I, UF.UC.getZeroShadow(&I));
    return;
  }
  IRBuilder<> IRB(&I);
  Value *S = IRB.CreateExtractValue(AggShadow, I.getIndices());
  if (auto *SI = dyn_cast<Instruction>(S))
    UF.UC.markNosanitize(SI);
  UF.setShadow(&I, S);
}

void UCSanVisitor::visitPHINode(PHINode &PN) {
  Type *ShadowTy = UF.UC.getShadowTy(PN.getType());
  PHINode *ShadowPN =
      PHINode::Create(ShadowTy, PN.getNumIncomingValues(), "", &PN);

  // Give the shadow phi node valid predecessors to fool SplitEdge into working.
  Value *UndefShadow = UndefValue::get(ShadowTy);
  for (auto i = PN.block_begin(), e = PN.block_end(); i != e;
       ++i) {
    ShadowPN->addIncoming(UndefShadow, *i);
  }

  UF.PHIFixups.push_back({&PN, ShadowPN});
  UF.setShadow(&PN, ShadowPN);
}

void UCSanVisitor::visitUnreachableInst(UnreachableInst &I) {
  IRBuilder<> IRB(&I);
  Value *ExitCall = IRB.CreateCall(UF.UC.ExitFn,
                                   {ConstantInt::get(UF.UC.Int32Ty, 0)});
  UF.UC.markNosanitize(ExitCall);
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

  // Initialize builtin type IDs (fixed across modules)
  initBuiltinTypeIDs();

  // Load existing type table (for multi-file compilation)
  loadTypeTable();

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

static bool mentionsSymbol(StringRef Text, StringRef Sym) {
  auto IsIdent = [](char C) {
    return isAlnum(C) || C == '_' || C == '.' || C == '$';
  };
  for (size_t Pos = Text.find(Sym); Pos != StringRef::npos;
       Pos = Text.find(Sym, Pos + 1)) {
    size_t End = Pos + Sym.size();
    if ((Pos == 0 || !IsIdent(Text[Pos - 1])) &&
        (End == Text.size() || !IsIdent(Text[End])))
      return true;
  }
  return false;
}

// Functions a top-level asm() block defines in .text that nothing the scope
// keeps refers to any more: their callers were out of scope and became
// __external$ stubs.  Such asm still gets assembled, and kernel asm addresses
// globals absolutely -- kvm.c's __raw_callee_save___kvm_vcpu_is_preempted
// does "movq __per_cpu_offset(,%rdi,8)", an R_X86_64_32S the PIE link
// refuses, so every function of arch/x86/kernel/kvm.o failed to link.  Drop
// the .pushsection/.popsection block when every label in it is unreferenced.
// A function written straight into .text, from `.type X, @function` to
// `.size X`, is dropped the same way: rethook.c's arch_rethook_trampoline
// does "pushq $arch_rethook_trampoline", and once its C users are stubs that
// self-reference is all that is left of it.
static void dropUnreferencedAsmFunctions(Module &M) {
  std::string Asm = M.getModuleInlineAsm();
  if (Asm.empty())
    return;
  SmallVector<StringRef, 64> Lines;
  StringRef(Asm).split(Lines, '\n');

  // [first, last] line of each top-level .text push/pop block
  SmallVector<std::pair<size_t, size_t>, 4> Regions;
  size_t Depth = 0, Start = 0;
  bool IsText = false;
  auto IsTextSection = [](StringRef Sec) {
    Sec = Sec.trim().split(',').first.trim().trim('"');
    return Sec == ".text" || Sec.starts_with(".text.");
  };
  // the section top-level code is in, and the open `.type X, @function`
  bool TopIsText = true;
  StringRef Func;
  size_t FuncStart = 0;
  for (size_t I = 0; I < Lines.size(); ++I) {
    StringRef L = Lines[I].trim();
    if (L.consume_front(".pushsection")) {
      if (Depth++ == 0) {
        IsText = IsTextSection(L);
        Start = I;
      }
    } else if (L.starts_with(".popsection") && Depth > 0) {
      if (--Depth == 0 && IsText)
        Regions.push_back({Start, I});
    } else if (Depth > 0) {
      continue;
    } else if (L == ".text") {
      TopIsText = true;
    } else if (L.starts_with(".data") || L.starts_with(".bss") ||
               L.starts_with(".rodata")) {
      TopIsText = false;
      Func = StringRef();
    } else if (L.consume_front(".section")) {
      TopIsText = IsTextSection(L);
      Func = StringRef();
    } else if (L.consume_front(".type")) {
      auto [Name, Kind] = L.split(',');
      if (TopIsText && Kind.trim() == "@function") {
        Func = Name.trim();
        FuncStart = I;
      }
    } else if (L.consume_front(".size") && !Func.empty() &&
               L.split(',').first.trim() == Func) {
      Regions.push_back({FuncStart, I});
      Func = StringRef();
    }
  }
  if (Regions.empty())
    return;

  std::vector<StringRef> InlineAsms;
  for (Function &F : M)
    for (Instruction &I : instructions(F))
      if (auto *CB = dyn_cast<CallBase>(&I))
        if (auto *IA = dyn_cast<InlineAsm>(CB->getCalledOperand()))
          InlineAsms.push_back(IA->getAsmString());

  // `.globl X` and friends name a symbol without referring to it; the lines
  // naming a dropped label go with it
  auto SymbolDirective = [&](size_t I, StringRef Sym) {
    StringRef L = Lines[I].trim();
    for (StringRef D : {".globl", ".global", ".weak", ".hidden", ".local",
                        ".type", ".size"})
      if (L.consume_front(D) && !L.empty() && isSpace(L[0]))
        return L.trim().split(',').first.trim() == Sym;
    return false;
  };

  DenseSet<size_t> Dropped;
  for (auto [First, Last] : Regions) {
    SmallVector<StringRef, 4> Labels;
    for (size_t I = First; I <= Last; ++I) {
      SmallVector<StringRef, 4> Stmts;
      Lines[I].split(Stmts, ';');
      for (StringRef S : Stmts) {
        S = S.trim();
        if (!S.consume_back(":") || S.empty() || S.starts_with(".L") ||
            isDigit(S[0]) ||
            S.find_first_not_of("abcdefghijklmnopqrstuvwxyz"
                                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.$") !=
                StringRef::npos)
          continue;
        Labels.push_back(S);
      }
    }
    if (Labels.empty())
      continue;
    auto Referenced = [&](StringRef Sym) {
      if (GlobalValue *GV = M.getNamedValue(Sym))
        if (!GV->isDeclaration() || !GV->use_empty())
          return true;
      for (size_t I = 0; I < Lines.size(); ++I)
        if ((I < First || I > Last) && mentionsSymbol(Lines[I], Sym) &&
            !SymbolDirective(I, Sym))
          return true;
      for (StringRef A : InlineAsms)
        if (mentionsSymbol(A, Sym))
          return true;
      return false;
    };
    if (llvm::any_of(Labels, Referenced))
      continue;
    for (size_t I = First; I <= Last; ++I)
      Dropped.insert(I);
    for (StringRef Sym : Labels)
      for (size_t I = 0; I < Lines.size(); ++I)
        if (SymbolDirective(I, Sym))
          Dropped.insert(I);
  }
  if (Dropped.empty())
    return;

  std::string Kept;
  for (size_t I = 0; I < Lines.size(); ++I) {
    if (Dropped.count(I))
      continue;
    Kept += Lines[I];
    Kept += '\n';
  }
  M.setModuleInlineAsm(Kept);
}

// A code template a top-level asm() block keeps as data (.rodata), for the
// kernel to copy and patch -- callthunks.c's skl_call_thunk_template, `sarq
// $5, %gs:pcpu_hot + 16` -- addresses a percpu symbol absolutely, an
// R_X86_64_32S the PIE link refuses, and every function of
// arch/x86/kernel/callthunks.o failed to link.  Never run in place, its
// percpu offsets name nothing in a userspace run: they become 0, which keeps
// the encoding (a 32-bit displacement) and so the template's length.
static void zeroPercpuInAsmData(Module &M) {
  std::string Asm = M.getModuleInlineAsm();
  if (Asm.find("%gs:") == std::string::npos)
    return;
  SmallVector<StringRef, 64> Lines;
  StringRef(Asm).split(Lines, '\n');
  std::string Out;
  bool Changed = false;
  size_t Depth = 0;
  bool InData = false;
  auto IsIdent = [](char C) { return isAlnum(C) || C == '_' || C == '.'; };
  for (StringRef Line : Lines) {
    StringRef L = Line.trim();
    if (L.consume_front(".pushsection")) {
      if (Depth++ == 0) {
        StringRef Sec = L.trim().split(',').first.trim().trim('"');
        InData = !(Sec == ".text" || Sec.starts_with(".text."));
      }
    } else if (L.starts_with(".popsection") && Depth > 0) {
      if (--Depth == 0)
        InData = false;
    }
    std::string Text = Line.str();
    if (InData) {
      for (size_t Pos = Text.find("%gs:"); Pos != std::string::npos;
           Pos = Text.find("%gs:", Pos + 4)) {
        size_t B = Pos + 4, E = B;
        while (E < Text.size() && Text[E] == ' ')
          ++E;
        size_t S = E;
        if (S < Text.size() && (isAlpha(Text[S]) || Text[S] == '_')) {
          while (E < Text.size() && IsIdent(Text[E]))
            ++E;
          Text.replace(B, E - B, "0");
          Changed = true;
        }
      }
    }
    Out += Text;
    Out += '\n';
  }
  if (Changed)
    M.setModuleInlineAsm(Out);
}

// The integer a pointer kept as one is, under the arithmetic the kernel does
// on it: tag bits masked off or set (sg_page's `page_link & ~3`), a constant
// offset added.  (Only used to find where the integer came from.)
static Value *stripPointerIntArith(Value *V) {
  for (unsigned Depth = 0; Depth < 8; ++Depth) {
    auto *BO = dyn_cast<BinaryOperator>(V);
    if (!BO)
      return V;
    switch (BO->getOpcode()) {
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Xor:
    case Instruction::Add:
    case Instruction::Sub:
      break;
    default:
      return V;
    }
    if (isa<ConstantInt>(BO->getOperand(1)))
      V = BO->getOperand(0);
    else if (isa<ConstantInt>(BO->getOperand(0)) &&
             BO->getOpcode() != Instruction::Sub)
      V = BO->getOperand(1);
    else
      return V;
  }
  return V;
}

// The struct type B points to, as the IR uses it: a GEP's result, or the one
// struct type that GEPs from B index (opaque pointers carry no pointee type).
static StructType *pointeeStruct(Value *B) {
  if (auto *GEP = dyn_cast<GEPOperator>(B))
    if (auto *ST = dyn_cast<StructType>(GEP->getResultElementType()))
      return ST;
  StructType *Found = nullptr;
  for (User *U : B->users()) {
    auto *GEP = dyn_cast<GEPOperator>(U);
    if (!GEP || GEP->getPointerOperand() != B)
      continue;
    auto *ST = dyn_cast<StructType>(GEP->getSourceElementType());
    if (!ST)
      continue;
    if (Found && Found != ST)
      return nullptr;
    Found = ST;
  }
  return Found;
}

// The memory Addr names, as a pointer slot's key: a global and the offset
// into it, or a struct type and the offset into one (modulo its size: an
// element of an array of them).
std::optional<UCSan::PointerSlot> UCSan::slotOf(Value *Addr) {
  const DataLayout &DL = Mod->getDataLayout();
  APInt Off(64, 0);
  Value *B = Addr->stripAndAccumulateConstantOffsets(DL, Off, true);
  int64_t O = Off.getSExtValue();
  if (auto *GV = dyn_cast<GlobalVariable>(B))
    return PointerSlot{GV, O};
  StructType *ST = pointeeStruct(B);
  if (!ST || ST->isOpaque() || !ST->isSized())
    return std::nullopt;
  int64_t Size = DL.getTypeAllocSize(ST);
  if (Size <= 0)
    return std::nullopt;
  O %= Size;
  if (O < 0)
    O += Size;
  return PointerSlot{ST, O};
}

// The memory the module keeps pointers in, as integers or not: what a loaded
// integer that becomes a pointer (inttoptr) was loaded from, what a pointer's
// integer (ptrtoint) is stored to, and what a pointer is loaded from or
// stored to.  A pointer difference the optimizer has folded to integers --
// sg_page() then page_to_pfn(), `(page_link & ~3) - vmemmap_base`, in which
// the inttoptr and ptrtoint of the source cancel out -- is then still known
// for one (isPointerInt): both integers come from where the module keeps
// pointers, scatterlist's page_link (an inttoptr on the sg_chain path) and
// vmemmap_base (one in pfn_to_page).  Before instrumenting: it adds
// inttoptrs of its own.
void UCSan::collectPointerSlots(Module &M) {
  auto Add = [this](Value *Addr) {
    if (auto S = slotOf(Addr))
      PointerSlots.insert(*S);
  };
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    for (Instruction &I : instructions(F)) {
      if (auto *ITP = dyn_cast<IntToPtrInst>(&I)) {
        auto *LI = dyn_cast<LoadInst>(stripPointerIntArith(ITP->getOperand(0)));
        if (LI && LI->getType()->isIntegerTy(64))
          Add(LI->getPointerOperand());
      } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
        Value *V = SI->getValueOperand();
        if (V->getType()->isPointerTy() ||
            isa<PtrToIntOperator>(stripPointerIntArith(V)))
          Add(SI->getPointerOperand());
      } else if (auto *LI = dyn_cast<LoadInst>(&I)) {
        if (LI->getType()->isPointerTy())
          Add(LI->getPointerOperand());
      }
    }
  }
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    for (Instruction &I : instructions(F))
      if (auto *LI = dyn_cast<LoadInst>(&I))
        if (LI->getType()->isIntegerTy(64))
          if (auto S = slotOf(LI->getPointerOperand()))
            if (PointerSlots.count(*S))
              PointerIntLoads.insert(LI);
  }
}

bool UCSan::isPointerInt(Value *X) {
  if (!X->getType()->isIntegerTy(64))
    return false;
  Value *S = stripPointerIntArith(X);
  if (isa<PtrToIntOperator>(S))
    return true;
  auto *LI = dyn_cast<LoadInst>(S);
  return LI && PointerIntLoads.count(LI);
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

  ModuleSymbolTable::CollectAsmSymbols(
      M, [this](StringRef Name, object::BasicSymbolRef::Flags Flags) {
        if (!(Flags & object::BasicSymbolRef::SF_Undefined))
          AsmDefinedSyms.insert(Name);
      });

  collectPointerSlots(M);

  // Declare what inline asm calls before the split, so it is split too.
  // String port I/O is rewritten first: its loop reads hardware through a
  // call of the same kind.
  lowerAsmStringIO(M, AsmCallees);
  declareAsmCallees(M, AsmCallees);

  // Filter functions based on scope
  for (Function &F : M) {
    if (F.isIntrinsic()) continue;

    // Skip runtime functions (basic check)
    if (UCRuntimeFunctions.find(&F) != UCRuntimeFunctions.end()) {
      continue;
    }

    // Demangle the LLVM mangled name before matching against the YAML scope,
    // which lists demangled (human) names. For plain C names demangleName()
    // returns the name unchanged.
    std::string FName = demangleName(F.getName());

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

    // A wrapper takes over a function the module defines itself
    // (kernel/exit.o's weak hidden abort, lib/string.o's strlen): what is left
    // is a declaration that must resolve against the real definition, in libc
    // or the runtime, which the wrapper calls.  It cannot keep the module's
    // hidden visibility or dso_local: the linker refuses a hidden undefined
    // symbol, and will not bind one to a shared library.
    auto dropBody = [](Function &F) {
      F.deleteBody();
      F.setVisibility(GlobalValue::DefaultVisibility);
      F.setDSOLocal(false);
    };
    if (inScope) {
      FnsToInstrument.push_back(&F);
    } else {
      auto WK = getWrapperKind(&F);
      if (WK == WK_TaintCustom && ClWithTaintPass) {
        // TaintPass will call the custom wrapper and pass taint labels.
        // UCSan will only do check_pointer on pointer args at call sites.
        UnwrappedFnMap[&F] = &F;
        // Remove the body of there is one
        if (!F.isDeclaration()) dropBody(F);
      } else if (WK == WK_Discard) {
        // Replace with a trivial stub so both UCSan and TaintPass skip it
        Function *Stub = buildDiscardFunction(&F);
        F.replaceAllUsesWith(Stub);
        dropBody(F);
      } else if (WK == WK_Uninstrumented) {
        // Leave the function as is, but add to UnwrappedFnMap
        UnwrappedFnMap[&F] = &F;
      } else if (WK == WK_Custom || WK == WK_AutoCustom) {
        if (!F.isDeclaration()) dropBody(F);
        UnwrappedFnMap[&F] = &F;
        // Calls go to the custom wrapper; the function's address as a value
        // is left to name the function, which no object defines (only the
        // wrapper), and TaintPass, which does not list it, renamed it to its
        // instrumented name: ftrace_pop_return_trace's `ret = (unsigned
        // long)panic` was an undefined panic.taint.  It names an
        // out-of-scope stub instead, as for any other out-of-scope function.
        bool AddressUsed = any_of(F.uses(), [&F](Use &U) {
          auto *CB = dyn_cast<CallBase>(U.getUser());
          return !CB || CB->getCalledOperand() != &F;
        });
        if (AddressUsed) {
          if (Function *Stub = buildDangleFunction(&F))
            F.replaceUsesWithIf(Stub, [&F](Use &U) {
              auto *CB = dyn_cast<CallBase>(U.getUser());
              return !CB || CB->getCalledOperand() != &F;
            });
        }
      } else if (WK == WK_ShimOrig) {
        // Original function: delete body, redirect calls via visitWrappedCallBase
        if (!F.isDeclaration()) dropBody(F);
        UnwrappedFnMap[&F] = &F;
      } else if (WK == WK_ShimTarget) {
        // LLM-generated __shim_ function, instrument like in-scope
        FnsToInstrument.push_back(&F);
      } else {
        FnsOutOfScope.push_back(&F);
      }
    }

    if (Scope.entry != "main" && F.getName() == "main") {
      F.setName("__original$main");
    }
  }

  // Build dangle wrappers for out-of-scope functions
  // (now: a function the module's own top-level asm defines keeps its
  // address, and only its direct calls go to the wrapper.  Its address names
  // the asm's code, which asm calls with a convention of its own: KVM's
  // fastop() does `call *fop`, fop = em_bsr + k * FASTOP_SIZE into a block of
  // `bsr; ret` stubs.  Pointed at the wrapper instead, that call landed in
  // the middle of compiled C, and em_bsr_c died in __taint_union on a
  // garbage label.)
  StringSet<> AsmDefinedFns;
  ModuleSymbolTable::CollectAsmSymbols(
      M, [&AsmDefinedFns](StringRef Name,
                          object::BasicSymbolRef::Flags Flags) {
        if (!(Flags & object::BasicSymbolRef::SF_Undefined))
          AsmDefinedFns.insert(Name);
      });
  // The asm-defined ones go last, once the other out-of-scope bodies are gone:
  // an address taken only in one of those (rethook's self-referencing
  // trampoline, whose C users are stubs) leaves the declaration unused, and
  // erased, so dropUnreferencedAsmFunctions can still drop the asm.
  SmallPtrSet<Function *, 16> InstrumentedFns(FnsToInstrument.begin(),
                                              FnsToInstrument.end());
  std::stable_partition(FnsOutOfScope.begin(), FnsOutOfScope.end(),
                        [&AsmDefinedFns](Function *F) {
                          return !(F->isDeclaration() &&
                                   AsmDefinedFns.count(F->getName()));
                        });
  for (Function *F : FnsOutOfScope) {
    if (Function *dangle = buildDangleFunction(F)) {
      if (F->isDeclaration() && AsmDefinedFns.count(F->getName())) {
        // Only an address that in-scope code hands to inline asm, through
        // address arithmetic, keeps naming the asm; anything else takes the
        // wrapper, as before: C that stores it or passes it on would call it
        // as C.  A static call trampoline (__SCT__tp_func_rseq_ip_fixup,
        // `jmp __traceiter_rseq_ip_fixup`), named by its static_call key's
        // initializer or by static_call_update's STATIC_CALL_TRAMP_ADDR, was
        // kept for that, and its asm block still jumped to functions the
        // split had erased: kernel/rseq.o, arch/x86/events/core.o and
        // arch/x86/kvm/x86.o stopped linking.
        F->removeDeadConstantUsers();
        DenseMap<User *, bool> Seen;
        std::function<bool(User *)> ToAsm = [&](User *Usr) {
          auto It = Seen.find(Usr);
          if (It != Seen.end())
            return It->second;
          Seen[Usr] = false; // a phi cycle
          bool R = false;
          if (auto *CB = dyn_cast<CallBase>(Usr)) {
            R = CB->isInlineAsm() &&
                InstrumentedFns.count(CB->getFunction()) > 0;
          } else if (auto *St = dyn_cast<StoreInst>(Usr)) {
            // through a local at -O0: `fop` stored to its alloca, then loaded
            auto *A = dyn_cast<AllocaInst>(St->getPointerOperand());
            R = A && InstrumentedFns.count(St->getFunction()) &&
                any_of(A->users(), [&](User *AU) {
                  return isa<LoadInst>(AU) && ToAsm(AU);
                });
          } else if (auto *I = dyn_cast<Instruction>(Usr)) {
            bool Arith = isa<LoadInst>(I) || isa<GetElementPtrInst>(I) ||
                         isa<PHINode>(I) ||
                         isa<SelectInst>(I) || isa<CastInst>(I) ||
                         isa<BinaryOperator>(I);
            R = Arith && InstrumentedFns.count(I->getFunction()) &&
                any_of(I->users(), ToAsm);
          } else if (isa<Constant>(Usr) && !isa<GlobalValue>(Usr)) {
            R = any_of(Usr->users(), ToAsm);
          }
          return Seen[Usr] = R;
        };
        F->replaceUsesWithIf(dangle, [&](Use &U) {
          auto *CB = dyn_cast<CallBase>(U.getUser());
          if (CB && CB->getCalledOperand() == F)
            return true;
          return !ToAsm(U.getUser());
        });
        // the asm's symbol, not one TaintPass renames to F.taint (a
        // `ptrtoint (ptr @F)` left by an erased body is no use)
        F->removeDeadConstantUsers();
        if (F->use_empty())
          F->eraseFromParent();
        else
          markFunctionNosanitize(F);
        continue;
      }
      F->replaceAllUsesWith(dangle);
      F->eraseFromParent();
    }
  }

  // check if we need to dump cov information
  std::unique_ptr<llvm::raw_fd_ostream> COVF;
  if (!ClDumpCfg.empty()) {
    std::error_code EC;
    COVF = std::make_unique<raw_fd_ostream>(ClDumpCfg, EC, llvm::sys::fs::OF_Append | llvm::sys::fs::OF_Text);
    if (EC) {
      errs() << "Failed to open control flow file: " << ClDumpCfg << "\n";
      COVF.reset();
    }
  }

  // Instrument in-scope functions
  for (Function *F : FnsToInstrument) {
    if (!F || F->isDeclaration()) continue;

    // Make in-scope functions externally visible for debugging/linking,
    // but preserve internal/private linkage to avoid multiple definitions
    // when linking (e.g. static inline functions like percpu_counter_add)
    if (!F->hasLocalLinkage())
      F->setLinkage(GlobalValue::ExternalLinkage);

    // Kernel-style inputs may use 8-byte stack alignment; force realignment so
    // inserted UCSan runtime calls follow userspace ABI requirements.
    F->addFnAttr(Attribute::getWithStackAlignment(*Ctx, Align(16)));
    F->addFnAttr("stackrealign");

    // Add driver wrapper for entry point
    bool isEntry = false;
    if (demangleName(F->getName()) == Scope.entry ||
        (Scope.entry == "main" && F->getName() == "__original$main")) {
      buildDriverWrapperFunction(F);
      isEntry = true;
    }

    // Annotate BBs for all functions (excluding entry)
    if (!isEntry) {
      unsigned int Idx = find(Scope.scope, demangleName(F->getName())) - Scope.scope.begin() + 2;
      unsigned int BBCount = 0;
      for (Function::iterator BB = F->begin(); BB != F->end(); BB++, BBCount++) {
        auto *BBID = ConstantInt::get(Int32Ty, Idx * BBID_STEP + BBCount);
        if (ClTraceBB) {
          // getFirstInsertionPt() (not getFirstNonPHI) so the trace call lands
          // after any landingpad in C++ EH blocks, keeping the module valid.
          CallInst::Create(UCTraceBBFn, {ConstantInt::get(Int32Ty, Idx), BBID},
                          "", &*BB->getFirstInsertionPt());
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

    // A byval parameter's memory is the copy the call made, on this frame's
    // stack, where the shadow is whatever an earlier frame left: the copy's
    // values are concrete here (the call copied the bytes, not their labels).
    for (Argument &A : F->args()) {
      if (!A.hasByValAttr() || !A.getParamByValType()->isSized())
        continue;
      Value *Len = ConstantInt::get(
          Int64Ty, Mod->getDataLayout().getTypeAllocSize(A.getParamByValType()));
      CallInst *Clear = EntryIRB.CreateCall(
          UCSetLabelFn, {ConstantInt::get(PrimitiveShadowTy, 0),
                         EntryIRB.CreatePointerCast(&A, VoidPtrTy), Len});
      markNosanitize(Clear);
    }

    // UCSanVisitor may create new basic blocks, which confuses df_iterator.
    // Build a copy of the list before iterating over it.
    SmallVector<BasicBlock *, 4> BBList(depth_first(&F->getEntryBlock()));
    for (BasicBlock *BB : BBList) {

      // Dump cov info
      if (COVF) {
        auto getBBID = [&](BasicBlock *B) -> int64_t {
          auto *MD = B->getTerminator()->getMetadata(BBIDName);
          if (!MD) return -1;
          auto *C = dyn_cast<ConstantAsMetadata>(MD->getOperand(0));
          return dyn_cast<ConstantInt>(C->getValue())->getZExtValue();
        };

        int64_t CurID = getBBID(BB);
        if (CurID >= 0) {
          Instruction *Term = BB->getTerminator();
          // COV := debug_info:current_bbid:termination_types
          // debug_info := file,line,column
          // types := C (conditional branch)
          //       := D (unconditional branch)
          //       := S (switch cases)
          //       := R (return)
          //       := U (unreachable)
          if (const auto &DL = Term->getDebugLoc()) {
            *COVF << DL->getFilename() << "," << DL.getLine() << "," << DL.getCol();
          } else {
            *COVF << F->getName() << ",0,0";
          }
          *COVF << ":" << CurID << ":";
          if (auto *BR = dyn_cast<BranchInst>(Term)) {
            if (BR->isConditional()) {
              // condition branch: C:T:true_target_id:F:false_target_id
              *COVF << "C:T:" << getBBID(BR->getSuccessor(0))
                    << ":F:" << getBBID(BR->getSuccessor(1)) << "\n";
            } else {
              // unconditional branch: D:next_bbid
              *COVF << "D:" << getBBID(BR->getSuccessor(0)) << "\n";
            }
          } else if (auto *SI = dyn_cast<SwitchInst>(Term)) {
            // switch cases: S:default_bbid:case1_bbid:case2_bbid:...
            *COVF << "S";
            for (unsigned i = 0, n = SI->getNumSuccessors(); i < n; ++i) {
              *COVF << ":" << getBBID(SI->getSuccessor(i));
            }
            *COVF << "\n";
          } else if (isa<ReturnInst>(Term)) {
            // return: "R"
            *COVF << "R\n";
          } else if (isa<UnreachableInst>(Term)) {
            // unreachable: "U"
            *COVF << "U\n";
          } else {
            errs() << "Warning: unhandled termination type: " << *Term << "\n";
          }
        }
      }

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

    UF.emitMemoryAccessSummaries();

    // Removal instructions
    for (auto *RI : UF.RemovalInsts)
      RI->eraseFromParent();
  }

  dropUnreferencedAsmFunctions(M);
  zeroPercpuInAsmData(M);

  // Symbols the module's own inline asm defines: declared in the IR (C's
  // `extern kprobe_opcode_t optprobe_template_entry[]`) but defined by a
  // top-level asm() block, so they are no undefined globals to give a weak
  // definition -- that collided with the asm's label at codegen ("symbol
  // 'optprobe_template_end' is already defined", every function of
  // arch/x86/kernel/kprobes/opt.o).
  StringSet<> AsmDefined;
  ModuleSymbolTable::CollectAsmSymbols(
      M, [&AsmDefined](StringRef Name, object::BasicSymbolRef::Flags Flags) {
        if (!(Flags & object::BasicSymbolRef::SF_Undefined))
          AsmDefined.insert(Name);
      });

  // Fix initializer for declared global variables with external linkage
  // Also strip dso_local so llc generates PIC-compatible relocations
  // (needed for code compiled without -fPIC, e.g. kernel)
  for (GlobalVariable &GV : M.globals()) {
    if (GV.isDSOLocal() && !GV.hasLocalLinkage() && GV.hasDefaultVisibility()) {
      // Keep dso_local on globals used in inline asm with immediate ("i")
      // constraint, as their address must be a compile-time constant.
      // Walk through ConstantExpr users (e.g. GEP, bitcast) to find
      // indirect uses in inline asm.
      bool usedAsImmInAsm = false;
      SmallVector<User *, 8> Worklist(GV.users().begin(), GV.users().end());
      SmallPtrSet<User *, 8> Visited;
      while (!Worklist.empty() && !usedAsImmInAsm) {
        User *U = Worklist.pop_back_val();
        if (!Visited.insert(U).second)
          continue;
        if (isa<ConstantExpr>(U)) {
          Worklist.append(U->user_begin(), U->user_end());
          continue;
        }
        auto *CB = dyn_cast<CallBase>(U);
        if (!CB || !CB->isInlineAsm())
          continue;
        auto *IA = cast<InlineAsm>(CB->getCalledOperand());
        auto Constraints = IA->ParseConstraints();
        unsigned argIdx = 0;
        for (auto &CI : Constraints) {
          if (CI.Type != InlineAsm::isInput)
            continue;
          if (argIdx < CB->arg_size() &&
              CB->getArgOperand(argIdx)->stripPointerCasts() == &GV) {
            for (auto &Code : CI.Codes) {
              if (Code == "i") {
                usedAsImmInAsm = true;
                break;
              }
            }
          }
          if (usedAsImmInAsm) break;
          argIdx++;
        }
      }
      if (!usedAsImmInAsm)
        GV.setDSOLocal(false);
    }
    // (an extern_weak one too: the kernel declares what only its final link
    // defines -- kallsyms_num_syms, kallsyms_offsets -- __weak, and left
    // undefined its address is 0, which kallsyms_lookup_names read through)
    if (GV.isDeclaration() &&
        (GV.hasExternalLinkage() || GV.hasExternalWeakLinkage()) &&
        !AsmDefined.contains(GV.getName())) {
      GV.setLinkage(GlobalValue::WeakAnyLinkage);
      GV.setInitializer(Constant::getNullValue(GV.getValueType()));
    }
  }
  for (Function &F : M) {
    if (F.isDSOLocal() && !F.hasLocalLinkage() && F.hasDefaultVisibility()) {
      F.setDSOLocal(false);
    }
  }

  // === C++ exception-handling passthrough ===
  // The dangle loop replaced C++ EH runtime functions with __external$ stubs
  // that return normally, and erased the originals (F->eraseFromParent()).
  // __cxa_throw is noreturn, so when its stub returns the caller hits
  // `unreachable` (UB -> segfault / wrong exit code). Fix: rebuild the stubs as
  // passthroughs to the real libc++ implementations so throw/catch works inside
  // instrumented code. Because the originals were erased, we re-declare them via
  // getOrInsertFunction using the stub's (preserved) signature.
  {
    static const char *CxxEHNames[] = {
        "__cxa_throw",              "__cxa_rethrow",
        "__cxa_allocate_exception", "__cxa_free_exception",
        "__cxa_begin_catch",        "__cxa_end_catch",
        nullptr};
    for (int idx = 0; CxxEHNames[idx]; ++idx) {
      const char *Name = CxxEHNames[idx];
      std::string ExtName = std::string("__external$") + Name;
      Function *ExtF = M.getFunction(ExtName);
      if (!ExtF) continue;  // EH function not used in this module

      // Re-declare the real libc++ implementation with the stub's signature.
      FunctionCallee RealCallee =
          M.getOrInsertFunction(Name, ExtF->getFunctionType());
      Function *OrigF = dyn_cast<Function>(RealCallee.getCallee());
      if (!OrigF) continue;

      // Rebuild the stub body as a passthrough to the real function.
      ExtF->deleteBody();
      BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", ExtF);
      IRBuilder<> IRB(BB);
      std::vector<Value *> Args;
      for (auto &Arg : ExtF->args()) Args.push_back(&Arg);

      bool IsNoReturn = StringRef(Name) == "__cxa_throw" ||
                        StringRef(Name) == "__cxa_rethrow";
      CallInst *CI = IRB.CreateCall(OrigF, Args);
      if (IsNoReturn) {
        CI->addFnAttr(Attribute::NoReturn);
        IRB.CreateUnreachable();
      } else if (ExtF->getReturnType()->isVoidTy()) {
        IRB.CreateRetVoid();
      } else {
        IRB.CreateRet(CI);
      }
    }

    // Restore the real __gxx_personality_v0 on all instrumented functions.
    // The dangle loop's replaceAllUsesWith rewired the personality references to
    // the stub; revert them so libunwind can correctly walk instrumented frames
    // during EH unwinding.
    Function *StubPersonality = M.getFunction("__external$__gxx_personality_v0");
    if (StubPersonality) {
      FunctionCallee RealCallee = M.getOrInsertFunction(
          "__gxx_personality_v0", StubPersonality->getFunctionType());
      if (Function *RealPersonality = dyn_cast<Function>(RealCallee.getCallee())) {
        for (Function &F : M) {
          if (F.hasPersonalityFn() &&
              F.getPersonalityFn()->stripPointerCasts() == StubPersonality) {
            F.setPersonalityFn(RealPersonality);
          }
        }
      }
    }
  }

  // Emit type table JSON
  emitTypeTable();

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
