//===- LoopOutlinePass.cpp - outline one loop iteration -------------------===//
//
// New-PM module pass that outlines the *body* of each innermost loop (one
// iteration) into a standalone function, so the validation oracle can check a
// loop invariant inductively: `{I & guard} body {I}`.
//
// Approach (at -O0, where loop-carried state is in allocas, no header PHIs):
// take ALL of a loop's blocks (header included, so the guard and its variables
// like the bound `n` are in scope), but first REDIRECT the back-edge
// (latch -> header) to a fresh unreachable sink. The region is then acyclic,
// single-entry (header), and runs exactly ONE iteration before "returning"
// (the redirected back-edge and the loop exits all become region exits).
// CodeExtractor turns it into:
//     __ucsan_loopbody_<fn>_<n>(&i, &n, &p, ...) -> exit-selector
// The loop-carried state crosses as alloca-pointer args (memory model), which
// ucsan symbolizes (= free havoc); the harness assumes I & guard on the loaded
// values, calls the body, and asserts I on the (memory-updated) values.
//
// Redirecting the back-edge destroys the original loop — fine, this transform
// is for the VALIDATION-only build (the oracle targets the outlined body as
// entry; the parent's correctness is irrelevant there).
//
// First cut: innermost loops only. Anything CodeExtractor declines (isEligible
// / null) is skipped — graceful degrade, never a miscompile (verifyModule gates).
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SetVector.h"
#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"

#include <string>
#include <vector>

#define DEBUG_TYPE "loop-outline"

using namespace llvm;

static cl::opt<bool> ClVerbose(
    "loop-outline-verbose",
    cl::desc("Print loop-outline decisions"), cl::init(false), cl::Hidden);

// Path to write the arg→source-var sidecar JSON. The outlined function's args
// are alloca POINTERS with numbered IR names; source names + types live only in
// debug info. The oracle reads this to build the invariant harness.
static cl::opt<std::string> ClSidecar(
    "loop-outline-sidecar",
    cl::desc("Write arg→source-var map JSON to this path"), cl::init(""));

// Render a DIType as a C type string (best-effort; common cases). Resolves
// const/volatile/typedef, pointers, basic types, structs.
static std::string diTypeToC(const DIType *T) {
  if (!T)
    return "void";
  if (auto *B = dyn_cast<DIBasicType>(T))
    return B->getName().empty() ? "int" : B->getName().str();
  if (auto *D = dyn_cast<DIDerivedType>(T)) {
    switch (D->getTag()) {
    case dwarf::DW_TAG_pointer_type:
      return diTypeToC(D->getBaseType()) + " *";
    case dwarf::DW_TAG_const_type:
    case dwarf::DW_TAG_volatile_type:
    case dwarf::DW_TAG_typedef:
    case dwarf::DW_TAG_restrict_type:
      return diTypeToC(D->getBaseType());
    default:
      return "void";
    }
  }
  if (auto *C = dyn_cast<DICompositeType>(T)) {
    if (C->getTag() == dwarf::DW_TAG_array_type)
      return diTypeToC(C->getBaseType()) + " *";  // array decays to pointer
    if (!C->getName().empty())
      return ("struct " + C->getName()).str();
  }
  return "void";
}

namespace {

// A loop selected for extraction (gathered before any mutation; BasicBlock*
// stay valid because innermost loops are disjoint).
struct Target {
  Function *F;
  BasicBlock *Header;
  std::vector<BasicBlock *> Blocks;       // ALL loop blocks (header included)
  SmallVector<BasicBlock *, 4> Latches;   // back-edge sources (latch -> header)
};

static void gatherInnermost(Loop *L, Function &F,
                            std::vector<Target> &Out) {
  if (!L->getSubLoops().empty()) {
    for (Loop *Sub : *L)
      gatherInnermost(Sub, F, Out);
    return;  // first cut: innermost only (nested handled bottom-up later)
  }
  Target T;
  T.F = &F;
  T.Header = L->getHeader();
  for (BasicBlock *BB : L->blocks())
    T.Blocks.push_back(BB);
  L->getLoopLatches(T.Latches);
  if (T.Blocks.empty() || T.Latches.empty())
    return;
  Out.push_back(std::move(T));
}

// First debug line of a block (0 if none) — used to key the outlined body back
// to the source loop the contract's invariant references.
static unsigned dbgLine(BasicBlock *BB) {
  for (Instruction &I : *BB)
    if (const DebugLoc &DL = I.getDebugLoc())
      return DL.getLine();
  return 0;
}

// C type for an outlined ARG: like diTypeToC but PRESERVES arrays as
// "elem [N]" (the outlined arg of a stack array is pointer-to-array, so the
// harness must declare `elem (*p)[N]` and materialize N*sizeof(elem), not decay
// it to a pointer).
static std::string diArgCType(const DIType *T) {
  if (auto *C = dyn_cast_or_null<DICompositeType>(T)) {
    if (C->getTag() == dwarf::DW_TAG_array_type) {
      int64_t n = 0;
      for (DINode *E : C->getElements()) {
        if (auto *sr = dyn_cast<DISubrange>(E)) {
          if (auto *ci = sr->getCount().dyn_cast<ConstantInt *>())
            n = ci->getSExtValue();
          break;
        }
      }
      return diTypeToC(C->getBaseType()) + " [" + std::to_string(n) + "]";
    }
  }
  return diTypeToC(T);
}

// Map each outlined-function arg to its source var name + C type, via the
// llvm.dbg.declare of the alloca passed in at the (single) call site.
struct ArgInfo {
  unsigned idx;
  std::string var;
  std::string ctype;
};
static std::vector<ArgInfo> buildArgMap(Function *Out, Function *F) {
  DenseMap<const Value *, DILocalVariable *> Dbg;
  for (BasicBlock &BB : *F)
    for (Instruction &I : BB)
      if (auto *DDI = dyn_cast<DbgDeclareInst>(&I))
        if (DDI->getAddress() && DDI->getVariable())
          Dbg[DDI->getAddress()] = DDI->getVariable();

  CallBase *CB = nullptr;
  for (User *U : Out->users())
    if ((CB = dyn_cast<CallBase>(U)))
      break;
  std::vector<ArgInfo> Out2;
  if (!CB)
    return Out2;
  for (unsigned i = 0, e = CB->arg_size(); i < e; ++i) {
    const Value *A = CB->getArgOperand(i)->stripPointerCasts();
    ArgInfo AI{i, "", ""};
    auto It = Dbg.find(A);
    if (It != Dbg.end()) {
      AI.var = It->second->getName().str();
      AI.ctype = diArgCType(It->second->getType());
    }
    Out2.push_back(std::move(AI));
  }
  return Out2;
}

// C declarator for a global the harness must `extern`-declare (arrays keep
// `[]`, since `int a[]` and `int *a` are different symbols at link).
static std::string diGlobalDecl(StringRef name, const DIType *T) {
  if (auto *C = dyn_cast_or_null<DICompositeType>(T))
    if (C->getTag() == dwarf::DW_TAG_array_type)
      return diTypeToC(C->getBaseType()) + " " + name.str() + "[]";
  return diTypeToC(T) + " " + name.str();
}

// Globals referenced by the outlined body (name, C extern declarator).  These
// are NOT outlined args (module-level), so the harness needs them to render
// invariants that mention a global (e.g. a loop filling a global array).
static std::vector<std::pair<std::string, std::string>>
collectGlobals(Function *Out) {
  SetVector<GlobalVariable *> gvs;
  for (BasicBlock &BB : *Out)
    for (Instruction &I : BB)
      for (Value *Op : I.operands())
        if (auto *gv = dyn_cast<GlobalVariable>(Op->stripPointerCasts()))
          if (!(gv->getName()).starts_with("llvm.") && !gv->getName().empty())
            gvs.insert(gv);
  std::vector<std::pair<std::string, std::string>> out;
  for (GlobalVariable *gv : gvs) {
    SmallVector<DIGlobalVariableExpression *, 1> dbgs;
    gv->getDebugInfo(dbgs);
    if (dbgs.empty())
      continue;  // no debug info ⇒ compiler-internal (string literals, etc.)
    const DIType *ty = dbgs[0]->getVariable()->getType();
    out.push_back({gv->getName().str(), diGlobalDecl(gv->getName(), ty)});
  }
  return out;
}

static Function *extractTarget(const Target &T, unsigned Idx) {
  // Redirect each back-edge (latch -> header) to a fresh unreachable sink so
  // the loop region becomes acyclic = exactly one iteration. (Validation-only
  // transform; the original loop is intentionally destroyed.)
  BasicBlock *Sink = BasicBlock::Create(
      T.F->getContext(), "__oneiter_sink", T.F);
  new UnreachableInst(T.F->getContext(), Sink);
  for (BasicBlock *Latch : T.Latches) {
    Instruction *Term = Latch->getTerminator();
    for (unsigned i = 0, e = Term->getNumSuccessors(); i < e; ++i)
      if (Term->getSuccessor(i) == T.Header)
        Term->setSuccessor(i, Sink);
  }

  // Fresh DominatorTree after the CFG edit.
  DominatorTree DT;
  DT.recalculate(*T.F);

  CodeExtractorAnalysisCache CEAC(*T.F);
  // NOTE: the trailing Suffix argument is intentionally left at its default;
  // LLVM 18 inserted an AllocationBlock parameter before it, so passing it
  // positionally is not source-compatible across versions.
  CodeExtractor CE(T.Blocks, &DT, /*AggregateArgs=*/false,
                   /*BFI=*/nullptr, /*BPI=*/nullptr, /*AC=*/nullptr,
                   /*AllowVarArgs=*/false, /*AllowAlloca=*/false);
  if (!CE.isEligible()) {
    if (ClVerbose)
      errs() << "[loop-outline] skip " << T.F->getName()
             << " loop#" << Idx << ": not eligible\n";
    return nullptr;
  }
  Function *Out = CE.extractCodeRegion(CEAC);
  if (!Out) {
    if (ClVerbose)
      errs() << "[loop-outline] skip " << T.F->getName()
             << " loop#" << Idx << ": extract failed\n";
    return nullptr;
  }
  Out->setName("__ucsan_loopbody_" + T.F->getName().str() + "_" +
               std::to_string(Idx));
  // Keep it as a standalone, externally-visible symbol so METADATA `entry:` can
  // target it and the inliner cannot fold it away.
  Out->addFnAttr(Attribute::NoInline);
  Out->setLinkage(GlobalValue::ExternalLinkage);
  if (ClVerbose)
    errs() << "[loop-outline] outlined " << Out->getName() << " ("
           << Out->arg_size() << " args)\n";
  return Out;
}

struct LoopOutlinePass : public PassInfoMixin<LoopOutlinePass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    // Phase 1 (read-only): gather innermost-loop body regions.
    std::vector<Target> Targets;
    for (Function &F : M) {
      if (F.isDeclaration() || (F.getName()).starts_with("__ucsan_loopbody_"))
        continue;
      DominatorTree DT;
      DT.recalculate(F);
      LoopInfo LI;
      LI.analyze(DT);
      for (Loop *L : LI)
        gatherInnermost(L, F, Targets);
    }
    if (Targets.empty())
      return PreservedAnalyses::all();

    // Phase 2 (mutate): extract each region. Per-function counter for names.
    std::string Sidecar;  // JSON array, built incrementally
    bool Changed = false;
    Function *Prev = nullptr;
    unsigned Idx = 0;
    for (const Target &T : Targets) {
      if (T.F != Prev) {
        Prev = T.F;
        Idx = 0;
      }
      unsigned HdrLine = dbgLine(T.Header);  // capture before extraction moves it
      Function *Out = extractTarget(T, Idx++);
      if (!Out)
        continue;
      Changed = true;
      // Sidecar entry: {fn, header_line, args:[{idx,var,ctype}]}.
      if (!Sidecar.empty())
        Sidecar += ",\n";
      Sidecar += "  {\"fn\": \"" + Out->getName().str() +
                 "\", \"header_line\": " + std::to_string(HdrLine) +
                 ", \"args\": [";
      bool first = true;
      for (const ArgInfo &AI : buildArgMap(Out, T.F)) {
        if (!first)
          Sidecar += ", ";
        first = false;
        Sidecar += "{\"idx\": " + std::to_string(AI.idx) + ", \"var\": \"" +
                   AI.var + "\", \"ctype\": \"" + AI.ctype + "\"}";
      }
      Sidecar += "], \"globals\": [";
      bool gfirst = true;
      for (const auto &G : collectGlobals(Out)) {
        if (!gfirst)
          Sidecar += ", ";
        gfirst = false;
        Sidecar += "{\"name\": \"" + G.first + "\", \"decl\": \"" +
                   G.second + "\"}";
      }
      Sidecar += "]}";
    }

    if (Changed && verifyModule(M, &errs())) {
      // Should not happen for eligible regions; loud if it does.
      errs() << "[loop-outline] ERROR: verifyModule failed after outlining\n";
    }

    if (!ClSidecar.empty()) {
      std::error_code EC;
      raw_fd_ostream OS(ClSidecar, EC, sys::fs::OF_Text);
      if (EC)
        errs() << "[loop-outline] cannot write sidecar " << ClSidecar
               << ": " << EC.message() << "\n";
      else
        OS << "[\n" << Sidecar << "\n]\n";
    }
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

  static bool isRequired() { return true; }
};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LoopOutlinePass", "v0.1",
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "loop-outline") {
                    MPM.addPass(LoopOutlinePass());
                    return true;
                  }
                  return false;
                });
          }};
}
