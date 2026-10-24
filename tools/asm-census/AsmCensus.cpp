// Inline-asm census: one JSON line per inline asm call site, classified
// against the behaviour of UCSanVisitor::visitInlineAsm
// (instrumentation/UCSanPass.cpp).  The classification mirrors that code on
// purpose -- the symbol extraction for `call` and the trap patterns are
// copies -- of the version before the inline asm rework (commit 2d58f46);
// see README.md for what that means for the numbers, how to run it, and
// what each field means.
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

std::string typeStr(Type *T) {
  std::string S;
  raw_string_ostream OS(S);
  T->print(OS);
  return OS.str();
}

// How UCSan would see a pointer operand.
std::string kindOf(Value *V) {
  Value *S = V->stripPointerCasts();
  if (isa<GlobalVariable>(S)) return "global";
  if (isa<Function>(S)) return "function";
  if (isa<ConstantPointerNull>(S)) return "null";
  if (isa<Constant>(S)) {
    Value *U = getUnderlyingObject(S);
    if (isa<GlobalVariable>(U)) return "constexpr_global";
    return "constexpr_other";
  }
  if (isa<AllocaInst>(S)) return "alloca";
  Value *U = getUnderlyingObject(S);
  if (isa<GlobalVariable>(U)) return "gep_global";
  if (isa<AllocaInst>(U)) return "gep_alloca";
  if (isa<Argument>(U)) return "arg";
  if (isa<CallBase>(U)) return "call";
  if (isa<LoadInst>(U)) return "load";
  if (isa<PHINode>(U) || isa<SelectInst>(U)) return "phi";
  if (isa<IntToPtrInst>(U)) return "inttoptr";
  return "other";
}

// Mirror of UCSan's getUnderlyingObjectType-derived size.
uint64_t ucsanSize(Value *V, const DataLayout &DL) {
  Value *U = getUnderlyingObject(V);
  Type *T = nullptr;
  if (auto *AI = dyn_cast<AllocaInst>(U)) T = AI->getAllocatedType();
  else if (auto *GV = dyn_cast<GlobalVariable>(U)) T = GV->getValueType();
  if (T && T->isSized()) return DL.getTypeAllocSize(T);
  return 0;
}

struct AsmCensus : PassInfoMixin<AsmCensus> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    const DataLayout &DL = M.getDataLayout();
    for (Function &F : M) {
      for (Instruction &I : instructions(F)) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB || !CB->isInlineAsm()) continue;
        auto *IA = cast<InlineAsm>(CB->getCalledOperand());
        json::Object O;
        O["file"] = M.getSourceFileName();
        O["fn"] = F.getName();
        O["asm"] = IA->getAsmString();
        O["cons"] = IA->getConstraintString();
        O["side"] = IA->hasSideEffects();
        O["callbr"] = isa<CallBrInst>(CB);
        O["ret"] = typeStr(CB->getType());
        O["ret_used"] = !CB->getType()->isVoidTy() && !CB->use_empty();

        auto Cons = IA->ParseConstraints();
        bool AllClobbers = true, MemClobber = false;
        json::Array IndOut, IndIn, RegPtrIn, InCodes, SizeBad;
        unsigned ArgIdx = 0, NRegIn = 0, NRegOut = 0, OpNo = 0;
        StringRef AsmS(IA->getAsmString());
        for (unsigned CIdx = 0; CIdx < Cons.size(); ++CIdx) {
          auto &C = Cons[CIdx];
          if (C.Type == InlineAsm::isClobber) {
            for (auto &Code : C.Codes)
              if (Code == "{memory}") MemClobber = true;
            continue;
          }
          AllClobbers = false;
          unsigned MyOp = OpNo++;
          if (C.Type == InlineAsm::isLabel) continue;
          if (C.Type == InlineAsm::isOutput && !C.isIndirect) {
            ++NRegOut;
            continue;
          }
          if (ArgIdx >= CB->arg_size()) break;
          Value *A = CB->getArgOperand(ArgIdx);
          std::string Code = C.Codes.empty() ? "" : C.Codes[0];
          if (C.isIndirect) {
            std::string K = kindOf(A);
            (C.Type == InlineAsm::isOutput ? IndOut : IndIn).push_back(K);
            // UCSan checks non-constant, non-alloca indirect operands.
            bool Checked = !isa<Constant>(A) &&
                           !isa<AllocaInst>(A->stripPointerCasts());
            if (Checked) {
              uint64_t Elem = 0;
              if (Type *ET = CB->getParamElementType(ArgIdx))
                if (ET->isSized()) Elem = DL.getTypeAllocSize(ET);
              uint64_t US = ucsanSize(A, DL);
              if (US != Elem)
                SizeBad.push_back(json::Object{{"kind", K},
                                               {"ucsan", (int64_t)US},
                                               {"elem", (int64_t)Elem}});
            }
          } else if (C.Type == InlineAsm::isInput) {
            ++NRegIn;
            InCodes.push_back(Code);
            if (A->getType()->isPointerTy()) {
              std::string N = std::to_string(MyOp);
              bool Deref = AsmS.contains("($" + N + ")") ||
                           AsmS.contains("(${" + N + ":");
              RegPtrIn.push_back(json::Object{{"kind", kindOf(A)},
                                              {"op", (int64_t)MyOp},
                                              {"code", Code},
                                              {"deref", Deref}});
            }
          }
          ++ArgIdx;
        }
        O["all_clobbers"] = AllClobbers;
        O["mem_clobber"] = MemClobber;
        O["ind_out"] = std::move(IndOut);
        O["ind_in"] = std::move(IndIn);
        O["reg_ptr_in"] = std::move(RegPtrIn);
        O["reg_in"] = (int64_t)NRegIn;
        O["reg_out"] = (int64_t)NRegOut;
        O["in_codes"] = std::move(InCodes);
        O["size_bad"] = std::move(SizeBad);

        // Mirror UCSan's call detection exactly.
        StringRef S(IA->getAsmString());
        size_t P = S.find("callq ");
        if (P == StringRef::npos) P = S.find("call ");
        if (P != StringRef::npos) {
          StringRef After = S.substr(P + (S[P + 4] == 'q' ? 6 : 5)).ltrim();
          size_t E = After.find_first_of(" \t\n\r;");
          StringRef Sym = E != StringRef::npos ? After.substr(0, E) : After;
          O["call_sym"] = Sym;
          O["call_prefix"] = P > 0 ? std::string(1, S[P - 1]) : "";
          if (!Sym.empty() && Sym[0] != '$' && Sym[0] != '%' && Sym[0] != '*') {
            Function *Callee = M.getFunction(Sym);
            O["call_action"] = Callee ? "rewrite" : "delete";
            if (Callee) O["callee_params"] = (int64_t)Callee->arg_size();
          } else {
            O["call_action"] = "skip";
          }
        }
        bool Trap = S.contains("ud2") || S.contains(".byte 0x0f, 0x0b") ||
                    S.contains("int3") || S.contains("int $3") ||
                    S.contains("hlt");
        O["trap"] = Trap;
        json::Array Imm;
        for (Value *A : CB->args())
          if (auto *CI = dyn_cast<ConstantInt>(A)) Imm.push_back(CI->getSExtValue());
        O["imm"] = std::move(Imm);
        outs() << formatv("{0}", json::Value(std::move(O))) << "\n";
      }
    }
    return PreservedAnalyses::all();
  }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "AsmCensus", "0.1", [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name != "asm-census") return false;
                  MPM.addPass(AsmCensus());
                  return true;
                });
          }};
}
