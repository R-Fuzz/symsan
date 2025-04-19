#ifndef GRAD_JIT_H
#define GRAD_JIT_H

#include "llvm/ADT/StringRef.h"
#include "llvm/ExecutionEngine/JITSymbol.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/Core.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/ExecutionEngine/Orc/ExecutorProcessControl.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/IRTransformLayer.h"
#include "llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/GVN.h"

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace rgd {

class GradJit {
private:
  std::unique_ptr<llvm::orc::ExecutionSession> ES;

  llvm::DataLayout DL;
  llvm::orc::MangleAndInterner Mangle;

  llvm::orc::RTDyldObjectLinkingLayer ObjectLayer;
  llvm::orc::IRCompileLayer CompileLayer;
  llvm::orc::IRTransformLayer OptimizeLayer;

  llvm::orc::JITDylib &MainJD;

public:
  GradJit(std::unique_ptr<llvm::orc::ExecutionSession> ES,
          llvm::orc::JITTargetMachineBuilder JTMB, llvm::DataLayout DL)
      : ES(std::move(ES)), DL(std::move(DL)), Mangle(*this->ES, this->DL),
        ObjectLayer(*this->ES,
            []() { return std::make_unique<llvm::SectionMemoryManager>(); }),
        CompileLayer(*this->ES, ObjectLayer,
            std::make_unique<llvm::orc::ConcurrentIRCompiler>(std::move(JTMB))),
        OptimizeLayer(*this->ES, CompileLayer, optimizeModule),
        MainJD(this->ES->createBareJITDylib("main")) {
    MainJD.addGenerator(
        cantFail(llvm::orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(
            DL.getGlobalPrefix())));
  }

  ~GradJit() {
    if (auto Err = ES->endSession())
      ES->reportError(std::move(Err));
  }

  static llvm::Expected<std::unique_ptr<GradJit>> Create() {
    auto EPC = llvm::orc::SelfExecutorProcessControl::Create();
    if (!EPC) {
      llvm::errs() << "Cannot create EPC: " << EPC.takeError() << "\n";
      return EPC.takeError();
    }

    auto ES = std::make_unique<llvm::orc::ExecutionSession>(std::move(*EPC));

    llvm::orc::JITTargetMachineBuilder JTMB(
        ES->getExecutorProcessControl().getTargetTriple());

    auto DL = JTMB.getDefaultDataLayoutForTarget();
    if (!DL) {
      llvm::errs() << "Cannot get default DL for target: "
                   << DL.takeError() << "\n";
      return DL.takeError();
    }

    return std::make_unique<GradJit>(std::move(ES), std::move(JTMB),
                                     std::move(*DL));
  }

  const llvm::DataLayout &getDataLayout() const { return DL; }

  llvm::orc::JITDylib &getMainJITDylib() { return MainJD; }

  void addModule(std::unique_ptr<llvm::Module> M,
                 std::unique_ptr<llvm::LLVMContext> ctx) {
    auto RT = MainJD.getDefaultResourceTracker();
    cantFail(OptimizeLayer.add(RT,
        llvm::orc::ThreadSafeModule(std::move(M), std::move(ctx))));
  }

  llvm::Expected<llvm::JITEvaluatedSymbol> lookup(llvm::StringRef Name) {
    return ES->lookup({&MainJD}, Mangle(Name.str()));
  }

private:
  static llvm::Expected<llvm::orc::ThreadSafeModule>
  optimizeModule(llvm::orc::ThreadSafeModule TSM,
                 const llvm::orc::MaterializationResponsibility &R) {
    TSM.withModuleDo([](llvm::Module &M) {
      // Create a function pass manager.
      auto FPM = std::make_unique<llvm::legacy::FunctionPassManager>(&M);

      // Add some optimizations.
      FPM->add(llvm::createInstructionCombiningPass());
      FPM->add(llvm::createReassociatePass());
      FPM->add(llvm::createGVNPass());
      FPM->add(llvm::createInstSimplifyLegacyPass());
      FPM->doInitialization();

      // Run the optimizations over all functions in the module being added to
      // the JIT.
      for (auto &F : M)
        FPM->run(F);
    });

    return std::move(TSM);
  }
};

} // namespace rgd

#endif // GRAD_JIT_H

