#ifndef GRAD_JIT_H
#define GRAD_JIT_H

#include "llvm/ADT/StringRef.h"
#include "llvm/ExecutionEngine/JITSymbol.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/Core.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/IRTransformLayer.h"
#include "llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/Orc/TargetProcessControl.h"
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
      llvm::orc::ExecutionSession ES;
      llvm::orc::RTDyldObjectLinkingLayer ObjectLayer;
      llvm::orc::IRCompileLayer CompileLayer;
      llvm::orc::IRTransformLayer OptimizeLayer;
      //std::unique_ptr<llvm::TargetMachine> TM;

      llvm::DataLayout DL;
      llvm::orc::MangleAndInterner Mangle;
      llvm::orc::JITDylib *MainJD;
      // llvm::orc::ThreadSafeContext Ctx;
      // std::unique_ptr<llvm::orc::JITCompileCallbackManager> CompileCallbackManager;
      // llvm::orc::CompileOnDemandLayer CODLayer;

    public:
      GradJit(llvm::orc::JITTargetMachineBuilder JTMB, llvm::DataLayout DL)
        : ObjectLayer(ES,
            []() { return std::make_unique<llvm::SectionMemoryManager>(); }),
        // TM(llvm::EngineBuilder().selectTarget()),
        CompileLayer(ES, ObjectLayer, std::make_unique<llvm::orc::ConcurrentIRCompiler>(std::move(JTMB))),
        OptimizeLayer(ES, CompileLayer, optimizeModule),
        DL(std::move(DL)), Mangle(ES, this->DL)
        // CompileCallbackManager(
        //   llvm::orc::createLocalCompileCallbackManager(TM->getTargetTriple(), ES, 0)),
        //   CODLayer(ES, OptimizeLayer,
        //   [this](llvm::Function &F) { return std::set<llvm::Function*>({&F}); },
        //   *CompileCallbackManager,
        //   llvm::orc::createLocalIndirectStubsManagerBuilder(
        //     TM->getTargetTriple()))
        //   Ctx(std::make_unique<llvm::LLVMContext>())
        {
          MainJD = &cantFail(ES.createJITDylib("main"));

          MainJD->addGenerator(
              cantFail(llvm::orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(
                DL.getGlobalPrefix())));
        }

      ~GradJit() {
        if (auto Err = ES.endSession())
          ES.reportError(std::move(Err));
      }

      const llvm::DataLayout &getDataLayout() const { return DL; }
      // llvm::LLVMContext &getContext() { return *Ctx.getContext(); }
      // llvm::orc::ThreadSafeContext &getTSC() {return Ctx;}

      static llvm::Expected<std::unique_ptr<GradJit>> Create() {
        auto JTMB = llvm::orc::JITTargetMachineBuilder::detectHost();

        if (!JTMB) {
          llvm::errs() << "Cannot detect host: " << JTMB.takeError() << "\n";
          return JTMB.takeError();
        }

        auto DL = JTMB->getDefaultDataLayoutForTarget();
        if (!DL) {
          llvm::errs() << "Cannot get default DL for target: " << DL.takeError() << "\n";
          return DL.takeError();
        }

        return std::make_unique<GradJit>(std::move(*JTMB), std::move(*DL));
      }

      llvm::Error addModule(std::unique_ptr<llvm::Module> M,
                            std::unique_ptr<llvm::LLVMContext> ctx) {
        return OptimizeLayer.add(*MainJD,
          llvm::orc::ThreadSafeModule(std::move(M), std::move(ctx)));
      }

      llvm::Expected<llvm::JITEvaluatedSymbol> lookup(llvm::StringRef Name) {
        return ES.lookup({MainJD}, Mangle(Name.str()));
      }

    private:
      static llvm::orc::ThreadSafeModule
      optimizeModule(llvm::orc::ThreadSafeModule TSM, const llvm::orc::MaterializationResponsibility &R) {
        // Create a function pass manager.
        auto FPM = std::make_unique<llvm::legacy::FunctionPassManager>(TSM.getModuleUnlocked());

        // Add some optimizations.
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createReassociatePass());
        FPM->add(llvm::createGVNPass());
        FPM->add(llvm::createCFGSimplificationPass());
        FPM->doInitialization();

        // Run the optimizations over all functions in the module being added to
        // the JIT.
        for (auto &F : *TSM.getModuleUnlocked())
          FPM->run(F);

        return TSM;
      }
  };
}

#endif // LLVM_EXECUTIONENGINE_ORC_KALEIDOSCOPEJIT_H

