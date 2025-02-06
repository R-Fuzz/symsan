/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "defs.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/Support/DJB.h"

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

using namespace llvm;

cl::opt<std::string> DistanceFile(
    "distance",
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("filename")
);

cl::opt<std::string> TargetsFile(
    "targets",
    cl::desc("Input file containing the target lines of code."),
    cl::value_desc("targets"));

cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
    cl::value_desc("outdir"));

namespace llvm {

std::string getMangledName(const Function *F) {
    std::string mangledName = std::to_string(F->getReturnType()->getTypeID()) + "_" + F->getName().str();
    for (auto &A : F->args()) {
        mangledName += "_" + std::to_string(A.getType()->getTypeID());
    }
    return mangledName;
}


/// \brief Retrieve the first available debug location in \p BB that is not
/// inside /usr/ and store the **absolute, normalized path** in \p Filename.
/// Sets \p Line and \p Col accordingly.
///
/// This version does:
///  1) Loops over instructions in \p BB
///  2) Checks the debug location (and possibly inlined-at location)
///  3) Builds an absolute, normalized path (resolving "." and "..")
///  4) Skips if the path is empty, line=0, or the path starts with "/usr/"
///  5) Returns the first valid debug info found
void getDebugLocationFullPath(const BasicBlock *BB,
                              std::string &Filename,
                              unsigned &Line,
                              unsigned &Col) {
  Filename.clear();
  Line = 0;
  Col = 0;

  // We don't want paths that point to system libraries in /usr/
  static const std::string Xlibs("/usr/");

  // Iterate over instructions in the basic block
  for (auto &Inst : *BB) {
    if (DILocation *Loc = Inst.getDebugLoc()) {
      // Extract directory & filename
      std::string Dir  = Loc->getDirectory().str();
      std::string File = Loc->getFilename().str();
      unsigned    L    = Loc->getLine();
      unsigned    C    = Loc->getColumn();

      // If there's no filename, check the inlined location
      if (File.empty()) {
        if (DILocation *inlinedAt = Loc->getInlinedAt()) {
          Dir  = inlinedAt->getDirectory().str();
          File = inlinedAt->getFilename().str();
          L    = inlinedAt->getLine();
          C    = inlinedAt->getColumn();
        }
      }

      // Skip if still no filename or line==0
      if (File.empty() || L == 0)
        continue;

      // Build an absolute path in a SmallString
      llvm::SmallString<256> FullPath;

      // 1) If Dir is already absolute, just start with that.
      //    Otherwise, use the current working directory as a base.
      if (!Dir.empty() && llvm::sys::path::is_absolute(Dir)) {
        FullPath = Dir;
      } else {
        llvm::sys::fs::current_path(FullPath); // get the current working dir
        if (!Dir.empty()) {
          llvm::sys::path::append(FullPath, Dir);
        }
      }

      // 2) Append the filename
      llvm::sys::path::append(FullPath, File);

      // 3) Remove dot segments (both "." and "..")
      llvm::sys::path::remove_dots(FullPath, /*remove_dot_dot=*/true);

      // Now FullPath is absolute & normalized
      // Check if it's in /usr/
      if (StringRef(FullPath).startswith(Xlibs))
        continue; // skip system-libs

      // Found a valid location => set output vars
      Filename = FullPath.str().str(); // convert to std::string
      Line     = L;
      Col      = C;
      break; // stop after the first valid location
    }
  }
}

void getInsDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line, unsigned &Col) {
  std::string filename;
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    filename = Loc->getFilename().str();
    Col = Loc->getColumn();
    if (filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Col = oDILoc->getColumn();
        filename = oDILoc->getFilename().str();
      }
    }
    std::size_t found = filename.find_last_of("/\\");
    if (found != std::string::npos)
      filename = filename.substr(found + 1);
    Filename = filename;
  }
}

void getBBDebugLoc(const BasicBlock *BB, std::string &Filename, unsigned &Line, unsigned &Col) {
  std::string bb_name("");
  std::string filename;
  unsigned line = 0;
  unsigned col = 0;
  for (auto &I : *BB) {
    getInsDebugLoc(&I, filename, line, col);
    /* Don't worry about external libs */
    static const std::string Xlibs("/usr/");
    if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
      continue;
    Filename = filename;
    Line = line;
    Col = col;
    break;
  }
}

void getFuncDebugLoc(const Function *F, std::string &Filename, unsigned &Line) {
  if (F == nullptr || F->empty()) return;
    // Again assuming the debug location is attached to the first instruction of the function.
    const BasicBlock &entry = F->getEntryBlock();
    if (entry.empty()) return;
    const Instruction *I = entry.getFirstNonPHIOrDbg();
    if (I == nullptr) return;
    unsigned col = 0;
    getInsDebugLoc(I, Filename, Line, col);
}

uint32_t getBasicblockId(BasicBlock &BB, std::string &filename, unsigned &line, unsigned &col) {
  static uint32_t unamed = 0;
  std::string bb_name_with_col("");
  getBBDebugLoc(&BB, filename, line, col);
  if (!filename.empty() && line != 0 ){
    bb_name_with_col = filename + ":" + std::to_string(line) + ":" + std::to_string(col);
  }else{
    std::size_t found = filename.find_last_of("/\\");
    if (found != std::string::npos)
      filename = filename.substr(found + 1);
    bb_name_with_col = filename + ":unamed:" + std::to_string(unamed++);
  }
  getDebugLocationFullPath(&BB, filename, line, col);
  return djbHash(bb_name_with_col);
}

template<>
struct DOTGraphTraits<Function*> : public DefaultDOTGraphTraits {
  DOTGraphTraits(bool isSimple=false) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(Function *F) {
    return "CFG for '" + F->getName().str() + "' function";
  }

  std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
    std::string label = "id:" + std::to_string(djbHash(Node->getName()));
    auto *TI = Node->getTerminator();
    if (TI && TI->getNumSuccessors() == 2) {
      BranchInst *branch_inst = dyn_cast<BranchInst>(TI);
      if (branch_inst && branch_inst->isConditional()) {
        auto *TT = TI->getSuccessor(0);
        label += ",T:" + std::to_string(djbHash(TT->getName()));
        auto *FT = TI->getSuccessor(1);
        label += ",F:" + std::to_string(djbHash(FT->getName()));
      }
    }
    if (!Node->getName().empty()) {
      return Node->getName().str() + "," + label;
    }

    std::string Str;
    raw_string_ostream OS(Str);

    Node->printAsOperand(OS, false);
    return OS.str() + "," + label;
  }
};

} // namespace llvm

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}

char AFLCoverage::ID = 0;

static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
    "asan.",
    "llvm.",
    "sancov.",
    "__ubsan_handle_",
    "free",
    "malloc",
    "calloc",
    "realloc",
    "llvm.dbg.declare",
    "llvm.dbg.value"
  };

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}

bool AFLCoverage::runOnModule(Module &M) {
  static uint32_t unamed = 0;
  bool is_aflgo = false;
  bool is_aflgo_preprocessing = false;

  if (!TargetsFile.empty() && !DistanceFile.empty()) {
    FATAL("Cannot specify both '-targets' and '-distance'!");
    return false;
  }

  std::list<std::string> targets;
  std::map<uint64_t, int> bb_to_dis;

  if (!TargetsFile.empty()) {

    if (OutDirectory.empty()) {
      FATAL("Provide output directory '-outdir <directory>'");
      return false;
    }

    std::ifstream targetsfile(TargetsFile);
    std::string line;
    while (std::getline(targetsfile, line)){
      if (line.empty()) continue;
      targets.push_back(line);
    }
    targetsfile.close();

    is_aflgo_preprocessing = true;

  } else if (!DistanceFile.empty()) {

    std::ifstream cf(DistanceFile);
    if (cf.is_open()) {

      std::string line;
      while (getline(cf, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string token;
        getline(ss, token, ',');
        uint64_t BB_id = std::stoull(token);
        // Read filename:loc (not used here)
        getline(ss, token, ',');
        // Read distance
        getline(ss, token, ',');
        int bb_dis = (int) atof(token.c_str());
        bb_to_dis[BB_id] = bb_dis;
      }
      cf.close();

      is_aflgo = true;

    } else {
      FATAL("Unable to find %s.", DistanceFile.c_str());
      return false;
    }

  }

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    if (is_aflgo || is_aflgo_preprocessing)
      SAYF(cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (%s mode)\n",
           (is_aflgo_preprocessing ? "preprocessing" : "distance instrumentation"));
    else
      SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");


  } else be_quiet = 1;

  /* Instrument all the things! */

  int inst_blocks = 0;

  if (is_aflgo_preprocessing) {

    std::ofstream bbcalls(OutDirectory + "/direct_calls.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream ftargets(OutDirectory + "/Ftargets.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream bbtargets(TargetsFile, std::ofstream::out | std::ofstream::app);

    /* Create dot-files directory */
    std::string dotfiles(OutDirectory + "/dot-files");
    if (sys::fs::create_directory(dotfiles)) {
      FATAL("Could not create directory %s.", dotfiles.c_str());
    }

    for (auto &F : M) {

      bool has_BBs = false;
      std::string funcName = getMangledName(&F);

      /* Black list of function names */
      if (isBlacklisted(&F)) {
        continue;
      }

      bool is_fun_target = false;
      for (auto &BB : F) {
        bool is_target = false;

        std::string bb_name("");
        std::string bb_name_with_col("");
        std::string filename;
        unsigned line = 0;
        unsigned col = 0;

        /* Find bb_name */
        getBBDebugLoc(&BB, filename, line, col);
        if (!filename.empty() && line != 0 ){
          bb_name = filename + ":" + std::to_string(line);
          bb_name_with_col = filename + ":" + std::to_string(line) + ":" + std::to_string(col);
        }else{
          filename = M.getSourceFileName();
          std::size_t found = filename.find_last_of("/\\");
          if (found != std::string::npos)
            filename = filename.substr(found + 1);
          bb_name = filename + ":unamed:" + std::to_string(unamed++);
          bb_name_with_col = bb_name;
        }
        /* handle direct calls */
        for (auto &I : BB) {
          if (auto *c = dyn_cast<CallInst>(&I)) {
            if (auto *CalledF = c->getCalledFunction()) {
              if (!isBlacklisted(CalledF) && !bb_name.empty()) {
                // Getting the mangled name of the function.
                std::string mangledName = getMangledName(CalledF);
                bbcalls << bb_name << "," << mangledName << std::endl;
              }
            }
          }
        }
        /* find target BB */
        for (auto &target : targets) {
          for (auto &I : BB) {
            getInsDebugLoc(&I, filename, line, col);
            /* Don't worry about external libs */
            static const std::string Xlibs("/usr/");
            if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
              continue;

            std::size_t found = target.find_last_of("/\\");
            if (found != std::string::npos)
              target = target.substr(found + 1);
            std::size_t pos = target.find_last_of(":");
            std::string target_file = target.substr(0, pos);
            unsigned int target_line = atoi(target.substr(pos + 1).c_str());
            if (!target_file.compare(filename) && target_line == line){
              is_target = true;
              if (!bb_name.empty()) bbtargets << "\n" << bb_name;
              break;
            }
          }
        }

        if (is_target) {
          is_fun_target = true;
          bbtargets << "\n";
        }
        if (!bb_name.empty()) {
          BB.setName(bb_name_with_col);
          if (!BB.hasName()) {
            std::string newname = bb_name_with_col;
            Twine t(newname);
            SmallString<256> NameData;
            StringRef NameRef = t.toStringRef(NameData);
            MallocAllocator Allocator;
            BB.setValueName(ValueName::Create(NameRef, Allocator));
          }
          has_BBs = true;
        }
      }

      if (has_BBs) {
        /* Print CFG */
        std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
        std::error_code EC;
        raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::F_None);
        if (!EC) {
          WriteGraph(cfgFile, &F, true);
        }

        if (is_fun_target)
          ftargets << funcName << "\n";
      }
    }
    bbcalls.close();
    ftargets.close();
    bbtargets.close();
  } else {
    /* Distance instrumentation */

    LLVMContext &C = M.getContext();
    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#ifdef __x86_64__
    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8 + 8);
    ConstantInt *MapDistSumLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
#else
    IntegerType *LargestType = Int32Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4 + 4);
    ConstantInt *MapDistSumLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(LargestType, 1);

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    std::ofstream bbLocs(OutDirectory + "/bid_loc_mapping.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream funcInfo(OutDirectory + "/function_info.txt", std::ofstream::out | std::ofstream::app);

    for (auto &F : M) {
      unsigned minLine = std::numeric_limits<unsigned>::max();
      unsigned maxLine = 0;

      std::string filename;
      for (auto &BB : F) {

        int distance = -2;
        unsigned line = 0;
        unsigned col = 0;
        uint64_t bb_id = (uint64_t) getBasicblockId(BB, filename, line, col);

        if (line < minLine && line > 0) {
          minLine = line;
        }
        if (line > maxLine && line > 0) {
          maxLine = line;
        }
        if (!filename.empty() && line != 0)
          bbLocs << bb_id << "," << F.getGUID() << "," << filename << ":" << line << "\n";

        if (is_aflgo) {
          if (bb_to_dis.find(bb_id) != bb_to_dis.end()) {
            /* Find distance for BB */
            distance = bb_to_dis[bb_id];
          }
        }

        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        if (distance >= 0) {
          LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
          MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          ConstantInt *Distance = ConstantInt::get(LargestType, (unsigned) distance);
          ConstantInt *Zero = ConstantInt::get(LargestType, (unsigned) 0);

          /* Store global minimal BB distance to shm[MAPSIZE]
          *  sub = distance - map_dist
          *  lshr = sign(sub) 
          *  shm[MAPSIZE] = lshr * distance + (1 - lshr) * map_dist
          */
          Value *MapDistPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
          LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *Sub = IRB.CreateSub(Distance, MapDist);
          ConstantInt *Bits = ConstantInt::get(LargestType, 63);
          Value *Lshr = IRB.CreateLShr(Sub, Bits);
          Value *Mul1 = IRB.CreateMul(Lshr, Distance);
          Value *Sub1 = IRB.CreateSub(One, Lshr);
          Value *Mul2 = IRB.CreateMul(Sub1, MapDist);
          Value *Incr = IRB.CreateAdd(Mul1, Mul2);

          IRB.CreateStore(Incr, MapDistPtr)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          /* Store local minimal distance to shm[MAPSIZE + (4 or 8)] */
          Value *MapDistSumPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapDistSumLoc), LargestType->getPointerTo());
          MapDist = IRB.CreateLoad(MapDistSumPtr);
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Sub = IRB.CreateSub(Distance, MapDist);
          Bits = ConstantInt::get(LargestType, 63);
          Lshr = IRB.CreateLShr(Sub, Bits);
          Mul1 = IRB.CreateMul(Lshr, Distance);
          Sub1 = IRB.CreateSub(One, Lshr);
          Mul2 = IRB.CreateMul(Sub1, MapDist);
          Incr = IRB.CreateAdd(Mul1, Mul2);

          IRB.CreateStore(Incr, MapDistSumPtr)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          /* Increase count at shm[MAPSIZE + (4 or 8) + (4 or 8)] */
          Value *MapCntPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
          LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          IRB.CreateStore(IncrCnt, MapCntPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        }else if (distance == -1){
          llvm::FunctionCallee exitFunc = M.getOrInsertFunction(
              "exit", llvm::FunctionType::get(
                llvm::Type::getVoidTy(M.getContext()), Int32Ty, false));
          IRB.CreateCall(exitFunc, {IRB.getInt32(0)});
        }
        if (distance >= 0 || distance == -1) {
          inst_blocks++;
        }

      }
      if (!filename.empty() && minLine != std::numeric_limits<unsigned>::max() && maxLine != 0)
        funcInfo << F.getGUID() << "," << F.getName().str() << "," << filename << "," << minLine << "," << maxLine << "\n";
    }
  }

  /* Say something nice. */

  if (!is_aflgo_preprocessing && !be_quiet) {
    std::ofstream debugfile(OutDirectory + "/debug.txt", std::ofstream::out | std::ofstream::app);
    std::string moduleName = M.getName().str();
    if (!inst_blocks) {
      WARNF("No instrumentation targets found for %s.", moduleName.c_str());
      debugfile << "No instrumentation targets found for " << moduleName << std::endl;
    }else {
      const char* mode = "non-hardened";
      if (getenv("AFL_HARDEN")) {
          mode = "hardened";
      } else if (getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) {
          mode = "ASAN/MSAN";
      }
      OKF("Instrumented %u locations (%s mode) to %s", inst_blocks, mode, moduleName.c_str());
      debugfile << "Instrumented " << inst_blocks << " locations (" << mode << " mode) to " << moduleName << std::endl;
    }
    debugfile.close();
  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
