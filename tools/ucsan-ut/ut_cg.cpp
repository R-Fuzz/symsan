// ut-cg: the call graph facts the scope script (cg_scope.py) needs, from
// bitcode directly.
//
// The script read them off llvm-dis's text with regexes: for an Isolate test's
// module (all of v8 linked in, 26M lines) that took ~25 minutes, of which
// llvm-dis was one.  Same facts, same names (as the text spells them: quoted
// when LLVM quotes them), one line each, tab-separated:
//
//   D fn file size noreturn   a definition: its DISubprogram's file, its
//                             instruction count, 1 if its attributes say so
//   X fn                      a declaration
//   A alias aliasee           (the aliasee as written: no constant cast)
//   G var ref...              a global variable, and what its initializer names
//   R fn ref...               what fn's instructions name
//   E fn callee...            its direct calls and invokes
//   I fn n                    its indirect call sites
//   L fn class...             the classes it allocas ("class.X"/"struct.X" -> X)
//
// usage: ut-cg IN.bc > OUT.cg
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <set>
#include <string>
#include <vector>

using namespace llvm;

// as AsmWriter's printLLVMNameWithoutPrefix: quoted unless [-A-Za-z0-9._]
// and no leading digit; quoted, a byte outside printable ASCII, '"' or '\'
// is \XX
static std::string spell(StringRef N) {
  bool Q = N.empty() || isdigit(static_cast<unsigned char>(N[0]));
  for (unsigned char C : N)
    if (!isalnum(C) && C != '-' && C != '.' && C != '_') { Q = true; break; }
  if (!Q) return N.str();
  std::string S = "\"";
  for (unsigned char C : N) {
    if (isprint(C) && C != '"' && C != '\\') S += C;
    else {
      const char *H = "0123456789ABCDEF";
      S += '\\'; S += H[C >> 4]; S += H[C & 15];
    }
  }
  return S + "\"";
}

static std::string nameOf(const GlobalValue &G) {
  return G.hasName() ? spell(G.getName()) : std::string("__unnamed");
}

// the globals a value names, through constant expressions and aggregates
static void collect(const Value *V, std::set<const GlobalValue *> &Out,
                    std::set<const Constant *> &Seen) {
  if (auto *G = dyn_cast<GlobalValue>(V)) { Out.insert(G); return; }
  auto *C = dyn_cast<Constant>(V);
  if (!C || !Seen.insert(C).second) return;
  for (const Use &U : C->operands()) collect(U.get(), Out, Seen);
}

int main(int argc, char **argv) {
  if (argc != 2) { errs() << "usage: ut-cg IN.bc > OUT.cg\n"; return 1; }
  LLVMContext Ctx;
  SMDiagnostic Err;
  std::unique_ptr<Module> M = parseIRFile(argv[1], Err, Ctx);
  if (!M) { Err.print(argv[0], errs()); return 1; }
  raw_ostream &OS = outs();

  for (const GlobalVariable &G : M->globals()) {
    OS << "G\t" << nameOf(G);
    if (G.hasInitializer()) {
      std::set<const GlobalValue *> Refs;
      std::set<const Constant *> Seen;
      collect(G.getInitializer(), Refs, Seen);
      std::set<std::string> Names;
      for (const GlobalValue *R : Refs) Names.insert(nameOf(*R));
      for (const std::string &N : Names) OS << "\t" << N;
    }
    OS << "\n";
  }
  for (const GlobalAlias &A : M->aliases()) {
    const Constant *T = A.getAliasee()->stripPointerCasts();
    if (auto *G = dyn_cast<GlobalValue>(T))
      OS << "A\t" << nameOf(A) << "\t" << nameOf(*G) << "\n";
  }
  for (const Function &F : *M) {
    std::string FN = nameOf(F);
    if (F.isDeclaration()) { OS << "X\t" << FN << "\n"; continue; }
    std::string File;
    if (const DISubprogram *SP = F.getSubprogram())
      if (const DIFile *DF = SP->getFile()) File = DF->getFilename().str();
    unsigned Size = 0, Indirect = 0;
    std::set<std::string> Refs, Edges, Classes;
    std::set<const Constant *> Seen;
    for (const Instruction &I : instructions(F)) {
      ++Size;
      std::set<const GlobalValue *> GV;
      for (const Use &U : I.operands()) collect(U.get(), GV, Seen);
      for (const GlobalValue *G : GV) Refs.insert(nameOf(*G));
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        if (isa<InlineAsm>(CB->getCalledOperand())) continue;
        const Value *Callee = CB->getCalledOperand()->stripPointerCasts();
        if (auto *G = dyn_cast<GlobalValue>(Callee)) Edges.insert(nameOf(*G));
        else ++Indirect;
      }
      if (auto *AI = dyn_cast<AllocaInst>(&I))
        if (auto *ST = dyn_cast<StructType>(AI->getAllocatedType()))
          if (ST->hasName()) {
            StringRef N = ST->getName();
            if (N.consume_front("class.") || N.consume_front("struct."))
              Classes.insert(N.str());
          }
    }
    OS << "D\t" << FN << "\t" << File << "\t" << Size << "\t"
       << (F.hasFnAttribute(Attribute::NoReturn) ? 1 : 0) << "\n";
    if (!Refs.empty()) {
      OS << "R\t" << FN;
      for (const std::string &N : Refs) OS << "\t" << N;
      OS << "\n";
    }
    if (!Edges.empty()) {
      OS << "E\t" << FN;
      for (const std::string &N : Edges) OS << "\t" << N;
      OS << "\n";
    }
    if (Indirect) OS << "I\t" << FN << "\t" << Indirect << "\n";
    if (!Classes.empty()) {
      OS << "L\t" << FN;
      for (const std::string &N : Classes) OS << "\t" << N;
      OS << "\n";
    }
  }
  return 0;
}
