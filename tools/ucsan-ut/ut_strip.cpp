// ut-strip: a test's module keeps only what no prebuilt library provides.
//
// Library code (what a unit test's scope calls out of it, run concretely) is
// TaintPass's only.  Built once into an archive (a v8 tree's objects, each
// TaintPass'd as library code, weak), it need not be in every test's module:
// llvm-link --only-needed brings in all of v8 for an Isolate test (90k
// functions, ~1.5h of opt and llc per test).  Every definition the archive
// also defines becomes a declaration here, but for the scope's functions, whose
// UCSan copy (strong) is the point of the build -- and wins over the archive's
// weak one, for library code's calls too.  What only this module defines (the
// test's own code, a template only it instantiates) stays.
//
// usage: ut-strip IN.bc OUT.bc DEFS KEEP
//   DEFS: the symbols the archive defines, a function's without ".taint"
//   KEEP: the names whose bodies stay (the scope), one per line
//   (globaldce afterwards drops what only the dropped bodies used)
//
// ut-strip --promote IN.bc OUT.bc TAG: each of an object's internal symbols
// made external, as NAME.ut.TAG (TAG: unique to the object), before both the
// archive and the bitcode a test's module is linked from are built from it.
// Otherwise a module that keeps an internal function keeps its own copy of the
// state it shares with the rest of its file: v8.cc's v8_startup_state_, which
// the module's V8::InitializePlatform advanced and the archive's
// V8::Initialize found still idle ("Wrong initialization order").  External,
// the module's references are the archive's, and an internal function in the
// scope is UCSan's for library code too.  (Private symbols -- string literals
// -- stay: a copy of a constant is the constant.)
//
// ut-strip --extern IN.bc OUT.bc NAMES: the named internal definitions made
// external, names kept: the entry (gen_entry.py, its own module) calls a
// test's TestBody, factory and destructor directly, and a test class in an
// anonymous namespace has them internal.  llvm-link does not bind a
// declaration to an internal definition; it renames the definition (.N) and
// the entry's calls stay undefined.
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

using namespace llvm;

static bool readNames(const char *Path, std::unordered_set<std::string> &S) {
  std::ifstream In(Path);
  if (!In) { errs() << Path << ": cannot open\n"; return false; }
  for (std::string L; std::getline(In, L);)
    if (!L.empty()) S.insert(L);
  return true;
}

static int promote(const char *In, const char *Out, const std::string &Tag) {
  LLVMContext Ctx;
  SMDiagnostic Err;
  std::unique_ptr<Module> M = parseIRFile(In, Err, Ctx);
  if (!M) { Err.print("ut-strip", errs()); return 1; }
  unsigned N = 0;
  for (GlobalValue &G : M->global_values()) {
    if (!G.hasInternalLinkage() || G.getName().empty() ||
        G.getName().starts_with("llvm."))
      continue;
    G.setName(G.getName() + ".ut." + Tag);
    G.setLinkage(GlobalValue::ExternalLinkage);
    G.setVisibility(GlobalValue::DefaultVisibility);
    G.setDSOLocal(false);   // no local alias: a strong copy may override it
    ++N;
  }
  if (verifyModule(*M, &errs())) return 1;
  std::error_code EC;
  raw_fd_ostream OS(Out, EC);
  if (EC) { errs() << Out << ": " << EC.message() << "\n"; return 1; }
  WriteBitcodeToFile(*M, OS);
  return 0;
}

static int externalize(const char *In, const char *Out, const char *Names) {
  std::unordered_set<std::string> S;
  if (!readNames(Names, S)) return 1;
  LLVMContext Ctx;
  SMDiagnostic Err;
  std::unique_ptr<Module> M = parseIRFile(In, Err, Ctx);
  if (!M) { Err.print("ut-strip", errs()); return 1; }
  for (GlobalValue &G : M->global_values())
    if (G.hasLocalLinkage() && !G.isDeclaration() &&
        S.count(G.getName().str())) {
      G.setLinkage(GlobalValue::ExternalLinkage);
      G.setVisibility(GlobalValue::DefaultVisibility);
    }
  if (verifyModule(*M, &errs())) return 1;
  std::error_code EC;
  raw_fd_ostream OS(Out, EC);
  if (EC) { errs() << Out << ": " << EC.message() << "\n"; return 1; }
  WriteBitcodeToFile(*M, OS);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 5 && std::string(argv[1]) == "--promote")
    return promote(argv[2], argv[3], argv[4]);
  if (argc == 5 && std::string(argv[1]) == "--extern")
    return externalize(argv[2], argv[3], argv[4]);
  if (argc != 5) {
    errs() << "usage: ut-strip IN.bc OUT.bc DEFS KEEP\n"
              "       ut-strip --promote IN.bc OUT.bc TAG\n"
              "       ut-strip --extern IN.bc OUT.bc NAMES\n";
    return 1;
  }
  std::unordered_set<std::string> Defs, Keep;
  if (!readNames(argv[3], Defs) || !readNames(argv[4], Keep)) return 1;

  LLVMContext Ctx;
  SMDiagnostic Err;
  std::unique_ptr<Module> M = parseIRFile(argv[1], Err, Ctx);
  if (!M) { Err.print(argv[0], errs()); return 1; }

  // an alias the archive does not define keeps what it aliases: an alias of
  // a declaration is no alias
  for (GlobalAlias &A : M->aliases())
    if (!Defs.count(A.getName().str()))
      if (const GlobalObject *O = A.getAliaseeObject())
        Keep.insert(O->getName().str());
  auto drop = [&](const GlobalValue &G) {
    return !G.isDeclaration() && !G.hasLocalLinkage() &&
           Defs.count(G.getName().str()) && !Keep.count(G.getName().str());
  };

  unsigned Fns = 0, Vars = 0, Aliases = 0;
  for (Function &F : *M) {
    if (!drop(F)) continue;
    F.deleteBody();          // (external linkage)
    F.setComdat(nullptr);
    F.clearMetadata();       // a declaration's !dbg may not be distinct
    F.setPersonalityFn(nullptr);
    ++Fns;
  }
  for (GlobalVariable &G : M->globals()) {
    if (!drop(G)) continue;
    G.setInitializer(nullptr);
    G.setLinkage(GlobalValue::ExternalLinkage);
    G.setComdat(nullptr);
    G.clearMetadata();
    ++Vars;
  }
  // an alias the archive defines, of what is now a declaration: a declaration
  std::vector<GlobalAlias *> Dead;
  for (GlobalAlias &A : M->aliases()) {
    const GlobalObject *O = A.getAliaseeObject();
    if (!Defs.count(A.getName().str()) || (O && !O->isDeclaration())) continue;
    GlobalValue *D;
    if (auto *FT = dyn_cast<FunctionType>(A.getValueType()))
      D = Function::Create(FT, GlobalValue::ExternalLinkage,
                           A.getAddressSpace(), "", M.get());
    else
      D = new GlobalVariable(*M, A.getValueType(), false,
                             GlobalValue::ExternalLinkage, nullptr, "", nullptr,
                             GlobalValue::NotThreadLocal, A.getAddressSpace());
    D->takeName(&A);
    A.replaceAllUsesWith(D);
    Dead.push_back(&A);
  }
  for (GlobalAlias *A : Dead) { A->eraseFromParent(); ++Aliases; }

  // A static constructor left to the archive is its object's: that object's
  // .init_array runs it, whenever the object is linked in.  Listed in the
  // module's llvm.global_ctors as well, it ran twice -- gmock's
  // g_gmock_implicit_sequence made two pthread keys and registered two
  // destructors, and the second's pthread_key_delete failed: gtest's abort at
  // exit, once the test had passed.
  unsigned Ctors = 0;
  for (const char *Name : {"llvm.global_ctors", "llvm.global_dtors"}) {
    GlobalVariable *GV = M->getNamedGlobal(Name);
    if (!GV || !GV->hasInitializer()) continue;
    auto *CA = dyn_cast<ConstantArray>(GV->getInitializer());
    if (!CA) continue;
    SmallVector<Constant *, 16> Kept;
    for (Use &U : CA->operands()) {
      auto *E = cast<ConstantStruct>(U.get());
      auto *F = dyn_cast<Function>(E->getOperand(1)->stripPointerCasts());
      if (F && F->isDeclaration() && Defs.count(F->getName().str())) {
        ++Ctors;
        continue;
      }
      Kept.push_back(E);
    }
    if (Kept.size() == CA->getNumOperands()) continue;
    if (Kept.empty()) { GV->eraseFromParent(); continue; }
    auto *AT = ArrayType::get(CA->getType()->getElementType(), Kept.size());
    auto *NGV = new GlobalVariable(*M, AT, false, GV->getLinkage(),
                                   ConstantArray::get(AT, Kept), "", GV);
    NGV->takeName(GV);
    GV->eraseFromParent();
  }

  if (verifyModule(*M, &errs())) return 1;
  std::error_code EC;
  raw_fd_ostream OS(argv[2], EC);
  if (EC) { errs() << argv[2] << ": " << EC.message() << "\n"; return 1; }
  WriteBitcodeToFile(*M, OS);
  errs() << "ut-strip: " << Fns << " functions, " << Vars << " variables, "
         << Aliases << " aliases, " << Ctors
         << " static constructors left to the archive\n";
  return 0;
}
