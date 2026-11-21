// ut-entry: a failed check on what the test itself controls is an assumption,
// not a finding.
//
// Two kinds of check fail on seeds the test can never have, and both make the
// seed invalid input (ucsan_invalid_input, exit 122) instead of a PANIC:
//
// 1. The test's own checks.  A fixture CHECKs what an out-of-scope dependency
//    returned (CHECK_NOT_NULL(platform_.get())); out of scope that value is
//    under-constrained, so the check fails on some seeds.  In the test's
//    functions (the allow file's harness-* entries) each fatal reporter call
//    becomes a call to its assumption.
//
// 2. The unit's preconditions on what the test passes it.  With its arguments
//    symbolized, the test calls the unit's API outside its contract
//    (BitVector::Add's DCHECK(i < length())): 92% of BitVectorTest's seeds were
//    such PANICs.  The same check reached from inside the unit is a finding,
//    though, so the function itself keeps it.  Each API function the test
//    calls directly is specialized for that call instead: its clone
//    (F.ut_entry, which keeps F's debug info) calls the assumptions in place of
//    the fatal reporters it calls, and so do the check helpers it calls
//    (v8::base::Check*Impl, whose failure path is MakeCheckOpString).  The
//    test's call sites call the clone; the unit's own calls still call F.
//
// A test function's calls to the check helpers are specialized the same way,
// so its CHECK_EQ is an assumption as its CHECK is.
//
// The test's functions are the allow file's, and with --harness-file every
// function whose debug info places it in a file under that path: the allow
// file has only what ut-unit's walk saw, the test's own TU, and a helper
// another test file defines is test code too (function-tester.cc's
// CompileRun, whose ToLocalChecked is how a test says its JS compiles).
//
// usage: ut-entry IN.bc OUT.bc ALLOW
//          [--fatal MANGLED]... [--fatal-prefix NAME]...
//          [--helper-prefix NAME]... [--harness-file PATH]...
//          [--unit-preconditions off]
//   ALLOW: the scope's allow file; its harness-prefix / harness-exact lines
//          name the test's functions (ut_scope.py)
//   PATH:  a prefix of the debug info's file name, as the compiler saw it
//          (v8: ../../test/ and V8_DIR/test/, both spellings occur)
//   --changed-out FILE: the test functions whose bodies it changed, one
//          mangled name per line.  A prebuilt archive's copy of one has none
//          of the changes, so it must not replace this one (ut-strip KEEP):
//          function-tester.cc's CompileRun is in the archive and not in the
//          scope.
//   NAME:  matched against the bare name (ns::C::f: no return type, template
//          arguments or parameters), as cg_scope.py matches
//   --unit-preconditions off: step 2 (the unit's checks at the test's calls
//          into it as assumptions) is not done; the test's own checks still
//          are.  For a test with a spec (UT_SPEC): the spec states the API's
//          preconditions from its contract, and the unit's CHECK/DCHECK/
//          UNREACHABLE stay detectors -- assumed, they hid a death test's
//          death and every input where the unit is stricter than its contract
//          (bignum: ShiftLeft(-1), AssignPowerUInt16's EnsureCapacity)
//   prints the __ucsan_ut_assume.N names it declared, one per fatal reporter
//   (each to be mapped to ucsan_invalid_input)
// ut-entry --bare < NAMES: the bare-name rule alone, for testing it
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace llvm;

static std::vector<std::string> FatalPrefixes, HelperPrefixes, HarnessFiles;
static bool UnitPreconditions = true;  // --unit-preconditions off: false
static std::set<std::string> FatalNames;

static bool endsWith(const std::string &S, const std::string &X) {
  return S.size() >= X.size() && S.compare(S.size() - X.size(), X.size(), X) == 0;
}

// as the scripts' ut_names.py: "R ns::C<T>::f<U>(int) const" -> "ns::C::f".
// The name is found from the end: the parameter list is the last top-level
// "(...)" (before cv/ref qualifiers and a requires-clause), and the name is the
// last top-level word before it, or "operator T" for a conversion operator.
static std::string bare(std::string D) {
  for (const char *P : {"virtual thunk to ", "non-virtual thunk to "})
    if (D.rfind(P, 0) == 0) D = D.substr(strlen(P));
  for (size_t I; (I = D.find("(anonymous namespace)::")) != std::string::npos;)
    D.erase(I, strlen("(anonymous namespace)::"));
  // a clone's suffix, " (.ut_entry)"; an allow entry's "NAME("
  if (endsWith(D, ")")) {
    size_t I = D.rfind(" (.");
    if (I != std::string::npos && D.find_first_of("()", I + 2) == D.size() - 1)
      D.resize(I);
  }
  if (endsWith(D, "(")) D.pop_back();
  // operator names that hold a bracket are kept whole while brackets count
  std::vector<std::string> Ops;
  static const char *OpNames[] = {"<<=", ">>=", "<=>", "<<", ">>", "<=", ">=",
                                  "->*", "->",  "<",   ">",  "()", "[]"};
  std::string P;
  for (size_t I = 0; I < D.size();) {
    if (D.compare(I, 8, "operator") == 0) {
      bool Hit = false;
      for (const char *O : OpNames)
        if (D.compare(I + 8, strlen(O), O) == 0) {
          P += "operator\x01" + std::to_string(Ops.size()) + "\x01";
          Ops.push_back(O);   // the placeholder keeps "operator"
          I += 8 + strlen(O);
          Hit = true;
          break;
        }
      if (Hit) continue;
    }
    P += D[I++];
  }
  D = P;
  for (size_t I; (I = D.find("[abi:")) != std::string::npos;)
    D.erase(I, D.find(']', I) - I + 1);
  int Depth = 0;
  for (size_t I = 0; I < D.size(); ++I) {
    char C = D[I];
    if (C == '(' || C == '<') ++Depth;
    else if (C == ')' || C == '>') --Depth;
    else if (Depth == 0 && D.compare(I, 10, " requires ") == 0) { D.resize(I); break; }
  }
  std::string S = D;
  while (!S.empty() && S.back() == ' ') S.pop_back();
  for (bool More = true; More;) {
    More = false;
    for (const char *Q : {" const", " volatile", " &&", " &", " noexcept"})
      if (endsWith(S, Q)) {
        S.resize(S.size() - strlen(Q));
        More = true;
        break;
      }
  }
  if (endsWith(S, ")")) {
    int D2 = 0;
    for (size_t J = S.size(); J-- > 0;) {
      if (S[J] == ')') ++D2;
      else if (S[J] == '(' && --D2 == 0) { S.resize(J); break; }
    }
  }
  std::string T;
  Depth = 0;
  for (char C : S) {
    if (C == '<') { ++Depth; continue; }
    if (C == '>') { Depth = Depth > 0 ? Depth - 1 : 0; continue; }
    if (Depth == 0) T += C;
  }
  std::vector<std::string> Words;
  std::string Cur;
  Depth = 0;
  for (char C : T) {
    if (C == '(') ++Depth;
    else if (C == ')') --Depth;
    if (C == ' ' && Depth == 0) {
      if (!Cur.empty()) Words.push_back(Cur);
      Cur.clear();
    } else {
      Cur += C;
    }
  }
  if (!Cur.empty()) Words.push_back(Cur);
  std::string Name = Words.empty() ? T : Words.back();
  for (size_t I = 0; I < Words.size(); ++I)
    if (Words[I] == "operator" || endsWith(Words[I], "::operator")) {
      Name = Words[I];
      for (size_t K = I + 1; K < Words.size(); ++K) Name += " " + Words[K];
      break;
    }
  std::string R;
  for (size_t I = 0; I < Name.size();) {
    if (Name[I] == '\x01') {
      size_t E = Name.find('\x01', I + 1);
      R += Ops[std::stoul(Name.substr(I + 1, E - I - 1))];
      I = E + 1;
    } else {
      R += Name[I++];
    }
  }
  return R;
}

static std::string bareOf(const Function &F) {
  return bare(demangle(F.getName().str()));
}

static bool beginsAny(const std::string &B, const std::vector<std::string> &Ps) {
  for (auto &P : Ps)
    if (B.compare(0, P.size(), P) == 0)
      return true;
  return false;
}

static bool isFatal(const Function &F) {
  return FatalNames.count(F.getName().str()) ||
         beginsAny(bareOf(F), FatalPrefixes);
}

static bool isHelper(const Function &F) {
  return !F.isDeclaration() && beginsAny(bareOf(F), HelperPrefixes);
}

// defined in a file under one of the --harness-file paths
static bool inHarnessFile(const Function &F) {
  const DISubprogram *SP = F.getSubprogram();
  return SP && beginsAny(SP->getFilename().str(), HarnessFiles);
}

// through an alias too: a complete-object constructor (C1) is an alias of the
// base-object one (C2), so a test's `BytecodeArrayBuilder builder(...)` was
// not seen as a call into the unit, and its CHECK_GE on the symbolized
// parameter_count stayed a PANIC
static Function *directCallee(Instruction &I) {
  auto *CB = dyn_cast<CallBase>(&I);
  if (!CB) return nullptr;
  return dyn_cast_or_null<Function>(
      CB->getCalledOperand()->stripPointerCastsAndAliases());
}

struct Specializer {
  Module &M;
  std::map<Function *, Function *> Assume;    // fatal reporter -> its assumption
  std::map<Function *, Function *> Clones;    // F -> F.ut_entry, or null
  std::set<Function *> InProgress;
  std::vector<std::string> NewNames;

  explicit Specializer(Module &M) : M(M) {}

  Function *assumeFor(Function *Fatal) {
    auto It = Assume.find(Fatal);
    if (It != Assume.end()) return It->second;
    std::string Name = "__ucsan_ut_assume." + std::to_string(Assume.size());
    Function *A = Function::Create(Fatal->getFunctionType(),
                                   GlobalValue::ExternalLinkage, Name, M);
    A->setAttributes(Fatal->getAttributes());
    NewNames.push_back(Name);
    return Assume[Fatal] = A;
  }

  // what each call in F becomes when F's checks are assumptions: a fatal
  // reporter its assumption, a check helper that checks its clone
  std::map<Function *, Function *> replacements(Function *F) {
    std::map<Function *, Function *> Repl;
    for (Instruction &I : instructions(F)) {
      Function *Callee = directCallee(I);
      if (!Callee || Repl.count(Callee)) continue;
      if (isFatal(*Callee))
        Repl[Callee] = assumeFor(Callee);
      else if (isHelper(*Callee))
        if (Function *C = specialize(Callee))
          Repl[Callee] = C;
    }
    return Repl;
  }

  static unsigned redirect(Function *F,
                           const std::map<Function *, Function *> &Repl) {
    unsigned N = 0;
    for (Instruction &I : instructions(F)) {
      Function *Callee = directCallee(I);
      auto R = Callee ? Repl.find(Callee) : Repl.end();
      if (R != Repl.end()) {
        cast<CallBase>(I).setCalledOperand(R->second);
        ++N;
      }
    }
    return N;
  }

  // the clone of F in which its checks are assumptions, or null if F's own
  // body checks nothing
  Function *specialize(Function *F) {
    auto It = Clones.find(F);
    if (It != Clones.end()) return It->second;
    if (F->isDeclaration() || InProgress.count(F)) return nullptr;
    InProgress.insert(F);
    auto Repl = replacements(F);
    InProgress.erase(F);
    if (Repl.empty())
      return Clones[F] = nullptr;
    ValueToValueMapTy VMap;
    Function *C = CloneFunction(F, VMap);
    C->setName(F->getName() + ".ut_entry");
    C->setLinkage(GlobalValue::InternalLinkage);
    C->setComdat(nullptr);
    redirect(C, Repl);
    return Clones[F] = C;
  }
};

int main(int argc, char **argv) {
  // the bare-name rule alone, one demangled name per line (to test it)
  if (argc == 2 && std::string(argv[1]) == "--bare") {
    for (std::string L; std::getline(std::cin, L);) outs() << bare(L) << "\n";
    return 0;
  }
  if (argc < 4) {
    errs() << "usage: ut-entry IN.bc OUT.bc ALLOW [--fatal M]... "
              "[--fatal-prefix N]... [--helper-prefix N]... "
              "[--harness-file P]... [--unit-preconditions off] "
              "[--changed-out FILE]\n";
    return 1;
  }
  std::string ChangedOut;
  for (int I = 4; I + 1 < argc; I += 2) {
    std::string K = argv[I], V = argv[I + 1];
    if (K == "--fatal") FatalNames.insert(V);
    else if (K == "--fatal-prefix") FatalPrefixes.push_back(V);
    else if (K == "--helper-prefix") HelperPrefixes.push_back(V);
    else if (K == "--harness-file") HarnessFiles.push_back(V);
    else if (K == "--changed-out") ChangedOut = V;
    else if (K == "--unit-preconditions") UnitPreconditions = V != "off";
    else { errs() << "unknown option " << K << "\n"; return 1; }
  }
  // the test's functions, as ut_scope.py writes them: an allow entry is a
  // demangled name, matched by its bare name
  std::set<std::string> HarnessExact;
  std::vector<std::string> HarnessPrefixes;
  std::ifstream AL(argv[3]);
  if (!AL) { errs() << argv[3] << ": cannot open\n"; return 1; }
  for (std::string L; std::getline(AL, L);) {
    size_t Sp = L.find(' ');
    if (Sp == std::string::npos) continue;
    std::string K = L.substr(0, Sp), N = L.substr(Sp + 1);
    if (K == "harness-exact") HarnessExact.insert(bare(N + "("));
    else if (K == "harness-prefix") HarnessPrefixes.push_back(bare(N + "("));
  }

  LLVMContext Ctx;
  SMDiagnostic Err;
  std::unique_ptr<Module> M = parseIRFile(argv[1], Err, Ctx);
  if (!M) { Err.print(argv[0], errs()); return 1; }

  std::vector<Function *> Harness;
  std::set<Function *> IsHarness;
  for (Function &F : *M) {
    if (F.isDeclaration()) continue;
    std::string B = bareOf(F);
    if (HarnessExact.count(B) || beginsAny(B, HarnessPrefixes) ||
        inHarnessFile(F)) {
      Harness.push_back(&F);
      IsHarness.insert(&F);
    }
  }

  Specializer S(*M);
  unsigned Own = 0, Sites = 0;
  std::set<Function *> Entries, Changed;
  for (Function *H : Harness) {
    // 1. the test's own checks
    unsigned N = Specializer::redirect(H, S.replacements(H));
    Own += N;
    if (N) Changed.insert(H);
    // 2. the unit's preconditions, at the test's calls into it
    if (!UnitPreconditions) continue;
    for (Instruction &I : instructions(H)) {
      Function *Callee = directCallee(I);
      if (!Callee || Callee->isDeclaration() || IsHarness.count(Callee) ||
          isFatal(*Callee) || isHelper(*Callee) ||
          Callee->getName().ends_with(".ut_entry"))
        continue;
      if (Function *C = S.specialize(Callee)) {
        cast<CallBase>(I).setCalledOperand(C);
        Entries.insert(Callee);
        Changed.insert(H);
        ++Sites;
      }
    }
  }
  if (verifyModule(*M, &errs())) return 1;
  if (!ChangedOut.empty()) {
    std::ofstream CO(ChangedOut);
    if (!CO) { errs() << ChangedOut << ": cannot open\n"; return 1; }
    for (Function *F : Changed) CO << F->getName().str() << "\n";
  }
  std::error_code EC;
  raw_fd_ostream OS(argv[2], EC);
  if (EC) { errs() << argv[2] << ": " << EC.message() << "\n"; return 1; }
  WriteBitcodeToFile(*M, OS);
  errs() << Harness.size() << " test functions: " << Own
         << " of their own checks and " << Sites << " calls to "
         << Entries.size() << " unit functions made assumptions ("
         << S.NewNames.size() << " reporters)\n";
  for (auto &N : S.NewNames) outs() << N << "\n";
  return 0;
}
