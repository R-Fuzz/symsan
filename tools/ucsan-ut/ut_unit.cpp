// ut-unit: what does each gtest TEST call into, at the source level?
//
// For every *_Test::TestBody defined in the main file, walk the calls (calls,
// constructor calls, operators, function addresses).  Code the test itself
// defines -- fixture methods, helpers, lambdas, anything spelled under test/ --
// is transparent: the walk goes into it.  The first call that leaves test code
// is an API call; it is recorded with its owner, the outermost class enclosing
// the callee (a nested Iterator belongs to its BitVector), or for a free
// function the file that declares it.  gtest (::testing) and the standard
// library are not APIs under test.
//
// Then, for each owner class, its shape: members with their access, nested
// classes, friends (debug info has none of these: clang emits no
// DW_TAG_friend), and bases.  The unit is decided from this by ut_unit.py.
//
// usage: ut-unit -p BUILD_DIR FILE... > out.jsonl
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclFriend.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"
#include <map>
#include <set>

using namespace clang;
using namespace clang::tooling;

static llvm::cl::OptionCategory Cat("ut-unit");

namespace {

std::string fileOf(const SourceManager &SM, SourceLocation L) {
  L = SM.getExpansionLoc(L);
  if (L.isInvalid()) return "";
  if (auto F = SM.getFileEntryRefForID(SM.getFileID(L)))
    return F->getName().str();
  return "";
}

// v8's test code: test/, but not third_party/googletest
bool isTestFile(StringRef F) {
  return (F.contains("/test/") || F.starts_with("test/") ||
          F.starts_with("../../test/")) &&
         !F.contains("googletest") && !F.contains("googlemock");
}

bool inNamespace(const Decl *D, StringRef NS) {
  for (const DeclContext *C = D->getDeclContext(); C; C = C->getParent())
    if (auto *N = dyn_cast<NamespaceDecl>(C))
      if (N->getIdentifier() && N->getName() == NS && isa<TranslationUnitDecl>(N->getParent()))
        return true;
  return false;
}

bool isLibrary(const Decl *D) {
  return inNamespace(D, "std") || inNamespace(D, "testing") ||
         inNamespace(D, "__gnu_cxx");
}

// the outermost class enclosing D (D's own class for a method), or null
const CXXRecordDecl *ownerOf(const Decl *D) {
  const CXXRecordDecl *Owner = nullptr;
  for (const DeclContext *C = D->getDeclContext(); C; C = C->getParent()) {
    if (auto *R = dyn_cast<CXXRecordDecl>(C)) {
      if (R->isLambda()) continue;
      Owner = R;
    }
  }
  if (auto *R = dyn_cast<CXXRecordDecl>(D)) Owner = Owner ? Owner : R;
  if (Owner)
    if (auto *P = Owner->getTemplateInstantiationPattern()) Owner = P;
  return Owner;
}

std::string accessName(AccessSpecifier A) {
  switch (A) {
  case AS_public: return "public";
  case AS_protected: return "protected";
  case AS_private: return "private";
  default: return "none";
  }
}

std::string qname(const NamedDecl *D) {
  std::string S;
  llvm::raw_string_ostream OS(S);
  PrintingPolicy PP(D->getASTContext().getLangOpts());
  PP.SuppressUnwrittenScope = true;
  D->printQualifiedName(OS, PP);
  return S;
}

struct Call {
  std::string callee, owner, file, access, kind;
  bool assert_ = false;  // only inside EXPECT_*/ASSERT_*: the test inspects it
  bool const_ = false;   // a const member function: observes, does not act
  bool operator<(const Call &O) const {
    return std::tie(callee, owner, file, assert_) <
           std::tie(O.callee, O.owner, O.file, O.assert_);
  }
};

class Walker : public RecursiveASTVisitor<Walker> {
public:
  Walker(ASTContext &Ctx, std::set<Call> &Calls,
         std::set<const CXXRecordDecl *> &Owners,
         std::set<const FunctionDecl *> &Seen)
      : Ctx(Ctx), SM(Ctx.getSourceManager()), Calls(Calls), Owners(Owners),
        Seen(Seen) {}
  bool shouldVisitTemplateInstantiations() const { return true; }
  bool shouldVisitLambdaBodies() const { return true; }

  // arrange/act/assert: a call in an EXPECT_/ASSERT_ argument (or in a test
  // helper called from one) inspects the result; it does not exercise the unit
  bool inAssertMacro(SourceLocation L) {
    while (L.isMacroID()) {
      StringRef N = Lexer::getImmediateMacroName(L, SM, Ctx.getLangOpts());
      if (N.starts_with("EXPECT_") || N.starts_with("ASSERT_")) return true;
      L = SM.getImmediateMacroCallerLoc(L);
    }
    return false;
  }
  void callee(const FunctionDecl *F, const char *Kind, SourceLocation At) {
    if (!F) return;
    bool Assert = InAssert || inAssertMacro(At);
    const FunctionDecl *Pat = F->getTemplateInstantiationPattern();
    const FunctionDecl *Src = Pat ? Pat : F;
    std::string File = fileOf(SM, Src->getLocation());
    if (isLibrary(F)) return;
    if (isTestFile(File)) {
      // test code is transparent: walk into its definition
      const FunctionDecl *Def = nullptr;
      if (F->hasBody(Def) && Seen.insert(Def).second && Seen.size() < 2000) {
        bool Saved = InAssert;
        InAssert = Assert;
        TraverseDecl(const_cast<FunctionDecl *>(Def));
        InAssert = Saved;
      }
      return;
    }
    if (F->isImplicit() && !isa<CXXConstructorDecl>(F) &&
        !isa<CXXDestructorDecl>(F) && !isa<CXXMethodDecl>(F))
      return;
    Call C;
    C.callee = qname(Src);
    C.kind = Kind;
    C.assert_ = Assert;
    if (auto *M = dyn_cast<CXXMethodDecl>(F)) C.const_ = M->isConst();
    C.access = accessName(F->getAccess());
    if (const CXXRecordDecl *O = ownerOf(Src)) {
      if (isTestFile(fileOf(SM, O->getLocation()))) return;
      C.owner = qname(O);
      C.file = fileOf(SM, O->getLocation());
      Owners.insert(O);
    } else {
      C.file = File;
    }
    Calls.insert(C);
  }
  bool VisitCallExpr(CallExpr *E) {
    callee(E->getDirectCallee(), "call", E->getBeginLoc());
    return true;
  }
  bool VisitCXXConstructExpr(CXXConstructExpr *E) {
    callee(E->getConstructor(), "ctor", E->getBeginLoc());
    return true;
  }
  bool VisitCXXDeleteExpr(CXXDeleteExpr *E) {
    if (auto *R = E->getDestroyedType()->getAsCXXRecordDecl())
      callee(R->getDestructor(), "dtor", E->getBeginLoc());
    return true;
  }
  bool VisitDeclRefExpr(DeclRefExpr *E) {
    if (auto *F = dyn_cast<FunctionDecl>(E->getDecl())) callee(F, "addr", E->getBeginLoc());
    return true;
  }

private:
  ASTContext &Ctx;
  const SourceManager &SM;
  std::set<Call> &Calls;
  std::set<const CXXRecordDecl *> &Owners;
  std::set<const FunctionDecl *> &Seen;
  bool InAssert = false;
};

bool nameIs(const NamedDecl *D, StringRef N) {
  return D->getIdentifier() && D->getName() == N;
}

bool derivesFromTestingTest(const CXXRecordDecl *R) {
  if (!R || !R->hasDefinition()) return false;
  bool Found = false;
  R->forallBases([&](const CXXRecordDecl *B) {
    if (qname(B) == "testing::Test") Found = true;
    return true;
  });
  return Found;
}

llvm::json::Object classShape(const CXXRecordDecl *R, const SourceManager &SM) {
  llvm::json::Object O;
  O["class"] = qname(R);
  O["file"] = fileOf(SM, R->getLocation());
  if (!R->hasDefinition()) { O["complete"] = false; return O; }
  R = R->getDefinition();
  llvm::json::Array Members, Nested, Friends, Bases;
  for (const Decl *D : R->decls()) {
    if (D->isImplicit()) continue;
    if (auto *FD = dyn_cast<FriendDecl>(D)) {
      llvm::json::Object F;
      if (NamedDecl *ND = FD->getFriendDecl()) {
        if (auto *FT = dyn_cast<FunctionTemplateDecl>(ND)) ND = FT->getTemplatedDecl();
        F["kind"] = isa<FunctionDecl>(ND) ? "function" : "decl";
        F["name"] = qname(ND);
      } else if (TypeSourceInfo *T = FD->getFriendType()) {
        F["kind"] = "class";
        if (auto *FR = T->getType()->getAsCXXRecordDecl()) F["name"] = qname(FR);
        else F["name"] = T->getType().getAsString();
      }
      Friends.push_back(std::move(F));
      continue;
    }
    if (auto *CR = dyn_cast<CXXRecordDecl>(D)) {
      if (CR->isThisDeclarationADefinition() || !CR->hasDefinition())
        Nested.push_back(llvm::json::Object{{"name", qname(CR)},
                                            {"access", accessName(CR->getAccess())}});
      continue;
    }
    const NamedDecl *ND = dyn_cast<NamedDecl>(D);
    if (!ND || isa<AccessSpecDecl>(D)) continue;
    std::string Kind = isa<FieldDecl>(D)                ? "field"
                       : isa<FunctionTemplateDecl>(D)   ? "method-template"
                       : isa<CXXMethodDecl>(D)          ? "method"
                       : isa<VarDecl>(D)                ? "static"
                                                        : "other";
    Members.push_back(llvm::json::Object{{"name", ND->getNameAsString()},
                                         {"kind", Kind},
                                         {"access", accessName(D->getAccess())}});
  }
  for (const CXXBaseSpecifier &B : R->bases())
    if (auto *BR = B.getType()->getAsCXXRecordDecl())
      Bases.push_back(llvm::json::Object{{"name", qname(BR)},
                                         {"access", accessName(B.getAccessSpecifier())}});
  O["members"] = std::move(Members);
  O["nested"] = std::move(Nested);
  O["friends"] = std::move(Friends);
  O["bases"] = std::move(Bases);
  return O;
}

class Consumer : public ASTConsumer {
public:
  void HandleTranslationUnit(ASTContext &Ctx) override {
    const SourceManager &SM = Ctx.getSourceManager();
    std::string Main = SM.getFileEntryRefForID(SM.getMainFileID())->getName().str();
    std::set<const CXXRecordDecl *> AllOwners;
    struct TestBodies : RecursiveASTVisitor<TestBodies> {
      std::vector<const CXXMethodDecl *> Bodies;
      const SourceManager *SM;
      bool VisitCXXMethodDecl(CXXMethodDecl *M) {
        if (nameIs(M, "TestBody") && M->hasBody() &&
            M->isThisDeclarationADefinition() &&
            SM->isInMainFile(SM->getExpansionLoc(M->getLocation())) &&
            derivesFromTestingTest(M->getParent()))
          Bodies.push_back(M);
        return true;
      }
    } TB;
    TB.SM = &SM;
    TB.TraverseDecl(Ctx.getTranslationUnitDecl());
    for (const CXXMethodDecl *M : TB.Bodies) {
      std::set<Call> Calls;
      std::set<const CXXRecordDecl *> Owners;
      std::set<const FunctionDecl *> Seen{M};
      Walker W(Ctx, Calls, Owners, Seen);
      W.TraverseStmt(M->getBody());
      // the fixture's SetUp/TearDown and constructors run too: their calls are
      // the test's environment, kept apart from the body's
      std::set<Call> FixCalls;
      std::set<const FunctionDecl *> FSeen{M};
      Walker FW(Ctx, FixCalls, Owners, FSeen);
      // the test class and the fixture classes it derives from in test code:
      // the harness, which runs instrumented with the unit
      llvm::json::Array TestClasses;
      for (const CXXRecordDecl *R = M->getParent(); R;) {
        TestClasses.push_back(qname(R));
        for (const CXXMethodDecl *FM : R->methods()) {
          const FunctionDecl *Def = nullptr;
          if ((isa<CXXConstructorDecl>(FM) || nameIs(FM, "SetUp") || nameIs(FM, "TearDown")) &&
              FM->hasBody(Def) && isTestFile(fileOf(SM, Def->getLocation())))
            FW.TraverseStmt(Def->getBody());
        }
        const CXXRecordDecl *Next = nullptr;
        for (const CXXBaseSpecifier &B : R->bases())
          if (auto *BR = B.getType()->getAsCXXRecordDecl())
            if (BR->hasDefinition() && isTestFile(fileOf(SM, BR->getLocation())))
              Next = BR->getDefinition();
        R = Next;
      }
      auto Emit = [](const std::set<Call> &S) {
        llvm::json::Array A;
        for (const Call &C : S)
          A.push_back(llvm::json::Object{{"callee", C.callee}, {"owner", C.owner},
                                         {"file", C.file}, {"access", C.access},
                                         {"kind", C.kind}, {"assert", C.assert_},
                                         {"const", C.const_}});
        return A;
      };
      llvm::json::Object O{{"tu", Main}, {"test", qname(M->getParent())},
                           {"calls", Emit(Calls)}, {"fixture_calls", Emit(FixCalls)},
                           {"helpers", (int64_t)Seen.size() - 1},
                           {"test_classes", std::move(TestClasses)},
                           {"test_fns", [&] {
                              llvm::json::Array A;
                              for (const FunctionDecl *F : Seen)
                                A.push_back(qname(F));
                              return A;
                            }()}};
      llvm::outs() << llvm::json::Value(std::move(O)) << "\n";
      AllOwners.insert(Owners.begin(), Owners.end());
    }
    for (const CXXRecordDecl *R : AllOwners) {
      llvm::json::Object O{{"tu", Main}, {"shape", classShape(R, SM)}};
      llvm::outs() << llvm::json::Value(std::move(O)) << "\n";
    }
  }
};

class Action : public ASTFrontendAction {
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &,
                                                 StringRef) override {
    return std::make_unique<Consumer>();
  }
};

} // namespace

int main(int argc, const char **argv) {
  auto OP = CommonOptionsParser::create(argc, argv, Cat);
  if (!OP) { llvm::errs() << OP.takeError(); return 1; }
  ClangTool Tool(OP->getCompilations(), OP->getSourcePathList());
  // as the wrapper toolchain does: drop the flags clang-18 does not know
  Tool.appendArgumentsAdjuster([](const CommandLineArguments &Args, StringRef) {
    CommandLineArguments R;
    for (const std::string &A : Args)
      if (A != "-fdiagnostics-show-inlining-chain" && A != "-fno-lifetime-dse" &&
          !StringRef(A).starts_with("-fsanitize-ignore-for-ubsan-feature="))
        R.push_back(A);
    return R;
  });
  // the wrapper's builtin headers are clang-18's own, its C++ library libc++ 19
  Tool.appendArgumentsAdjuster(getInsertArgumentAdjuster(
      {"-nostdinc++", "-isystem",
       "/data/csong/tmp/ucsan-v8/libcxx19/usr/lib/llvm-19/include/c++/v1"},
      ArgumentInsertPosition::BEGIN));
  Tool.appendArgumentsAdjuster(getInsertArgumentAdjuster(
      {"-resource-dir", "/usr/lib/llvm-18/lib/clang/18", "-Wno-everything"},
      ArgumentInsertPosition::END));
  return Tool.run(newFrontendActionFactory<Action>().get());
}
