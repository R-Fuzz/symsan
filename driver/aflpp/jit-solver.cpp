#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"

#include "solver.h"
#include "ast.h"
#include "jigsaw/rgdJit.h"
#include "jigsaw/jit.h"
#include "wheels/lockfreehash/lprobe/hash_table.h"

extern "C" {
#include "afl-fuzz.h"
}

using namespace rgd;

extern std::unique_ptr<GradJit> JIT;

struct myKV {
  std::shared_ptr<AstNode> node;
  test_fn_type fn;
  myKV(std::shared_ptr<AstNode> anode, test_fn_type f) : node(anode), fn(f) {}
};

struct myHash {
  using eType = struct myKV*;
  using kType = std::shared_ptr<AstNode>;
  eType empty() {return nullptr;}
  kType getKey(eType v) {return v->node;}
  int hash(kType v) {return v->hash();} //hash64_2(v);}
  //int hash(kType v) {return hash64_2(v);}
  //int cmp(kType v, kType b) {return (v > b) ? 1 : ((v == b) ? 0 : -1);}
  int cmp(kType v, kType b) {return (isEqualAst(*v,*b)) ? 0 : -1;}
  bool replaceQ(eType, eType) {return 0;}
  eType update(eType v, eType) {return v;}
  bool cas(eType* p, eType o, eType n) {return pbbs::atomic_compare_and_swap(p, o, n);}
};

static pbbs::Table<myHash> fCache(8000016, myHash(), 1.3);

JITSolver::JITSolver(): uuid(0) {
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetAsmPrinter();
  llvm::InitializeNativeTargetAsmParser();

  JIT = std::move(GradJit::Create().get());
}

solver_result_t
JITSolver::solve(std::shared_ptr<SearchTask> task,
                 const uint8_t *in_buf, size_t in_size,
                 uint8_t *out_buf, size_t &out_size) {

  auto base_task = task->base_task;
  while (base_task != nullptr) {
    // no need to solve
    if (base_task->skip_next) {
      DEBUGF("skipping task\n");
      task->skip_next = true; // set the flag for following tasks
      out_size = in_size;
      memcpy(out_buf, in_buf, in_size);
      if (base_task->solved) {
        for (auto const &[offset, value] : base_task->solution) {
          out_buf[offset] = value;
        }
        return SOLVER_SAT;
      } else {
        return SOLVER_UNSAT;
      }
    } else if (base_task->solved) {
      task->load_hint();
    }
    base_task = base_task->base_task;
  }

  for (size_t i = 0; i < task->constraints.size(); i++) {
    auto &c = task->constraints[i];
    DEBUGF("process constraint %d (fn=%p)\n", c->ast->label(), c->fn);
    // jit the AST into a native function if haven't done so
    if (c->fn == nullptr) {
      struct myKV *res = fCache.find(c->ast);
      if (res == nullptr) {
        DEBUGF("jit constraint %d\n", c->ast->label());
        uint64_t id = ++uuid;
        addFunction(c->get_root(), c->local_map, id);
        auto fn = performJit(id);
        auto kv = new struct myKV(c->ast, fn);
        if (!fCache.insert(kv))
          delete kv;
        const_cast<Constraint*>(c.get())->fn = fn; // XXX: workaround, no concurrent access
      } else {
        const_cast<Constraint*>(c.get())->fn = res->fn; // XXX: workaround
      }
    }
  }

  // solve the task
  bool res = gd_entry(task);
  if (res) {
    DEBUGF("solved\n");
    out_size = in_size;
    memcpy(out_buf, in_buf, in_size);
    for (auto const &[offset, value] : task->solution) {
      DEBUGF("generate_input offset:%zu => %u\n", offset, value);
      out_buf[offset] = value;
    }
    return SOLVER_SAT;
  } else {
    DEBUGF("timeout\n");
    return SOLVER_TIMEOUT;
  }
}