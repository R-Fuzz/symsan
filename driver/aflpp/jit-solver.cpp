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

#if !DEBUG
#undef DEBUGF
#define DEBUGF(_str...) do { } while (0)
#endif

static const uint64_t kUsToS = 1000000;

static uint64_t getTimeStamp() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * kUsToS + tv.tv_usec;
}

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
  uint64_t start;
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
        cache_misses++;
        DEBUGF("jit constraint %d\n", c->ast->label());
        uint64_t id = ++uuid;
        start = getTimeStamp();
        addFunction(c->get_root(), c->local_map, id);
        process_time += (getTimeStamp() - start);
        start = getTimeStamp();
        auto fn = performJit(id);
        jit_time += (getTimeStamp() - start);
        auto kv = new struct myKV(c->ast, fn);
        if (!fCache.insert(kv))
          delete kv;
        const_cast<Constraint*>(c.get())->fn = fn; // XXX: workaround, no concurrent access
      } else {
        cache_hits++;
        const_cast<Constraint*>(c.get())->fn = res->fn; // XXX: workaround
      }
    }
  }

  // solve the task
  start = getTimeStamp();
  bool res = gd_entry(task);
  solving_time += (getTimeStamp() - start);
  if (res) {
    DEBUGF("solved\n");
    out_size = in_size;
    memcpy(out_buf, in_buf, in_size);
#if DEBUG
    for (auto const &[offset, value] : task->solution) {
      DEBUGF("generate_input offset:%zu => %u\n", offset, value);
    }
#endif
    if (unlikely(!task->atoi_info.empty())) {
      // if there are atoi bytes, handle them first
      for (auto const &[offset, info] : task->atoi_info) {
        uint64_t val = 0;
        uint32_t length = std::get<0>(info);
        for (auto i = length; i != 0; --i) {
          DEBUGF("generate_input atoi offset:%d => %lu\n", offset + i - 1, val);
          auto itr = task->solution.find(offset + i - 1);
          assert(itr != task->solution.end());
          val |= itr->second << (8 * (i - 1));
          // remove from the solution
          task->solution.erase(itr);
        }
        uint32_t base = std::get<1>(info);
        uint32_t orig_len = std::get<2>(info);
        DEBUGF("generate_input atoi offset:%d => %lu, base = %d, original len = %d\n",
            offset, val, base, orig_len);
        const char *format = nullptr;
        switch (base) {
          case 2: format = "%lb"; break;
          case 8: format = "%lo"; break;
          case 10: format = "%ld"; break;
          case 16: format = "%lx"; break;
          default: WARNF("unsupported base %d\n", base);
        }
        if (format) {
          snprintf((char*)out_buf + offset, in_size - offset, format, val);
        }
      }
    }
    for (auto const &[offset, value] : task->solution) {
      // DEBUGF("generate_input offset:%zu => %u\n", offset, value);
      out_buf[offset] = value;
    }
    num_solved++;
    return SOLVER_SAT;
  } else {
    DEBUGF("timeout\n");
    num_timeout++;
    return SOLVER_TIMEOUT;
  }
}

void JITSolver::print_stats(int fd) {
  dprintf(fd, "JIT solver stats:\n");
  dprintf(fd, "  cache hits: %lu\n", cache_hits.load());
  dprintf(fd, "  cache misses: %lu\n", cache_misses.load());
  dprintf(fd, "  num solved: %lu\n", num_solved.load());
  dprintf(fd, "  num timeout: %lu\n", num_timeout.load());
  dprintf(fd, "  process time: %lu\n", process_time.load());
  dprintf(fd, "  jit  time: %lu\n", jit_time.load());
  dprintf(fd, "  solving time: %lu\n", solving_time.load());
}
