#include "defs.h"
#include "debug.h"
#include "version.h"

#include "dfsan/dfsan.h"

#include <z3++.h>

#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

using namespace __dfsan;

#define OPTIMISTIC 1

#undef AOUT
# define AOUT(...)                                      \
  do {                                                  \
    printf(__VA_ARGS__);                                \
  } while(false)

static dfsan_label_info *__dfsan_label_info;
static char *input_buf;
static size_t input_size;

dfsan_label_info* __dfsan::get_label_info(dfsan_label label) {
  return &__dfsan_label_info[label];
}

// for output
static const char* __output_dir = ".";
static u32 __instance_id = 0;
static u32 __session_id = 0;
static u32 __current_index = 0;
static z3::context __z3_context;
static z3::solver __z3_solver(__z3_context, "QF_BV");

// caches
static std::unordered_map<dfsan_label, u32> tsize_cache;
static std::unordered_map<dfsan_label, std::unordered_set<u32> > deps_cache;
static std::unordered_map<dfsan_label, z3::expr> expr_cache;

// dependencies
struct expr_hash {
  std::size_t operator()(const z3::expr &expr) const {
    return expr.hash();
  }
};
struct expr_equal {
  bool operator()(const z3::expr &lhs, const z3::expr &rhs) const {
    return lhs.id() == rhs.id();
  }
};
typedef std::unordered_set<z3::expr, expr_hash, expr_equal> expr_set_t;
typedef struct {
  expr_set_t expr_deps;
  std::unordered_set<dfsan_label> input_deps;
} branch_dep_t;
static std::vector<branch_dep_t*> __branch_deps;

static inline branch_dep_t* get_branch_dep(size_t n) {
  if (n >= __branch_deps.size()) {
    __branch_deps.resize(n + 1);
  }
  return __branch_deps.at(n);
}

static inline void set_branch_dep(size_t n, branch_dep_t* dep) {
  if (n >= __branch_deps.size()) {
    __branch_deps.resize(n + 1);
  }
  __branch_deps.at(n) = dep;
}

static z3::expr read_concrete(u64 addr, u8 size) {
  u8 *ptr = reinterpret_cast<u8*>(addr);
  if (ptr == nullptr) {
    throw z3::exception("invalid concrete address");
  }

  z3::expr val = __z3_context.bv_val(*ptr++, 8);
  for (u8 i = 1; i < size; i++) {
    val = z3::concat(__z3_context.bv_val(*ptr++, 8), val);
  }
  return val;
}

static z3::expr get_cmd(z3::expr const &lhs, z3::expr const &rhs, u32 predicate) {
  switch (predicate) {
    case bveq:  return lhs == rhs;
    case bvneq: return lhs != rhs;
    case bvugt: return z3::ugt(lhs, rhs);
    case bvuge: return z3::uge(lhs, rhs);
    case bvult: return z3::ult(lhs, rhs);
    case bvule: return z3::ule(lhs, rhs);
    case bvsgt: return lhs > rhs;
    case bvsge: return lhs >= rhs;
    case bvslt: return lhs < rhs;
    case bvsle: return lhs <= rhs;
    default:
      AOUT("FATAL: unsupported predicate: %u\n", predicate);
      throw z3::exception("unsupported predicate");
      break;
  }
  // should never reach here
  Die();
}

static inline z3::expr cache_expr(dfsan_label label, z3::expr const &e, std::unordered_set<u32> &deps) {
  expr_cache.insert({label,e});
  deps_cache.insert({label,deps});
  return e;
}

static z3::expr serialize(dfsan_label label, std::unordered_set<u32> &deps) {
  if (label < CONST_OFFSET || label == kInitializingLabel) {
    AOUT("WARNING: invalid label: %d\n", label);
    throw z3::exception("invalid label");
  }

  dfsan_label_info *info = get_label_info(label);
  AOUT("%u = (l1:%u, l2:%u, op:%u, size:%u, op1:%llu, op2:%llu)\n",
       label, info->l1, info->l2, info->op, info->size, info->op1.i, info->op2.i);

  auto expr_itr = expr_cache.find(label);
  if (expr_itr != expr_cache.end()) {
    auto deps_itr = deps_cache.find(label);
    deps.insert(deps_itr->second.begin(), deps_itr->second.end());
    return expr_itr->second;
  }

  // special ops
  if (info->op == 0) {
    // input
    z3::symbol symbol = __z3_context.int_symbol(info->op1.i);
    z3::sort sort = __z3_context.bv_sort(8);
    tsize_cache[label] = 1; // lazy init
    deps.insert(info->op1.i);
    // caching is not super helpful
    return __z3_context.constant(symbol, sort);
  } else if (info->op == Load) {
    u64 offset = get_label_info(info->l1)->op1.i;
    z3::symbol symbol = __z3_context.int_symbol(offset);
    z3::sort sort = __z3_context.bv_sort(8);
    z3::expr out = __z3_context.constant(symbol, sort);
    deps.insert(offset);
    for (u32 i = 1; i < info->l2; i++) {
      symbol = __z3_context.int_symbol(offset + i);
      out = z3::concat(__z3_context.constant(symbol, sort), out);
      deps.insert(offset + i);
    }
    tsize_cache[label] = 1; // lazy init
    return cache_expr(label, out, deps);
  } else if (info->op == ZExt) {
    z3::expr base = serialize(info->l1, deps);
    if (base.is_bool()) // dirty hack since llvm lacks bool
      base = z3::ite(base, __z3_context.bv_val(1, 1),
                           __z3_context.bv_val(0, 1));
    u32 base_size = base.get_sort().bv_size();
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, z3::zext(base, info->size - base_size), deps);
  } else if (info->op == SExt) {
    z3::expr base = serialize(info->l1, deps);
    u32 base_size = base.get_sort().bv_size();
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, z3::sext(base, info->size - base_size), deps);
  } else if (info->op == Trunc) {
    z3::expr base = serialize(info->l1, deps);
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, base.extract(info->size - 1, 0), deps);
  } else if (info->op == Extract) {
    z3::expr base = serialize(info->l1, deps);
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, base.extract((info->op2.i + info->size) - 1, info->op2.i), deps);
  } else if (info->op == Not) {
    if (info->l2 == 0 || info->size != 1) {
      throw z3::exception("invalid Not operation");
    }
    z3::expr e = serialize(info->l2, deps);
    tsize_cache[label] = tsize_cache[info->l2]; // lazy init
    if (!e.is_bool()) {
      throw z3::exception("Only LNot should be recorded");
    }
    return cache_expr(label, !e, deps);
  } else if (info->op == Neg) {
    if (info->l2 == 0) {
      throw z3::exception("invalid Neg predicate");
    }
    z3::expr e = serialize(info->l2, deps);
    tsize_cache[label] = tsize_cache[info->l2]; // lazy init
    return cache_expr(label, -e, deps);
  }
  // higher-order
  else if (info->op == fmemcmp) {
    z3::expr op1 = (info->l1 >= CONST_OFFSET) ? serialize(info->l1, deps) :
                   read_concrete(info->op1.i, info->size); // memcmp size in bytes
    if (info->l2 < CONST_OFFSET) {
      throw z3::exception("invalid memcmp operand2");
    }
    z3::expr op2 = serialize(info->l2, deps);
    tsize_cache[label] = 1; // lazy init
    // don't cache becaue of read_concrete?
    return z3::ite(op1 == op2, __z3_context.bv_val(0, 32),
                               __z3_context.bv_val(1, 32));
  } else if (info->op == fsize) {
    // file size
    z3::symbol symbol = __z3_context.str_symbol("fsize");
    z3::sort sort = __z3_context.bv_sort(info->size);
    z3::expr base = __z3_context.constant(symbol, sort);
    tsize_cache[label] = 1; // lazy init
    // don't cache because of deps
    if (info->op1.i) {
      // minus the offset stored in op1
      z3::expr offset = __z3_context.bv_val((uint64_t)info->op1.i, info->size);
      return base - offset;
    } else {
      return base;
    }
  }

  // common ops
  u8 size = info->size;
  // size for concat is a bit complicated ...
  if (info->op == Concat && info->l1 == 0) {
    assert(info->l2 >= CONST_OFFSET);
    size = info->size - get_label_info(info->l2)->size;
  }
  z3::expr op1 = __z3_context.bv_val((uint64_t)info->op1.i, size);
  if (info->l1 >= CONST_OFFSET) {
    op1 = serialize(info->l1, deps).simplify();
  } else if (info->size == 1) {
    op1 = __z3_context.bool_val(info->op1.i == 1);
  }
  if (info->op == Concat && info->l2 == 0) {
    assert(info->l1 >= CONST_OFFSET);
    size = info->size - get_label_info(info->l1)->size;
  }
  z3::expr op2 = __z3_context.bv_val((uint64_t)info->op2.i, size);
  if (info->l2 >= CONST_OFFSET) {
    std::unordered_set<u32> deps2;
    op2 = serialize(info->l2, deps2).simplify();
    deps.insert(deps2.begin(),deps2.end());
  } else if (info->size == 1) {
    op2 = __z3_context.bool_val(info->op2.i == 1);
  }
  // update tree_size
  tsize_cache[label] = tsize_cache[info->l1] + tsize_cache[info->l2];

  switch((info->op & 0xff)) {
    // llvm doesn't distinguish between logical and bitwise and/or/xor
    case And:     return cache_expr(label, info->size != 1 ? (op1 & op2) : (op1 && op2), deps);
    case Or:      return cache_expr(label, info->size != 1 ? (op1 | op2) : (op1 || op2), deps);
    case Xor:     return cache_expr(label, op1 ^ op2, deps);
    case Shl:     return cache_expr(label, z3::shl(op1, op2), deps);
    case LShr:    return cache_expr(label, z3::lshr(op1, op2), deps);
    case AShr:    return cache_expr(label, z3::ashr(op1, op2), deps);
    case Add:     return cache_expr(label, op1 + op2, deps);
    case Sub:     return cache_expr(label, op1 - op2, deps);
    case Mul:     return cache_expr(label, op1 * op2, deps);
    case UDiv:    return cache_expr(label, z3::udiv(op1, op2), deps);
    case SDiv:    return cache_expr(label, op1 / op2, deps);
    case URem:    return cache_expr(label, z3::urem(op1, op2), deps);
    case SRem:    return cache_expr(label, z3::srem(op1, op2), deps);
    // relational
    case ICmp:    return cache_expr(label, get_cmd(op1, op2, info->op >> 8), deps);
    // concat
    case Concat:  return cache_expr(label, z3::concat(op2, op1), deps); // little endian
    default:
      AOUT("FATAL: unsupported op: %u\n", info->op);
      throw z3::exception("unsupported operator");
      break;
  }
  // should never reach here
  Die();
}

static void generate_input(z3::model &m) {
  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "%s/id-%d-%d-%d", __output_dir,
           __instance_id, __session_id, __current_index++);
  int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    throw z3::exception("failed to open new input file for write");
  }

  if (write(fd, input_buf, input_size) == -1) {
    throw z3::exception("failed to copy original input\n");
  }
  AOUT("generate #%d output\n", __current_index - 1);

  // from qsym
  unsigned num_constants = m.num_consts();
  for (unsigned i = 0; i < num_constants; i++) {
    z3::func_decl decl = m.get_const_decl(i);
    z3::expr e = m.get_const_interp(decl);
    z3::symbol name = decl.name();

    if (name.kind() == Z3_INT_SYMBOL) {
      int offset = name.to_int();
      u8 value = (u8)e.get_numeral_int();
      AOUT("offset %d = %x\n", offset, value);
      lseek(fd, offset, SEEK_SET);
      write(fd, &value, sizeof(value));
    } else { // string symbol
      if (!name.str().compare("fsize")) {
        off_t size = (off_t)e.get_numeral_int64();
        if (size > input_size) { // grow
          lseek(fd, size, SEEK_SET);
          u8 dummy = 0;
          write(fd, &dummy, sizeof(dummy));
        } else {
          AOUT("truncate file to %ld\n", size);
          ftruncate(fd, size);
        }
        // don't remember size constraints
        throw z3::exception("skip fsize constraints");
      }
    }
  }

  close(fd);
}

// assumes under try-catch and the global solver __z3_solver already has nested context
static bool __solve_expr(z3::expr &e) {
  bool ret = false;
  // set up local optmistic solver
  z3::solver opt_solver = z3::solver(__z3_context, "QF_BV");
  opt_solver.set("timeout", 1000U);
  opt_solver.add(e);
  z3::check_result res = opt_solver.check();
  if (res == z3::sat) {
    // optimistic sat, check nested
    __z3_solver.push();
    __z3_solver.add(e);
    res = __z3_solver.check();
    if (res == z3::sat) {
      z3::model m = __z3_solver.get_model();
      generate_input(m);
      ret = true;
    } else {
    #if OPTIMISTIC
      z3::model m = opt_solver.get_model();
      generate_input(m);
    #endif
    }
    // reset
    __z3_solver.pop();
  }
  return ret;
}

static void __solve_cond(dfsan_label label, u8 r, bool add_nested, void *addr) {

  z3::expr result = __z3_context.bool_val(r != 0);

  bool pushed = false;
  try {
    std::unordered_set<dfsan_label> inputs;
    z3::expr cond = serialize(label, inputs);

#if 0
    if (get_label_info(label)->tree_size > 50000) {
      // don't bother?
      throw z3::exception("formula too large");
    }
#endif

    // collect additional input deps
    std::vector<dfsan_label> worklist;
    worklist.insert(worklist.begin(), inputs.begin(), inputs.end());
    while (!worklist.empty()) {
      auto off = worklist.back();
      worklist.pop_back();

      auto deps = get_branch_dep(off);
      if (deps != nullptr) {
        for (auto i : deps->input_deps) {
          if (inputs.insert(i).second)
            worklist.push_back(i);
        }
      }
    }

    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);
    // 2. add constraints
    expr_set_t added;
    for (auto off : inputs) {
      //AOUT("adding offset %d\n", off);
      auto deps = get_branch_dep(off);
      if (deps != nullptr) {
        for (auto &expr : deps->expr_deps) {
          if (added.insert(expr).second) {
            //AOUT("adding expr: %s\n", expr.to_string().c_str());
            __z3_solver.add(expr);
          }
        }
      }
    }
    assert(__z3_solver.check() == z3::sat);
    
    z3::expr e = (cond != result);
    if (__solve_expr(e)) {
      AOUT("branch solved\n");
    } else {
      AOUT("branch not solvable @%p\n", addr);
      //AOUT("\n%s\n", __z3_solver.to_smt2().c_str());
      //AOUT("  tree_size = %d", __dfsan_label_info[label].tree_size);
    }

    // nested branch
    if (add_nested) {
      for (auto off : inputs) {
        auto c = get_branch_dep(off);
        if (c == nullptr) {
          c = new branch_dep_t();
          set_branch_dep(off, c);
        }
        if (c == nullptr) {
          AOUT("WARNING: out of memory\n");
        } else {
          c->input_deps.insert(inputs.begin(), inputs.end());
          c->expr_deps.insert(cond == result);
        }
      }
    }

  } catch (z3::exception e) {
    AOUT("WARNING: solving error: %s @%p\n", e.msg(), addr);
  }

}

int main(int argc, char* const argv[]) {
  
  if (argc != 3) {
    fprintf(stderr, "Usage: %s target input\n", argv[0]);
    exit(1);    
  }

  char *program = argv[1];
  char *input = argv[2];

  // load input file
  struct stat st;
  int fd = open(input, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "Failed to open input file: %s\n", strerror(errno));
    exit(1);
  }
  fstat(fd, &st);
  input_size = st.st_size;
  input_buf = (char *)mmap(NULL, input_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (input_buf == (void *)-1) {
    fprintf(stderr, "Failed to map input file: %s\n", strerror(errno));
    exit(1);
  }

  // setup shmem and pipe
  int shmid = shmget(IPC_PRIVATE, 0xc00000000,
    O_CREAT | SHM_NORESERVE | S_IRUSR | S_IWUSR);
  if (shmid == -1) {
    fprintf(stderr, "Failed to get shmid: %s\n", strerror(errno));
    exit(1);
  }

  __dfsan_label_info = (dfsan_label_info *)shmat(shmid, NULL, SHM_RDONLY);
  if (__dfsan_label_info == (void *)-1) {
    fprintf(stderr, "Failed to map shm(%d): %s\n", shmid, strerror(errno));
    exit(1);
  }

  int pipefds[2];
  if (pipe(pipefds) != 0) {
    fprintf(stderr, "Failed to create pipe fds: %s\n", strerror(errno));
    exit(1);
  }

  // prepare the env and fork
  int length = snprintf(NULL, 0, "taint_file=%s:shm_id=%d:pipe_fd=%d:debug=1",
                        input, shmid, pipefds[1]);
  char *options = (char *)malloc(length + 1);
  snprintf(options, length + 1, "taint_file=%s:shm_id=%d:pipe_fd=%d:debug=1",
           input, shmid, pipefds[1]);
  
  int pid = fork();
  if (pid < 0) {
    fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
    exit(1);
  }

  if (pid == 0) {
    close(pipefds[0]); // close the read fd
    setenv("TAINT_OPTIONS", options, 1);
    char* args[3];
    args[0] = program;
    args[1] = input;
    args[2] = NULL;
    execv(program, args);
    exit(0);
  }

  close(pipefds[1]);

  pipe_msg msg;
  while (read(pipefds[0], &msg, sizeof(msg)) > 0) {
    // solve constraints
    switch (msg.msg_type) {
      case cond_type:
        __solve_cond(msg.label, msg.result, msg.flags & F_ADD_CONS, (void*)msg.addr);
        break;
      case gep_type:
        break;
      case memcmp_type:
        break;
      case fsize_type:
        break;
      default:
        break;
    }
  }

  wait(NULL);
  exit(0);
}