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

static const char *shm_name = "/symsan_union_table";

dfsan_label_info* __dfsan::get_label_info(dfsan_label label) {
  return &__dfsan_label_info[label];
}

// for output
static const char* __output_dir = ".";
static uint32_t __instance_id = 0;
static uint32_t __session_id = 0;
static uint32_t __current_index = 0;
static z3::context __z3_context;
static z3::solver __z3_solver(__z3_context, "QF_BV");

// caches
static std::unordered_map<dfsan_label, uint32_t> tsize_cache;
static std::unordered_map<dfsan_label, std::unordered_set<uint32_t> > deps_cache;
static std::unordered_map<dfsan_label, z3::expr> expr_cache;
static std::unordered_map<dfsan_label, memcmp_msg*> memcmp_cache;

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

static z3::expr read_concrete(dfsan_label label, uint16_t size) {
  auto itr = memcmp_cache.find(label);
  if (itr == memcmp_cache.end()) {
    throw z3::exception("cannot find memcmp content");
  }

  memcmp_msg *mmsg = itr->second;
  z3::expr val = __z3_context.bv_val(mmsg->content[0], 8);
  for (uint8_t i = 1; i < size; i++) {
    val = z3::concat(__z3_context.bv_val(mmsg->content[i], 8), val);
  }
  return val;
}

static z3::expr get_cmd(z3::expr const &lhs, z3::expr const &rhs, uint32_t predicate) {
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

static inline z3::expr cache_expr(dfsan_label label, z3::expr const &e, std::unordered_set<uint32_t> &deps) {
  expr_cache.insert({label,e});
  deps_cache.insert({label,deps});
  return e;
}

static z3::expr serialize(dfsan_label label, std::unordered_set<uint32_t> &deps) {
  if (label < CONST_OFFSET || label == kInitializingLabel) {
    AOUT("WARNING: invalid label: %d\n", label);
    throw z3::exception("invalid label");
  }

  dfsan_label_info *info = get_label_info(label);
  AOUT("%u = (l1:%u, l2:%u, op:%u, size:%u, op1:%lu, op2:%lu)\n",
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
    uint64_t offset = get_label_info(info->l1)->op1.i;
    z3::symbol symbol = __z3_context.int_symbol(offset);
    z3::sort sort = __z3_context.bv_sort(8);
    z3::expr out = __z3_context.constant(symbol, sort);
    deps.insert(offset);
    for (uint32_t i = 1; i < info->l2; i++) {
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
    uint32_t base_size = base.get_sort().bv_size();
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, z3::zext(base, info->size - base_size), deps);
  } else if (info->op == SExt) {
    z3::expr base = serialize(info->l1, deps);
    uint32_t base_size = base.get_sort().bv_size();
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
                   read_concrete(label, info->size); // memcmp size in bytes
    if (info->l2 < CONST_OFFSET) {
      throw z3::exception("invalid memcmp operand2");
    }
    z3::expr op2 = serialize(info->l2, deps);
    tsize_cache[label] = 1; // lazy init
    z3::expr e = z3::ite(op1 == op2, __z3_context.bv_val(0, 32),
                                     __z3_context.bv_val(1, 32));
    return cache_expr(label, e, deps);
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
  uint8_t size = info->size;
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
    std::unordered_set<uint32_t> deps2;
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
      uint8_t value = (uint8_t)e.get_numeral_int();
      AOUT("offset %d = %x\n", offset, value);
      lseek(fd, offset, SEEK_SET);
      write(fd, &value, sizeof(value));
    } else { // string symbol
      if (!name.str().compare("fsize")) {
        off_t size = (off_t)e.get_numeral_int64();
        if (size > input_size) { // grow
          lseek(fd, size, SEEK_SET);
          uint8_t dummy = 0;
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

static void __solve_cond(dfsan_label label, uint8_t r, bool add_nested, void *addr) {

  z3::expr result = __z3_context.bool_val(r != 0);

  bool pushed = false;
  try {
    std::unordered_set<dfsan_label> inputs;
    z3::expr cond = serialize(label, inputs);

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

// assumes under try-catch and the global solver already has context
static void __solve_gep(z3::expr &index, uint64_t lb, uint64_t ub, uint64_t step, void *addr) {

  // enumerate indices
  for (uint64_t i = lb; i < ub; i += step) {
    z3::expr idx = __z3_context.bv_val(i, 64);
    z3::expr e = (index == idx);
    if (__solve_expr(e))
      AOUT("\tindex == %ld feasible\n", i);
  }

  // check feasibility for OOB
  // upper bound
  z3::expr u = __z3_context.bv_val(ub, 64);
  z3::expr e = z3::uge(index, u);
  if (__solve_expr(e))
    AOUT("\tindex >= %ld solved @%p\n", ub, addr);
  else
    AOUT("\tindex >= %ld not possible\n", ub);

  // lower bound
  if (lb == 0) {
    e = (index < 0);
  } else {
    z3::expr l = __z3_context.bv_val(lb, 64);
    e = z3::ult(index, l);
  }
  if (__solve_expr(e))
    AOUT("\tindex < %ld solved @%p\n", lb, addr);
  else
    AOUT("\tindex < %ld not possible\n", lb);
}

static void __handle_gep(dfsan_label ptr_label, uptr ptr,
                         dfsan_label index_label, int64_t index,
                         uint64_t num_elems, uint64_t elem_size,
                         int64_t current_offset, void* addr) {

  AOUT("tainted GEP index: %ld = %d, ne: %ld, es: %ld, offset: %ld\n",
      index, index_label, num_elems, elem_size, current_offset);

  uint8_t size = get_label_info(index_label)->size;
  try {
    std::unordered_set<dfsan_label> inputs;
    z3::expr i = serialize(index_label, inputs);
    z3::expr r = __z3_context.bv_val(index, size);

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

    // set up the global solver with nested constraints
    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);
    expr_set_t added;
    for (auto off : inputs) {
      auto deps = get_branch_dep(off);
      if (deps != nullptr) {
        for (auto &expr : deps->expr_deps) {
          if (added.insert(expr).second) {
            __z3_solver.add(expr);
          }
        }
      }
    }
    assert(__z3_solver.check() == z3::sat);

    // first, check against fixed array bounds if available
    z3::expr idx = z3::zext(i, 64 - size);
    if (num_elems > 0) {
      __solve_gep(idx, 0, num_elems, 1, addr);
    } else {
      dfsan_label_info *bounds = get_label_info(ptr_label);
      // if the array is not with fixed size, check bound info
      if (bounds->op == Alloca) {
        z3::expr es = __z3_context.bv_val(elem_size, 64);
        z3::expr co = __z3_context.bv_val(current_offset, 64);
        if (bounds->l2 == 0) {
          // only perform index enumeration and bound check
          // when the size of the buffer is fixed
          z3::expr p = __z3_context.bv_val(ptr, 64);
          z3::expr np = idx * es + co + p;
          __solve_gep(np, (uint64_t)bounds->op1.i, (uint64_t)bounds->op2.i, elem_size, addr);
        } else {
          // if the buffer size is input-dependent (not fixed)
          // check if over flow is possible
          std::unordered_set<dfsan_label> dummy;
          z3::expr bs = serialize(bounds->l2, dummy); // size label
          if (bounds->l1) {
            dummy.clear();
            z3::expr be = serialize(bounds->l1, dummy); // elements label
            bs = bs * be;
          }
          z3::expr e = z3::ugt(idx * es * co, bs);
          if (__solve_expr(e))
            AOUT("index >= buffer size feasible @%p\n", addr);
        }
      }
    }

    // always preserve
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
        c->expr_deps.insert(i == r);
      }
    }

  } catch (z3::exception e) {
    AOUT("WARNING: index solving error: %s @%p\n", e.msg(), __builtin_return_address(0));
  }

}

int main(int argc, char* const argv[]) {
  
  if (argc != 3) {
    fprintf(stderr, "Usage: %s target input\n", argv[0]);
    exit(1);    
  }

  char *program = argv[1];
  char *input = argv[2];

  // setup output dir
  char *options = getenv("TAINT_OPTIONS");
  char *output = strstr(options, "output_dir=");
  if (output) {
    output += 11; // skip "output_dir="
    char *end = strchr(output, ':'); // try ':' first, then ' '
    if (end == NULL) end = strchr(output, ' ');
    size_t n = end == NULL? strlen(output) : (size_t)(end - output);
    __output_dir = strndup(output, n);
  }

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
  close(fd);

  // setup shmem and pipe
  int shmfd = shm_open(shm_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (shmfd == -1) {
    fprintf(stderr, "Failed to open shmem: %s\n", strerror(errno));
    exit(1);
  }

  if (ftruncate(shmfd, uniontable_size) == -1) {
    fprintf(stderr, "Failed to truncate shmem: %s\n", strerror(errno));
    exit(1);
  }

  __dfsan_label_info = (dfsan_label_info *)mmap(NULL, uniontable_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, shmfd, 0);
  if (__dfsan_label_info == (void *)-1) {
    fprintf(stderr, "Failed to map shm: %s\n", strerror(errno));
    exit(1);
  }
  // clear O_CLOEXEC flag
  fcntl(shmfd, F_SETFD, fcntl(shmfd, F_GETFD) & ~FD_CLOEXEC);

  int pipefds[2];
  if (pipe(pipefds) != 0) {
    fprintf(stderr, "Failed to create pipe fds: %s\n", strerror(errno));
    exit(1);
  }

  // prepare the env and fork
  int length = snprintf(NULL, 0, "taint_file=%s:shm_fd=%d:pipe_fd=%d:debug=1",
                        input, shmfd, pipefds[1]);
  options = (char *)malloc(length + 1);
  snprintf(options, length + 1, "taint_file=%s:shm_fd=%d:pipe_fd=%d:debug=1",
           input, shmfd, pipefds[1]);
  
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
  gep_msg gmsg;
  dfsan_label_info *info;
  size_t msg_size;
  memcmp_msg *mmsg = nullptr;

  while (read(pipefds[0], &msg, sizeof(msg)) > 0) {
    // solve constraints
    switch (msg.msg_type) {
      case cond_type:
        __solve_cond(msg.label, msg.result, msg.flags & F_ADD_CONS, (void*)msg.addr);
        break;
      case gep_type:
        if (read(pipefds[0], &gmsg, sizeof(gmsg)) != sizeof(gmsg)) {
          fprintf(stderr, "Failed to receive gep msg: %s\n", strerror(errno));
          break;
        }
        // double check
        if (msg.label != gmsg.index_label) {
          fprintf(stderr, "Incorrect gep msg: %d vs %d\n", msg.label, gmsg.index_label);
          break;
        }
        __handle_gep(gmsg.ptr_label, gmsg.ptr, gmsg.index_label, gmsg.index,
                     gmsg.num_elems, gmsg.elem_size, gmsg.current_offset, (void*)msg.addr);
        break;
      case memcmp_type:
        info = get_label_info(msg.label);
        // if both operands are symbolic, no content to be read
        if (info->l1 != CONST_LABEL && info->l2 != CONST_LABEL)
          break;
        msg_size = sizeof(memcmp_msg) + msg.result;
        mmsg = (memcmp_msg*)malloc(msg_size); // not freed until terminate
        if (read(pipefds[0], mmsg, msg_size) != msg_size) {
          fprintf(stderr, "Failed to receive memcmp msg: %s\n", strerror(errno));
          break;
        }
        // double check
        if (msg.label != mmsg->label) {
          fprintf(stderr, "Incorrect memcmp msg: %d vs %d\n", msg.label, mmsg->label);
          break;
        }
        // save the content
        memcmp_cache[msg.label] = mmsg;
        break;
      case fsize_type:
        break;
      default:
        break;
    }
  }

  wait(NULL);
  close(pipefds[0]);
  close(shmfd);
  shm_unlink(shm_name);
  exit(0);
}