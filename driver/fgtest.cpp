#include "defs.h"
#include "debug.h"
#include "version.h"

#include "dfsan/dfsan.h"

extern "C" {
#include "launch.h"
}

#include "parse.h"

#include <z3++.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

using namespace __dfsan;

#define OPTIMISTIC 1

#undef AOUT
# define AOUT(...)                                      \
  do {                                                  \
    printf(__VA_ARGS__);                                \
  } while(false)

// for input
static char *input_buf;
static size_t input_size;

// for output
static const char* __output_dir = ".";
static uint32_t __instance_id = 0;
static uint32_t __session_id = 0;
static uint32_t __current_index = 0;
static z3::context __z3_context;
static z3::solver __z3_solver(__z3_context, "QF_BV");

// z3parser
symsan::Z3AstParser *__z3_parser = nullptr;

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
      } else if (name.str().find("atoi") == 0) {
        off_t offset;
        int base;
        sscanf(name.str().c_str(), "atoi-%ld-%d", &offset, &base);
        AOUT("atoi: %s, offset = %ld, base = %d\n", name.str().c_str(), offset, base);
        lseek(fd, offset, SEEK_SET);
        const char *format = NULL;
        switch (base) {
          case 2: format = "%lb"; break;
          case 8: format = "%lo"; break;
          case 10: format = "%ld"; break;
          case 16: format = "%lx"; break;
          default: throw z3::exception("unsupported base");
        }
        dprintf(fd, format, (int)e.get_numeral_int());
      } else {
        AOUT("WARNING: unknown symbol: %s\n", name.str().c_str());
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

  std::vector<uint64_t> tasks;
  // r == 0 will negate r
  if (__z3_parser->parse_bool(label, r == 0, tasks) != 1) {
    AOUT("WARNING: failed to parse condition %d @%p\n", label, addr);
    return;
  }

  try {
    for (auto id : tasks) {
      std::shared_ptr<symsan::z3_task_t> task = __z3_parser->get_task(id);

      // setup global solver
      __z3_solver.reset();
      __z3_solver.set("timeout", 5000U);
      // 2. add constraints
      for (size_t i = 1; i < task->size(); i++) {
        __z3_solver.add(task->at(i));
      }
    
      // solve
      z3::expr e = task->at(0);
      std::cout << e << std::endl;
      if (__solve_expr(e)) {
        AOUT("branch solved\n");
      } else {
        AOUT("branch not solvable @%p\n", addr);
        //AOUT("\n%s\n", __z3_solver.to_smt2().c_str());
        //AOUT("  tree_size = %d", __dfsan_label_info[label].tree_size);
      }
    }
  } catch (z3::exception e) {
    AOUT("WARNING: solving error: %s @%p\n", e.msg(), addr);
  }

  // add nested constraints
  if (add_nested)
    __z3_parser->add_constraints(label, r);

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

  // uint8_t size = get_label_info(index_label)->size;
  // try {
  //   std::unordered_set<dfsan_label> inputs;
  //   z3::expr i = serialize(index_label, inputs);
  //   z3::expr r = __z3_context.bv_val(index, size);

  //   // collect additional input deps
  //   std::vector<dfsan_label> worklist;
  //   worklist.insert(worklist.begin(), inputs.begin(), inputs.end());
  //   while (!worklist.empty()) {
  //     auto off = worklist.back();
  //     worklist.pop_back();

  //     auto deps = get_branch_dep(off);
  //     if (deps != nullptr) {
  //       for (auto i : deps->input_deps) {
  //         if (inputs.insert(i).second)
  //           worklist.push_back(i);
  //       }
  //     }
  //   }

  //   // set up the global solver with nested constraints
  //   __z3_solver.reset();
  //   __z3_solver.set("timeout", 5000U);
  //   expr_set_t added;
  //   for (auto off : inputs) {
  //     auto deps = get_branch_dep(off);
  //     if (deps != nullptr) {
  //       for (auto &expr : deps->expr_deps) {
  //         if (added.insert(expr).second) {
  //           __z3_solver.add(expr);
  //         }
  //       }
  //     }
  //   }
  //   assert(__z3_solver.check() == z3::sat);

  //   // first, check against fixed array bounds if available
  //   z3::expr idx = z3::zext(i, 64 - size);
  //   if (num_elems > 0) {
  //     __solve_gep(idx, 0, num_elems, 1, addr);
  //   } else {
  //     dfsan_label_info *bounds = get_label_info(ptr_label);
  //     // if the array is not with fixed size, check bound info
  //     if (bounds->op == Alloca) {
  //       z3::expr es = __z3_context.bv_val(elem_size, 64);
  //       z3::expr co = __z3_context.bv_val(current_offset, 64);
  //       if (bounds->l2 == 0) {
  //         // only perform index enumeration and bound check
  //         // when the size of the buffer is fixed
  //         z3::expr p = __z3_context.bv_val(ptr, 64);
  //         z3::expr np = idx * es + co + p;
  //         __solve_gep(np, (uint64_t)bounds->op1.i, (uint64_t)bounds->op2.i, elem_size, addr);
  //       } else {
  //         // if the buffer size is input-dependent (not fixed)
  //         // check if over flow is possible
  //         std::unordered_set<dfsan_label> dummy;
  //         z3::expr bs = serialize(bounds->l2, dummy); // size label
  //         if (bounds->l1) {
  //           dummy.clear();
  //           z3::expr be = serialize(bounds->l1, dummy); // elements label
  //           bs = bs * be;
  //         }
  //         z3::expr e = z3::ugt(idx * es * co, bs);
  //         if (__solve_expr(e))
  //           AOUT("index >= buffer size feasible @%p\n", addr);
  //       }
  //     }
  //   }

  //   // always preserve
  //   for (auto off : inputs) {
  //     auto c = get_branch_dep(off);
  //     if (c == nullptr) {
  //       c = new branch_dep_t();
  //       set_branch_dep(off, c);
  //     }
  //     if (c == nullptr) {
  //       AOUT("WARNING: out of memory\n");
  //     } else {
  //       c->input_deps.insert(inputs.begin(), inputs.end());
  //       c->expr_deps.insert(i == r);
  //     }
  //   }

  // } catch (z3::exception e) {
  //   AOUT("WARNING: index solving error: %s @%p\n", e.msg(), __builtin_return_address(0));
  // }

}

int main(int argc, char* const argv[]) {
  
  if (argc != 3) {
    fprintf(stderr, "Usage: %s target input\n", argv[0]);
    exit(1);    
  }

  char *program = argv[1];
  char *input = argv[2];

  int is_stdin = 0;
  char *options = getenv("TAINT_OPTIONS");
  if (options) {
    // setup output dir
    char *output = strstr(options, "output_dir=");
    if (output) {
      output += 11; // skip "output_dir="
      char *end = strchr(output, ':'); // try ':' first, then ' '
      if (end == NULL) end = strchr(output, ' ');
      size_t n = end == NULL? strlen(output) : (size_t)(end - output);
      __output_dir = strndup(output, n);
    }

    // check if input is stdin
    char *taint_file = strstr(options, "taint_file=");
    if (taint_file) {
      taint_file += strlen("taint_file="); // skip "taint_file="
      char *end = strchr(taint_file, ':');
      if (end == NULL) end = strchr(taint_file, ' ');
      size_t n = end == NULL? strlen(taint_file) : (size_t)(end - taint_file);
      if (n == 5 && !strncmp(taint_file, "stdin", 5))
        is_stdin = 1;
    }
  }

  // load input file
  struct stat st;
  int input_fd = open(input, O_RDONLY);
  if (input_fd == -1) {
    fprintf(stderr, "Failed to open input file: %s\n", strerror(errno));
    exit(1);
  }
  fstat(input_fd, &st);
  input_size = st.st_size;
  input_buf = (char *)mmap(NULL, input_size, PROT_READ, MAP_PRIVATE, input_fd, 0);
  if (input_buf == (void *)-1) {
    fprintf(stderr, "Failed to map input file: %s\n", strerror(errno));
    exit(1);
  }

  // setup launcher
  void *shm_base = symsan_init(program, uniontable_size);
  if (shm_base == (void *)-1) {
    fprintf(stderr, "Failed to map shm: %s\n", strerror(errno));
    exit(1);
  }

  if (symsan_set_input(is_stdin ? "stdin" : input) != 0) {
    fprintf(stderr, "Failed to set input\n");
    exit(1);
  }

  char* args[3];
  args[0] = program;
  args[1] = input;
  args[2] = NULL;
  if (symsan_set_args(2, args) != 0) {
    fprintf(stderr, "Failed to set args\n");
    exit(1);
  }

  symsan_set_debug(1);
  symsan_set_bounds_check(0);

  // launch the target
  int ret = symsan_run(input_fd);
  if (ret < 0) {
    fprintf(stderr, "Failed to launch target: %s\n", strerror(errno));
    exit(1);
  } else if (ret > 0) {
    fprintf(stderr, "SymSan launch error %d\n", ret);
    exit(1);
  }
  close(input_fd);

  // setup z3 parser
  __z3_parser = new symsan::Z3AstParser(shm_base, uniontable_size, __z3_context);
  std::vector<symsan::input_t> inputs;
  inputs.push_back({(uint8_t*)input_buf, input_size});
  if (__z3_parser->restart(inputs) != 0) {
    fprintf(stderr, "Failed to restart parser\n");
    exit(1);
  }

  pipe_msg msg;
  gep_msg gmsg;
  size_t msg_size;
  memcmp_msg *mmsg = nullptr;

  while (symsan_read_event(&msg, sizeof(msg), 0) > 0) {
    // solve constraints
    switch (msg.msg_type) {
      case cond_type:
        __solve_cond(msg.label, msg.result, msg.flags & F_ADD_CONS, (void*)msg.addr);
        break;
      case gep_type:
        if (symsan_read_event(&gmsg, sizeof(gmsg), 0) != sizeof(gmsg)) {
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
        // flags = 0 means both operands are symbolic thus no content to read
        if (!msg.flags)
          break;
        msg_size = sizeof(memcmp_msg) + msg.result;
        mmsg = (memcmp_msg*)malloc(msg_size); // not freed until terminate
        if (symsan_read_event(mmsg, msg_size, 0) != msg_size) {
          fprintf(stderr, "Failed to receive memcmp msg: %s\n", strerror(errno));
          free(mmsg);
          break;
        }
        // double check
        if (msg.label != mmsg->label) {
          fprintf(stderr, "Incorrect memcmp msg: %d vs %d\n", msg.label, mmsg->label);
          free(mmsg);
          break;
        }
        // save the content
        __z3_parser->record_memcmp(msg.label, mmsg->content, msg.result);
        break;
      case fsize_type:
        break;
      default:
        break;
    }
  }

  symsan_destroy();
  exit(0);
}