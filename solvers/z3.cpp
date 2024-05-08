#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "dfsan/dfsan.h"

#include "parse.h"

#include <z3++.h>

#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#define OPTIMISTIC 1

using namespace __dfsan;

// for output
static const char* __output_dir;
static uint32_t __instance_id;
static uint32_t __session_id;
static uint32_t __current_index = 0;
static z3::context __z3_context;
static z3::solver __z3_solver(__z3_context, "QF_BV");
static symsan::Z3AstParser *__z3_parser = nullptr;

// filter?
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uint32_t __taint_trace_callstack;

static std::unordered_set<dfsan_label> __solved_labels;
typedef std::pair<uint32_t, void*> trace_context;
struct context_hash {
  std::size_t operator()(const trace_context &context) const {
    return std::hash<uint32_t>{}(context.first) ^ std::hash<void*>{}(context.second);
  }
};
static std::unordered_map<trace_context, uint16_t, context_hash> __branches;
static const uint16_t MAX_BRANCH_COUNT = 16;
static const uint64_t MAX_GEP_INDEX = 0x10000;
static std::unordered_set<uptr> __buffers;


static void generate_input(z3::model &m) {
  char path[PATH_MAX];
  internal_snprintf(path, PATH_MAX, "%s/id-%d-%d-%d", __output_dir,
                    __instance_id, __session_id, __current_index++);
  fd_t fd = OpenFile(path, WrOnly);
  if (fd == kInvalidFd) {
    throw z3::exception("failed to open new input file for write");
  }

  if (!tainted.is_stdin) {
    if (!WriteToFile(fd, tainted.buf, tainted.size)) {
      throw z3::exception("failed to copy original input\n");
    }
  } else {
    // FIXME: input is stdin
    throw z3::exception("original input is stdin");
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
      AOUT("offset %lld = %x\n", offset, value);
      internal_lseek(fd, offset, SEEK_SET);
      WriteToFile(fd, &value, sizeof(value));
    } else { // string symbol
      if (!name.str().compare("fsize")) {
        off_t size = (off_t)e.get_numeral_int64();
        if (size > tainted.size) { // grow
          internal_lseek(fd, size, SEEK_SET);
          uint8_t dummy = 0;
          WriteToFile(fd, &dummy, sizeof(dummy));
        } else {
          AOUT("truncate file to %lld\n", size);
          internal_ftruncate(fd, size);
        }
        // don't remember size constraints
        throw z3::exception("skip fsize constraints");
      }
    }
  }

  CloseFile(fd);
}

static bool __solve_expr(std::unique_ptr<symsan::z3_task_t> task) {
  bool ret = false;
  try {
    // setup global solver
    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);
    // solve the first constraint (optimistic)
    z3::expr e = task->at(0);
    __z3_solver.add(e);
    z3::check_result res = __z3_solver.check();
    if (res == z3::sat) {
      // optimistic sat, save a model
      z3::model m = __z3_solver.get_model();
      // check nested, if any
      if (task->size() > 1) {
        __z3_solver.push();
        // add nested constraints
        for (size_t i = 1; i < task->size(); i++) {
          __z3_solver.add(task->at(i));
        }
        res = __z3_solver.check();
        if (res == z3::sat) {
          m = __z3_solver.get_model();
        }
      }
      generate_input(m);
      ret = true;
    } else {
      //AOUT("\n%s\n", __z3_solver.to_smt2().c_str());
      //AOUT("  tree_size = %d", __dfsan_label_info[label].tree_size);
    }
  } catch (z3::exception ze) {
    AOUT("WARNING: solving error: %s\n", ze.msg());
  }
  return ret;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_cmp(dfsan_label op1, dfsan_label op2, uint32_t size, uint32_t predicate,
                  uint64_t c1, uint64_t c2, uint32_t cid) {
  if ((op1 == 0 && op2 == 0))
    return;

  void *addr = __builtin_return_address(0);
  auto itr = __branches.find({__taint_trace_callstack, addr});
  if (itr == __branches.end()) {
    itr = __branches.insert({{__taint_trace_callstack, addr}, 1}).first;
  } else if (itr->second < MAX_BRANCH_COUNT) {
    itr->second += 1;
  } else {
    return;
  }

  AOUT("solving cmp: %u %u %u %d %llu %llu 0x%x @%p\n",
       op1, op2, size, predicate, c1, c2, cid, addr);

  dfsan_label temp = dfsan_union(op1, op2, (predicate << 8) | ICmp, size, c1, c2);
  uint8_t r = get_const_result(c1, c2, predicate);

  if (__solved_labels.count(temp) != 0) 
    return;

  std::vector<uint64_t> tasks;
  if (__z3_parser->parse_cond(temp, r, r, tasks)) {
    AOUT("WARNING: failed to parse cmp %d @%p\n", temp, addr);
    return;
  }

  for (auto id : tasks) {
    auto task = __z3_parser->retrieve_task(id);
    // solve
    if (__solve_expr(std::move(task))) {
      AOUT("cmp solved\n");
    } else {
      AOUT("cmp not solvable @%p\n", addr);
    }
  }

  // mark as flipped
  __solved_labels.insert(temp);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_cond(dfsan_label label, uint8_t r, uint32_t cid) {
  if (label == 0)
    return;

  void *addr = __builtin_return_address(0);
  auto itr = __branches.find({__taint_trace_callstack, addr});
  if (itr == __branches.end()) {
    itr = __branches.insert({{__taint_trace_callstack, addr}, 1}).first;
  } else if (itr->second < MAX_BRANCH_COUNT) {
    itr->second += 1;
  } else {
    return;
  }

  AOUT("solving cond: %u %u 0x%x 0x%x %p %u\n",
       label, r, __taint_trace_callstack, cid, addr, itr->second);

  if (__solved_labels.count(label) != 0) 
    return;

  std::vector<uint64_t> tasks;
  if (__z3_parser->parse_cond(label, r, true, tasks)) {
    AOUT("WARNING: failed to parse condition %d @%p\n", label, addr);
    return;
  }

  for (auto id : tasks) {
    auto task = __z3_parser->retrieve_task(id);
    // solve
    if (__solve_expr(std::move(task))) {
      AOUT("branch solved\n");
    } else {
      AOUT("branch not solvable @%p\n", addr);
    }
  }

  // mark as flipped
  __solved_labels.insert(label);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_indcall(dfsan_label label) {
  if (label == 0)
    return;

  AOUT("tainted indirect call target: %d\n", label);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_gep(dfsan_label ptr_label, uint64_t ptr, dfsan_label index_label, int64_t index,
                  uint64_t num_elems, uint64_t elem_size, int64_t current_offset) {
  if (index_label == 0)
    return;

  if (__solved_labels.count(index_label) != 0) 
    return;

  if (__buffers.count(ptr) != 0)
    return;

  AOUT("tainted GEP index: %lld = %d, ne: %lld, es: %lld, offset: %lld\n",
      index, index_label, num_elems, elem_size, current_offset);

  void *addr = __builtin_return_address(0);
  std::vector<uint64_t> tasks;
  if (__z3_parser->parse_gep(ptr_label, ptr, index_label, index, num_elems,
                             elem_size, current_offset, tasks)) {
    AOUT("WARNING: failed to parse gep %d @%p\n", index_label, addr);
    return;
  }

  for (auto id : tasks) {
    auto task = __z3_parser->retrieve_task(id);
    // solve
    if (__solve_expr(std::move(task))) {
      AOUT("gep solved\n");
    } else {
      AOUT("gep not solvable @%p\n", addr);
    }
  }

  // mark as visited
  __solved_labels.insert(index_label);
  __buffers.insert(ptr);

}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_offset(dfsan_label offset_label, int64_t offset, unsigned size) {
  if (offset_label == 0)
    return;

  if (__solved_labels.count(offset_label) != 0)
    return;

  if (__z3_parser->add_constraints(offset_label, offset) != 0) {
    Report("WARNING: adding constraints error\n");
  }

  __solved_labels.insert(offset_label);
}

extern "C" void InitializeSolver() {
  __output_dir = flags().output_dir;
  __instance_id = flags().instance_id;
  __session_id = flags().session_id;
  __z3_parser = new symsan::Z3AstParser((void*)UnionTableAddr(), uniontable_size, __z3_context);
  std::vector<symsan::input_t> inputs;
  inputs.push_back({(u8*)tainted.buf, tainted.size});
  __z3_parser->restart(inputs);
}

