#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "dfsan/dfsan.h"

#include "parse-z3.h"

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
static symsan::Z3ParserSolver *__z3_parser = nullptr;

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


static void generate_input(symsan::Z3ParserSolver::solution_t &solutions) {

  if (tainted.is_stdin) {
    // FIXME: input is stdin
    AOUT("WARNING: original input is stdin");
    return;
  }

  char path[PATH_MAX];
  internal_snprintf(path, PATH_MAX, "%s/id-%d-%d-%d", __output_dir,
                    __instance_id, __session_id, __current_index++);
  fd_t fd = OpenFile(path, WrOnly);
  if (fd == kInvalidFd) {
    AOUT("WARNING: failed to open new input file for write");
    return;
  }

  if (!WriteToFile(fd, tainted.buf, tainted.size)) {
    AOUT("WARNING: failed to copy original input\n");
    CloseFile(fd);
    return;
  }
  AOUT("generate #%d output\n", __current_index - 1);

  for (auto const& sol : solutions) {
    uint8_t value = sol.val;
    AOUT("offset %d = %x\n", sol.offset, value);
    internal_lseek(fd, sol.offset, SEEK_SET);
    WriteToFile(fd, &value, sizeof(value));
  }

  // FIXME: fsize

  CloseFile(fd);
}

static inline bool __solve_task(uint64_t task_id) {
  symsan::Z3ParserSolver::solution_t solutions;
  auto status = __z3_parser->solve_task(task_id, 5000U, solutions);
  if (solutions.size() != 0) {
    generate_input(solutions);
    return true;
  } else {
    return false;
  }
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
    // solve
    if (__solve_task(id)) {
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
    // solve
    if (__solve_task(id)) {
      AOUT("branch solved\n");
    } else {
      AOUT("branch not solvable @%p\n", addr);
    }
  }

  // mark as flipped
  __solved_labels.insert(label);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
__taint_trace_select(dfsan_label cond_label, dfsan_label true_label,
                     dfsan_label false_label, uint8_t r, uint8_t true_op,
                     uint8_t false_op, uint32_t cid) {
  if (cond_label == 0)
    return r ? true_label : false_label;

  void *addr = __builtin_return_address(0);
  auto itr = __branches.find({__taint_trace_callstack, addr});
  if (itr == __branches.end()) {
    itr = __branches.insert({{__taint_trace_callstack, addr}, 1}).first;
  } else if (itr->second < MAX_BRANCH_COUNT) {
    itr->second += 1;
  } else {
    return r ? true_label : false_label;
  }

  AOUT("solving select: %u %u %u %u %u %u 0x%x @%p\n",
       cond_label, true_label, false_label, r, true_op, false_op, cid, addr);

  // check if it's actually a logical AND: select cond, label, false
  dfsan_label solving_label = 0, ret_label = 0;
  uint8_t solving_r = 0;
  if (true_label != 0 && false_op == 0) {
    solving_label = dfsan_union(cond_label, true_label, And, 1, r, true_op);
    solving_r = (r && true_op) ? 1 : 0;
    ret_label = solving_label;
  } else if (false_label != 0 && true_op == 1) {
    // logical OR: select cond, true, label
    solving_label = dfsan_union(cond_label, false_label, Or, 1, r, false_op);
    solving_r = (r || false_op) ? 1 : 0;
    ret_label = solving_label;
  } else {
    // normal select?
    AOUT("normal select?!\n");
    solving_label = cond_label;
    solving_r = r;
    ret_label = r ? true_label : false_label;
  }

  if (__solved_labels.count(solving_label) != 0)
    return ret_label;

  std::vector<uint64_t> tasks;
  if (__z3_parser->parse_cond(solving_label, solving_r, true, tasks)) {
    AOUT("WARNING: failed to parse condition %d @%p\n", solving_label, addr);
    return ret_label;
  }

  for (auto id : tasks) {
    // solve
    if (__solve_task(id)) {
      AOUT("branch solved\n");
    } else {
      AOUT("branch not solvable @%p\n", addr);
    }
  }

  // mark as flipped
  __solved_labels.insert(solving_label);

  return ret_label;
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
                             elem_size, current_offset, true, tasks)) {
    AOUT("WARNING: failed to parse gep %d @%p\n", index_label, addr);
    return;
  }

  for (auto id : tasks) {
    // solve
    if (__solve_task(id)) {
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
  __z3_parser = new symsan::Z3ParserSolver((void*)UnionTableAddr(), uniontable_size, __z3_context);
  std::vector<symsan::input_t> inputs;
  inputs.push_back({(u8*)tainted.buf, tainted.size});
  __z3_parser->restart(inputs);
}
