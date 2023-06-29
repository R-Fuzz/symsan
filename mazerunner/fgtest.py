#!/usr/bin/env python3
import os
import sys
from multiprocessing import shared_memory
import subprocess
import ctypes
import z3

from config import *
from defs import *

# resources
pipefds = shm = proc = None

# for output
output_dir = "."
__instance_id = 0
__session_id = 0
__current_index = 0
__z3_context = z3.Context()
__z3_solver = z3.SolverFor("QF_BV", ctx=__z3_context)

# caches
deps_cache = {} # key: dfsan_label, value: set()
expr_cache = {} # key: dfsan_label, value: z3.ExprRef
memcmp_cache = {} # key: dfsan_label, value: memcmp_msg
__branch_deps = [] # list of branch_dep_t dependencies

class branch_dep_t:
    def __init__(self):
        self.expr_deps = set() # z3.ExprRef set
        self.input_deps = set() # dfsan_label set

def get_branch_dep(n: int):
  if n >= len(__branch_deps):
    __branch_deps.extend([None] * (n + 1 - len(__branch_deps)))
  return __branch_deps[n]

def set_branch_dep(n: int, dep: branch_dep_t):
  if n >= len(__branch_deps):
    __branch_deps.extend([None] * (n + 1 - len(__branch_deps)))
  __branch_deps[n] = dep

def get_label_info(label: int):
    offset = label * ctypes.sizeof(dfsan_label_info)
    return dfsan_label_info.from_buffer_copy(shm.buf[offset:offset+ctypes.sizeof(dfsan_label_info)])

def read_concrete(label: int, size: int):
    if(not label in memcmp_cache):
        raise ValueError(f"label{label} must be in memcmp_cache")
    mmsg = memcmp_cache[label]
    val = z3.BitVecVal(mmsg.content[0], 8, __z3_context)
    for i in range(1, size):
        val = z3.Concat(z3.BitVecVal(mmsg.content[i], 8, __z3_context), val)
    return val

def get_cmd(lhs: z3.ExprRef, rhs: z3.ExprRef, predicate: int):
    if predicate == Predicate.bveq.value:
        return lhs == rhs
    elif predicate == Predicate.bvneq.value:
        return lhs != rhs
    elif predicate == Predicate.bvugt.value:
        return z3.UGT(lhs, rhs)
    elif predicate == Predicate.bvuge.value:
        return z3.UGE(lhs, rhs)
    elif predicate == Predicate.bvult.value:
        return z3.ULT(lhs, rhs)
    elif predicate == Predicate.bvule.value:
        return z3.ULE(lhs, rhs)
    elif predicate == Predicate.bvsgt.value:
        return lhs > rhs
    elif predicate == Predicate.bvsge.value:
        return lhs >= rhs
    elif predicate == Predicate.bvslt.value:
        return lhs < rhs
    elif predicate == Predicate.bvsle.value:
        return lhs <= rhs
    else:
        print(f"FATAL: unsupported predicate: {predicate}")
        raise ValueError("unsupported predicate")

def cache_expr(label: int, e: z3.ExprRef, deps: set):
    expr_cache[label] = e
    deps_cache[label] = deps
    return e

def generate_input(m: z3.Model):
    global input_buf, input_size, __instance_id, __session_id, __current_index
    path = os.path.join(output_dir, f"id-{__instance_id}-{__session_id}-{__current_index}")
    __current_index += 1
    with open(path, "wb") as f:
        f.write(input_buf)
    print(f"generate #{__current_index} output")
    fp = open(path, "r+b")
    for decl in m:
        name = decl.name()
        if decl.kind() == z3.Z3_OP_UNINTERPRETED:
            offset = int(name)
            value = m[decl].as_long()
            print(f"offset {offset} = {value}")
            if input_size <= offset:
                raise ValueError("offset is out of file size")
            fp.seek(offset)
            fp.write(bytes([value]))
        else:  # string symbol
            if name == "fsize":
                size = m[decl].as_long()
                if size > len(input_buf):
                    with open(path, "a+b") as f:
                        print(f"Grow filesize to {size}")
                        f.write(b"\x00" * (size - len(input_buf)))
                else:
                    print(f"Shrink file to {size}")
                    with open(path, "r+b") as f:
                        f.truncate(size)
                # don't remember size constraints
                raise Exception("skip fsize constraints")
    fp.close()

def serialize(label: int, deps: set):
    if label < CONST_OFFSET or label == INIT_LABEL:
        raise ValueError(f"Invalid label {label}\n")
    info = get_label_info(label)
    print(f"{label} = (l1:{info.l1}, l2:{info.l2}, op:{info.op}, size:{info.size}, "
        f"op1:{info.op1.i}, op2:{info.op2.i}, hash:{info.hash})")

    if label in expr_cache:
        deps.update(deps_cache[label])
        return expr_cache[label]

    if info.op == LLVM_INS.Input.value:
        sort = z3.BitVecSort(8, __z3_context)
        deps.add(info.op1.i)
        return z3.Const(str(info.op1.i), sort)

    elif info.op == LLVM_INS.Load.value:
        offset = get_label_info(info.l1).op1.i
        sort = z3.BitVecSort(8, __z3_context)
        out = z3.Const(str(offset), sort)
        deps.add(offset)
        for i in range(1, info.l2):
            out = z3.Concat(z3.Const(str(offset + i), sort), out)
            deps.add(offset + i)
        return cache_expr(label, out, deps)

    elif info.op == LLVM_INS.ZExt.value:
        base = serialize(info.l1, deps)
        if z3.is_bool(base):
            base = z3.If(base, z3.BitVecVal(1, 1, __z3_context), 
                               z3.BitVecVal(0, 1, __z3_context))
        base_size = base.sort().size()
        return cache_expr(label, z3.ZeroExt(info.size - base_size, base), deps)

    elif info.op == LLVM_INS.SExt.value:
        base = serialize(info.l1, deps)
        base_size = base.sort().size()
        return cache_expr(label, z3.SignExt(info.size - base_size, base), deps)

    elif info.op == LLVM_INS.Trunc.value:
        base = serialize(info.l1, deps)
        return cache_expr(label, z3.Extract(info.size - 1, 0, base), deps)

    elif info.op == LLVM_INS.Extract.value:
        base = serialize(info.l1, deps)
        return cache_expr(label, z3.Extract((info.op2.i + info.size) - 1, info.op2.i, base), deps)

    elif info.op == LLVM_INS.Not.value:
        if info.l2 == 0 or info.size != 1:
            raise ValueError("Invalid Not operation")
        e = serialize(info.l2, deps)
        if z3.is_bool(e):
            raise ValueError("Only LNot should be recorded")
        return cache_expr(label, z3.Not(e), deps)

    elif info.op == LLVM_INS.Neg.value:
        if info.l2 == 0:
            raise ValueError("Invalid Neg predicate")
        e = serialize(info.l2, deps)
        return cache_expr(label, -e, deps)
    # higher-order operations
    elif info.op == LLVM_INS.fmemcmp.value:
        op1 = serialize(info.l1, deps) if info.l1 >= CONST_OFFSET else read_concrete(label, info.size)
        if info.l2 < CONST_OFFSET:
            raise ValueError("Invalid memcmp operand2")
        op2 = serialize(info.l2, deps)
        if op1.size() != op2.size():
            if op1.size() > op2.size():
                op2 = z3.ZeroExt(op1.size() - op2.size(), op2)
            else:
                op1 = z3.ZeroExt(op2.size() - op1.size(), op1)
        e = z3.If(op1 == op2, z3.BitVecVal(0, 32, __z3_context), z3.BitVecVal(1, 32, __z3_context))
        return cache_expr(label, e, deps)

    elif info.op == LLVM_INS.fsize.value:
        symbol = z3.String("fsize") # file size
        sort = z3.BitVecSort(info.size, __z3_context)
        base = z3.Const(symbol, sort)
        # don't cache because of deps
        if info.op1.i:
            # minus the offset stored in op1
            offset = z3.BitVecVal(info.op1.i, info.size, __z3_context)
            return base - offset
        else:
            return base

    # common ops
    size = info.size
    if info.op == LLVM_INS.Concat and info.l1 == 0:
        if info.l2 < CONST_OFFSET:
            raise ValueError("Invalid Concat operation")
        size = info.size - get_label_info(info.l2).size
    op1 = z3.BitVecVal(info.op1.i, size, __z3_context)

    if info.l1 >= CONST_OFFSET:
        op1 = z3.simplify(serialize(info.l1, deps))
    elif info.size == 1:
        op1 = z3.BoolVal(info.op1.i == 1, __z3_context)
    if info.op == LLVM_INS.Concat and info.l2 == 0:
        if info.l1 < CONST_OFFSET:
            raise ValueError("Invalid Concat operation")
        size = info.size - get_label_info(info.l1).size
    op2 = z3.BitVecVal(info.op2.i, size, __z3_context)
    if info.l2 >= CONST_OFFSET:
        deps2 = set()
        op2 = z3.simplify(serialize(info.l2, deps2))
        deps.update(deps2)
    elif info.size == 1:
        op2 = z3.BoolVal(info.op2.i == 1, __z3_context)

    op = info.op & 0xff
    if op == LLVM_INS.And.value:
        return cache_expr(label, op1 & op2 if info.size != 1 else z3.And(op1, op2), deps)
    elif op == LLVM_INS.Or.value:
        return cache_expr(label, op1 | op2 if info.size != 1 else z3.Or(op1, op2), deps)
    elif op == LLVM_INS.Xor.value:
        return cache_expr(label, op1 ^ op2, deps)
    elif op == LLVM_INS.Shl.value:
        return cache_expr(label, z3.LShR(op1, op2), deps)
    elif op == LLVM_INS.LShr.value:
        return cache_expr(label, z3.LShR(op1, op2), deps)
    elif op == LLVM_INS.AShr.value:
        return cache_expr(label, z3.AShR(op1, op2), deps)
    elif op == LLVM_INS.Add.value:
        return cache_expr(label, op1 + op2, deps)
    elif op == LLVM_INS.Sub.value:
        return cache_expr(label, op1 - op2, deps)
    elif op == LLVM_INS.Mul.value:
        return cache_expr(label, op1 * op2, deps)
    elif op == LLVM_INS.UDiv.value:
        return cache_expr(label, z3.UDiv(op1, op2), deps)
    elif op == LLVM_INS.SDiv.value:
        return cache_expr(label, op1 / op2, deps)
    elif op == LLVM_INS.URem.value:
        return cache_expr(label, z3.URem(op1, op2), deps)
    elif op == LLVM_INS.SRem.value:
        return cache_expr(label, z3.SRem(op1, op2), deps)
    elif op == LLVM_INS.ICmp.value:
        return cache_expr(label, get_cmd(op1, op2, info.op >> 8), deps)
    elif op == LLVM_INS.Concat.value:
        return cache_expr(label, z3.Concat(op2, op1), deps) # little endian
    else:
        # Should never reach here
        print("FATAL: unsupported op: {}".format(info.op))
        raise ValueError("Unsupported operator")

def __solve_expr(e: z3.ExprRef):
  has_solved = False
  # set up local optmistic solver
  opt_solver = z3.SolverFor("QF_BV", ctx=__z3_context)
  opt_solver.set("timeout", 1000)
  opt_solver.add(e)
  if opt_solver.check() == z3.sat:
    # optimistic sat, check nested
    __z3_solver.push()
    __z3_solver.add(e)
    if __z3_solver.check() == z3.sat:
      m = __z3_solver.model()
      generate_input(m)
      has_solved = True
    else:
      if OPTIMISTIC:
        m = opt_solver.model()
        generate_input(m)
    # reset
    __z3_solver.pop()
  return has_solved

def __solve_cond(label: ctypes.c_uint32, r: ctypes.c_uint64, add_nested: bool, addr: ctypes.c_ulong):
    print(f"__solve_cond: label={label}, result={r}, add_cons={add_nested}, addr={hex(addr)}")
    
    result = z3.BoolVal(r != 0, ctx=__z3_context)
    inputs = set()
    cond = serialize(label, inputs)

    # collect additional input deps
    worklist = list(inputs)
    while worklist:
        off = worklist.pop()

        deps = get_branch_dep(off)
        if deps:
            for i in deps.input_deps:
                if i not in inputs:
                    inputs.add(i)
                    worklist.append(i)

    __z3_solver.reset()
    __z3_solver.set("timeout", 5000)
    
    # 2. add constraints
    added = set()
    for off in inputs:
        deps = get_branch_dep(off)
        if deps:
            for expr in deps.expr_deps:
                if expr not in added:
                    added.add(expr)
                    __z3_solver.add(expr)

    assert __z3_solver.check() == z3.sat

    e = (cond != result)
    if __solve_expr(e):
        print("branch solved")
    else:
        print("branch not solvable @{}".format(addr))

    # 3. nested branch
    if add_nested:
        for off in inputs:
            c = get_branch_dep(off)
            if not c:
                c = branch_dep_t()
                set_branch_dep(off, c)
            if not c:
                print("WARNING: out of memory")
            else:
                c.input_deps.update(inputs)
                c.expr_deps.add(cond == result)

def __handle_loop(id, addr):
    print(f"__handle_loop: id={id}, loop_header={hex(addr)}")

def __solve_gep(index: z3.ExprRef, lb: int, ub: int, step: int, addr: int):
    # enumerate indices
    for i in range(lb, ub, step):
        idx = z3.BitVecVal(i, 64, __z3_context)
        e = (index == idx)
        if __solve_expr(e):
            print(f"\tindex == {i} feasible")
    # check feasibility for OOB
    # upper bound
    u = z3.BitVecVal(ub, 64, __z3_context)
    e = z3.UGE(index, u)
    if __solve_expr(e):
        print(f"\tindex >= {ub} solved @{addr}")
    else:
        print(f"\tindex >= {ub} not possible")
    # lower bound
    if lb == 0:
        e = (index < 0)
    else:
        l = z3.BitVecVal(lb, 64, __z3_context)
        e = z3.ULT(index, l)
    if __solve_expr(e):
        print(f"\tindex < {lb} solved @{addr}")
    else:
        print(f"\tindex < {lb} not possible")


def __handle_gep(ptr_label: ctypes.c_uint32, ptr: ctypes.c_ulong, index_label: ctypes.c_uint32, 
                 index: ctypes.c_int64, num_elems: ctypes.c_uint64, elem_size: ctypes.c_uint64, 
                 current_offset: ctypes.c_int64, addr: ctypes.c_ulong):
    print(f"__handle_gep: ptr_label={ptr_label}, ptr={ptr}, index_label={index_label}, index={index}, "
          f"num_elems={num_elems}, elem_size={elem_size}, current_offset={current_offset}, addr={addr}")
    size = get_label_info(index_label).size
    inputs = set()
    index_bv = serialize(index_label, inputs)
    # collect additional input deps
    worklist = list(inputs)
    while worklist:
        off = worklist.pop()
        deps = get_branch_dep(off)
        if deps:
            for i in deps.input_deps:
                if i not in inputs:
                    inputs.add(i)
                    worklist.append(i)
    # set up the global solver with nested constraints
    __z3_solver.reset()
    __z3_solver.set("timeout", 5000)
    added = set()
    for off in inputs:
        deps = get_branch_dep(off)
        if deps:
            for expr in deps.expr_deps:
                if expr not in added:
                    added.add(expr)
                    __z3_solver.add(expr)
    assert __z3_solver.check() == z3.sat
    # first, check against fixed array bounds if available
    idx = z3.ZeroExt(64 - size, index_bv)
    if num_elems > 0:
        __solve_gep(idx, 0, num_elems, 1, addr)
    else:
        bounds = get_label_info(ptr_label)
        # if the array is not with fixed size, check bound info
        if bounds.op == LLVM_INS.Alloca:
            es = z3.BitVecVal(elem_size, 64, __z3_context)
            co = z3.BitVecVal(current_offset, 64, __z3_context)
            if bounds.l2 == 0:
                # only perform index enumeration and bound check
                # when the size of the buffer is fixed
                p = z3.BitVecVal(ptr, 64, __z3_context)
                np = idx * es + co + p
                __solve_gep(np, bounds.op1.i, bounds.op2.i, elem_size, addr)
            else:
                # if the buffer size is input-dependent (not fixed)
                # check if over flow is possible
                dummy = set()
                bs = serialize(bounds.l2, dummy)  # size label
                if bounds.l1:
                    dummy.clear()
                    be = serialize(bounds.l1, dummy)  # elements label
                    bs = bs * be
                e = z3.UGT(idx * es * co, bs)  # unsigned greater than
                if __solve_expr(e):
                    print(f"index >= buffer size feasible @{addr}")
    # always preserve
    r_bv = z3.BitVecVal(index, size, __z3_context)
    for off in inputs:
        c = get_branch_dep(off)
        if not c:
            c = branch_dep_t()
            set_branch_dep(off, c)
        if not c:
            print("WARNING: out of memory")
        else:
            c.input_deps.update(inputs)
            c.expr_deps.add(index_bv == r_bv)

def tear_down():
    global pipefds, shm, proc
    if pipefds:
        try:
            os.close(pipefds[0])
            os.close(pipefds[1])
        except OSError:
            pass
    if proc and not proc.poll():
        proc.kill()
        proc.wait()
    if shm:
        shm.close()
        shm.unlink()

def main(argv):
    global output_dir, input_buf, input_size, pipefds, shm, proc
    program = argv[1]
    input_file = argv[2]
    options = os.environ['TAINT_OPTIONS']
    if "output_dir=" in options:
        output = options.split("output_dir=")[1].split(":")[0].split(" ")[0]
        output_dir = output
    with open(input_file, "rb") as f:
        input_size = os.path.getsize(input_file)
        input_buf = f.read()

    # Create and map shared memory
    try:
        shm = shared_memory.SharedMemory(create=True, size=UNIONTABLE_SIZE)
    except:
        print(f"Failed to map shm({shm._fd}), size(shm.size)")
        sys.exit(1)

    # pipefds[0] for read, pipefds[1] for write
    pipefds = os.pipe()

    # create and execute the child symsan process
    options = f"taint_file={input_file}:shm_fd={shm._fd}:pipe_fd={pipefds[1]}:debug=0"
    try:
        proc = subprocess.Popen([program, input_file], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env={"TAINT_OPTIONS": options}, pass_fds=(shm._fd, pipefds[1]))
    except:
        print("Failed to execute subprocess")
        tear_down()
        sys.exit(1)
    os.close(pipefds[1])

    # process the request from symsan instrumented process
    while not proc.poll():
        msg_data = os.read(pipefds[0], ctypes.sizeof(pipe_msg))
        if not msg_data:
            break
        msg = pipe_msg.from_buffer_copy(msg_data)
        if msg.msg_type == MsgType.cond_type.value:
            if msg.label:
                __solve_cond(msg.label, msg.result, msg.flags & F_ADD_CONS, msg.addr)
                os.read(pipefds[0], ctypes.sizeof(mazerunner_msg))
            if (msg.flags & F_LOOP_EXIT) and (msg.flags & F_LOOP_LATCH):
                print(f"Loop exiting: {hex(msg.addr)}")
        elif msg.msg_type == MsgType.gep_type.value:
            gep_data = os.read(pipefds[0], ctypes.sizeof(gep_msg))
            gmsg = gep_msg.from_buffer_copy(gep_data)
            # Double check
            if msg.label != gmsg.index_label:
                print(f"Incorrect gep msg: {msg.label} vs {gmsg.index_label}")
                continue
            __handle_gep(gmsg.ptr_label, gmsg.ptr, gmsg.index_label, gmsg.index,
                        gmsg.num_elems, gmsg.elem_size, gmsg.current_offset, msg.addr)
        elif msg.msg_type == MsgType.memcmp_type.value:
            info = get_label_info(msg.label)
            if info.l1 != CONST_LABEL and info.l2 != CONST_LABEL:
                continue
            memcmp_data = os.read(pipefds[0], ctypes.sizeof(memcmp_msg) + msg.result)
            mmsg = memcmp_msg.from_buffer_copy(memcmp_data)
            mmsg.content = memcmp_data[ctypes.sizeof(memcmp_msg):]
            # Double check
            if msg.label != mmsg.label:
                print(f"Incorrect memcmp msg: {msg.label} vs {mmsg.label}")
                continue
            memcmp_cache[msg.label] = mmsg
        elif msg.msg_type == MsgType.loop_type.value:
            pass
        elif msg.msg_type == MsgType.fsize_type.value:
            pass
        else:
            print(f"Unknown message type: {msg.msg_type}", file=sys.stderr)
    tear_down()
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {} target input".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    main(sys.argv)
