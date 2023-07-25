from enum import Enum
import os
from multiprocessing import shared_memory
import ctypes
import z3
import logging

from defs import *

CONST_LABEL = 0
INIT_LABEL = -1
CONST_OFFSET = 1

def get_label_info(label: int, shm: shared_memory.SharedMemory):
    offset = label * ctypes.sizeof(dfsan_label_info)
    return dfsan_label_info.from_buffer_copy(shm.buf[offset:offset+ctypes.sizeof(dfsan_label_info)])

class branch_dep_t:
    def __init__(self):
        self.expr_deps = set() # z3.ExprRef set
        self.input_deps = set() # dfsan_label set

class AbortConcolicExecution(Exception):
    pass

class ConditionUnsat(Exception):
    pass

class SolverFlag:
    # If set, solve and trace this constraint. If unset, just trace.
    SHOULD_SOLVE = 0b0001
    # If set, skip and forget this constraint.
    SHOULD_SKIP = 0b0010
    # If set, solve any interesting constraint then abort.
    SHOULD_ABORT = 0b0100

class Predicate(Enum):
    bveq = 32
    bvneq = 33
    bvugt = 34
    bvuge = 35
    bvult = 36
    bvule = 37
    bvsgt = 38
    bvsge = 39
    bvslt = 40
    bvsle = 41

last_llvm_op = 67
class LLVM_INS(Enum):
    Input = 0
    Not = 1
    Neg = 2
    # Terminator Instructions - These instructions are used to terminate a basic
    # block of the program.   Every basic block must end with one of these
    # instructions for it to be a well formed basic block.
    # Ret = 1
    # Br = 2
    # Switch = 3
    # IndirectBr = 4
    # Invoke = 5
    # Resume = 6
    # Unreachable = 7
    # CleanupRet = 8
    # CatchRet = 9
    # CatchSwitch = 10
    # CallBr = 11
    # # Standard unary operators...
    # FNeg = 12
    # Standard binary operators...
    Add = 13
    FAdd = 14
    Sub = 15
    FSub = 16
    Mul = 17
    FMul = 18
    UDiv = 19
    SDiv = 20
    FDiv = 21
    URem = 22
    SRem = 23
    FRem = 24
    # Logical operators (integer operands)
    Shl = 25
    LShr = 26
    AShr = 27
    And = 28
    Or = 29
    Xor = 30
    # Memory operators...
    Alloca = 31
    Load = 32
    Store = 33
    GetElementPtr = 34
    Fence = 35
    AtomicCmpXchg = 36
    AtomicRMW = 37
    # Cast operators ...
    Trunc = 38
    ZExt = 39
    SExt = 40
    FPToUI = 41
    FPToSI = 42
    UIToFP = 43
    SIToFP = 44
    FPTrunc = 45
    FPExt = 46
    PtrToInt = 47
    IntToPtr = 48
    BitCast = 49
    AddrSpaceCast = 50
    CleanupPad = 51
    CatchPad = 52
    # Other operators...
    ICmp = 53
    FCmp = 54
    PHI = 55
    Call = 56
    Select = 57
    UserOp1 = 58
    UserOp2 = 59
    VAArg = 60
    ExtractElement = 61
    InsertElement = 62
    ShuffleVector = 63
    ExtractValue = 64
    InsertValue = 65
    LandingPad = 66
    Freeze = 67
    # self-defined
    Free      = last_llvm_op + 3
    Extract   = last_llvm_op + 4
    Concat    = last_llvm_op + 5
    Arg       = last_llvm_op + 6
    # higher-order
    fmemcmp   = last_llvm_op + 7
    fsize     = last_llvm_op + 8

class Serializer:
    class InvalidData(ValueError):
        pass

    def __init__(self, config, shm, context):
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.shm = shm
        self.__z3_context = context
        # caches
        self.__deps_cache = {} # key: dfsan_label, value: set()
        self.__expr_cache = {} # key: dfsan_label, value: z3.ExprRef
        self.memcmp_cache = {} # key: dfsan_label, value: memcmp_msg

    def to_z3_expr(self, label: int, deps: set):
        if label < CONST_OFFSET or label == INIT_LABEL:
            self.logger.error(f"to_z3_expr: Invalid label {label}")
            raise Serializer.InvalidData(f"Invalid label {label}\n")
        info = get_label_info(label, self.shm)
        self.logger.debug(f"to_z3_expr: {label} = (l1:{info.l1}, l2:{info.l2}, op:{info.op}, size:{info.size}, "
            f"op1:{info.op1.i}, op2:{info.op2.i}, hash:{info.hash})")

        if label in self.__expr_cache:
            deps.update(self.__deps_cache[label])
            return self.__expr_cache[label]

        if info.op == LLVM_INS.Input.value:
            sort = z3.BitVecSort(8, self.__z3_context)
            deps.add(info.op1.i)
            return z3.Const(str(info.op1.i), sort)

        elif info.op == LLVM_INS.Load.value:
            offset = get_label_info(info.l1, self.shm).op1.i
            sort = z3.BitVecSort(8, self.__z3_context)
            out = z3.Const(str(offset), sort)
            deps.add(offset)
            for i in range(1, info.l2):
                out = z3.Concat(z3.Const(str(offset + i), sort), out)
                deps.add(offset + i)
            return self.__cache_expr(label, out, deps)

        elif info.op == LLVM_INS.ZExt.value:
            base = self.to_z3_expr(info.l1, deps)
            if z3.is_bool(base):
                base = z3.If(base, z3.BitVecVal(1, 1, self.__z3_context), 
                                z3.BitVecVal(0, 1, self.__z3_context))
            base_size = base.sort().size()
            return self.__cache_expr(label, z3.ZeroExt(info.size - base_size, base), deps)

        elif info.op == LLVM_INS.SExt.value:
            base = self.to_z3_expr(info.l1, deps)
            base_size = base.sort().size()
            return self.__cache_expr(label, z3.SignExt(info.size - base_size, base), deps)

        elif info.op == LLVM_INS.Trunc.value:
            base = self.to_z3_expr(info.l1, deps)
            return self.__cache_expr(label, z3.Extract(info.size - 1, 0, base), deps)

        elif info.op == LLVM_INS.Extract.value:
            base = self.to_z3_expr(info.l1, deps)
            return self.__cache_expr(label, z3.Extract((info.op2.i + info.size) - 1, info.op2.i, base), deps)

        elif info.op == LLVM_INS.Not.value:
            if info.l2 == 0 or info.size != 1:
                self.logger.error(f"to_z3_expr: Invalid Not operation {label}")
                raise Serializer.InvalidData("Invalid Not operation")
            e = self.to_z3_expr(info.l2, deps)
            if z3.is_bool(e):
                self.logger.error(f"to_z3_expr: Only LNot should be recorded {label}")
                raise Serializer.InvalidData("Only LNot should be recorded")
            return self.__cache_expr(label, z3.Not(e), deps)

        elif info.op == LLVM_INS.Neg.value:
            if info.l2 == 0:
                self.logger.error(f"to_z3_expr: Invalid Neg predicate {label}")
                raise Serializer.InvalidData("Invalid Neg predicate")
            e = self.to_z3_expr(info.l2, deps)
            return self.__cache_expr(label, -e, deps)
        # higher-order operations
        elif info.op == LLVM_INS.fmemcmp.value:
            op1 = self.to_z3_expr(info.l1, deps) if info.l1 >= CONST_OFFSET else self.__read_concrete(label, info.size)
            if info.l2 < CONST_OFFSET:
                self.logger.error(f"to_z3_expr: Invalid fmemcmp operand2 {label}")
                raise Serializer.InvalidData("Invalid memcmp operand2")
            op2 = self.to_z3_expr(info.l2, deps)
            e = z3.If(op1 == op2, z3.BitVecVal(0, 32, self.__z3_context), z3.BitVecVal(1, 32, self.__z3_context))
            return self.__cache_expr(label, e, deps)

        elif info.op == LLVM_INS.fsize.value:
            symbol = z3.String("fsize") # file size
            sort = z3.BitVecSort(info.size, self.__z3_context)
            base = z3.Const(symbol, sort)
            # don't cache because of deps
            if info.op1.i:
                # minus the offset stored in op1
                offset = z3.BitVecVal(info.op1.i, info.size, self.__z3_context)
                return base - offset
            else:
                return base

        # common ops
        size = info.size
        if info.op == LLVM_INS.Concat.value and info.l1 == 0:
            if info.l2 < CONST_OFFSET:
                self.logger.error(f"to_z3_expr: Invalid Concat operation {label}")
                raise Serializer.InvalidData("Invalid Concat operation")
            size = info.size - get_label_info(info.l2, self.shm).size
        op1 = z3.BitVecVal(info.op1.i, size, self.__z3_context)
        if info.l1 >= CONST_OFFSET:
            op1 = z3.simplify(self.to_z3_expr(info.l1, deps))
        elif info.size == 1:
            op1 = z3.BoolVal(info.op1.i == 1, self.__z3_context)
        if info.op == LLVM_INS.Concat.value and info.l2 == 0:
            if info.l1 < CONST_OFFSET:
                self.logger.error("to_z3_expr: Invalid Concat operation {label}")
                raise Serializer.InvalidData("Invalid Concat operation")
            size = info.size - get_label_info(info.l1, self.shm).size
        op2 = z3.BitVecVal(info.op2.i, size, self.__z3_context)
        if info.l2 >= CONST_OFFSET:
            deps2 = set()
            op2 = z3.simplify(self.to_z3_expr(info.l2, deps2))
            deps.update(deps2)
        elif info.size == 1:
            op2 = z3.BoolVal(info.op2.i == 1, self.__z3_context)

        op = info.op & 0xff
        if op == LLVM_INS.And.value:
            return self.__cache_expr(label, op1 & op2 if info.size != 1 else z3.And(op1, op2), deps)
        elif op == LLVM_INS.Or.value:
            return self.__cache_expr(label, op1 | op2 if info.size != 1 else z3.Or(op1, op2), deps)
        elif op == LLVM_INS.Xor.value:
            return self.__cache_expr(label, op1 ^ op2, deps)
        elif op == LLVM_INS.Shl.value:
            return self.__cache_expr(label, z3.LShR(op1, op2), deps)
        elif op == LLVM_INS.LShr.value:
            return self.__cache_expr(label, z3.LShR(op1, op2), deps)
        elif op == LLVM_INS.AShr.value:
            return self.__cache_expr(label, z3.AShR(op1, op2), deps)
        elif op == LLVM_INS.Add.value:
            return self.__cache_expr(label, op1 + op2, deps)
        elif op == LLVM_INS.Sub.value:
            return self.__cache_expr(label, op1 - op2, deps)
        elif op == LLVM_INS.Mul.value:
            return self.__cache_expr(label, op1 * op2, deps)
        elif op == LLVM_INS.UDiv.value:
            return self.__cache_expr(label, z3.UDiv(op1, op2), deps)
        elif op == LLVM_INS.SDiv.value:
            return self.__cache_expr(label, op1 / op2, deps)
        elif op == LLVM_INS.URem.value:
            return self.__cache_expr(label, z3.URem(op1, op2), deps)
        elif op == LLVM_INS.SRem.value:
            return self.__cache_expr(label, z3.SRem(op1, op2), deps)
        elif op == LLVM_INS.ICmp.value:
            return self.__cache_expr(label, self.__get_cmd(op1, op2, info.op >> 8), deps)
        elif op == LLVM_INS.Concat.value:
            return self.__cache_expr(label, z3.Concat(op2, op1), deps) # little endian
        else:
            # Should never reach here
            self.logger.error("to_z3_expr: Unsupported op: {}".format(info.op))
            raise OperationUnsupportedError("Unsupported op: {}".format(info.op))

    def __get_cmd(self, lhs: z3.ExprRef, rhs: z3.ExprRef, predicate: int):
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
            self.logger.error(f"__get_cmd: unsupported predicate: {predicate}")
            raise OperationUnsupportedError("unsupported predicate")

    def __read_concrete(self, label: int, size: int):
        if(not label in self.memcmp_cache):
            self.logger.critical(f"__read_concrete: label{label} must be in self.memcmp_cache")
            raise SystemExit(f"label{label} must be in self.memcmp_cache")
        mmsg = self.memcmp_cache[label]
        val = z3.BitVecVal(mmsg.content[0], 8, self.__z3_context)
        for i in range(1, size):
            val = z3.Concat(z3.BitVecVal(mmsg.content[i], 8, self.__z3_context), val)
        return val

    def __cache_expr(self, label: int, e: z3.ExprRef, deps: set):
        self.__expr_cache[label] = e
        self.__deps_cache[label] = deps
        return e

class Z3Solver:
    def __init__(self, config, shm, input_file, output_dir, instance_id, session_id):
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.shm = shm
        # for output
        self.generated_files = []
        self.__instance_id = instance_id
        self.__session_id = session_id
        self.__current_index = 0
        # for input
        with open(input_file, "rb") as f:
            self.input_size = os.path.getsize(input_file)
            self.input_buf = f.read()
        # for z3
        self.output_dir = output_dir
        self.optimistic_solving_enabled = config.optimistic_solving_enabled
        self.nested_branch_enabled = config.nested_branch_enabled
        self.__z3_context = z3.Context()
        self.__z3_solver = z3.SolverFor("QF_BV", ctx=self.__z3_context)
        # list of branch_dep_t dependencies
        self.__branch_deps = []
        self.serializer = Serializer(config, self.shm, self.__z3_context)

    def handle_gep(self, gmsg: gep_msg, addr: ctypes.c_ulong):
        self.logger.debug(f"handle_gep: ptr_label={gmsg.ptr_label}, ptr={gmsg.ptr}, "
              f"index_label={gmsg.index_label}, index={gmsg.index}, num_elems={gmsg.num_elems}, "
              f"elem_size={gmsg.elem_size}, current_offset={gmsg.current_offset}, addr={addr}")
        size = get_label_info(gmsg.index_label, self.shm).size
        inputs = set()
        try:
            index_bv = self.serializer.to_z3_expr(gmsg.index_label, inputs)
        except Serializer.InvalidData:
            return
        self.__collect_constraints(inputs)
        if self.__z3_solver.check() != z3.sat:
            self.logger.critical(f"handle_gep: pre-condition is unsat")
        # first, check against fixed array bounds if available
        idx = z3.ZeroExt(64 - size, index_bv)
        if gmsg.num_elems > 0:
            self.__solve_gep(idx, 0, gmsg.num_elems, 1, addr)
        else:
            bounds = get_label_info(gmsg.ptr_label, self.shm)
            # if the array is not with fixed size, check bound info
            if bounds.op == LLVM_INS.Alloca:
                es = z3.BitVecVal(gmsg.elem_size, 64, self.__z3_context)
                co = z3.BitVecVal(gmsg.current_offset, 64, self.__z3_context)
                if bounds.l2 == 0:
                    # only perform index enumeration and bound check
                    # when the size of the buffer is fixed
                    p = z3.BitVecVal(gmsg.ptr, 64, self.__z3_context)
                    np = idx * es + co + p
                    self.__solve_gep(np, bounds.op1.i, bounds.op2.i, gmsg.elem_size, addr)
                else:
                    # if the buffer size is input-dependent (not fixed)
                    # check if over flow is possible
                    dummy = set()
                    try:
                        bs = self.serializer.to_z3_expr(bounds.l2, dummy)  # size label
                    except Serializer.InvalidData:
                        return
                    if bounds.l1:
                        dummy.clear()
                        try:
                            be = self.serializer.to_z3_expr(bounds.l1, dummy)  # elements label
                        except Serializer.InvalidData:
                            return
                        bs = bs * be
                    e = z3.UGT(idx * es * co, bs)  # unsigned greater than
                    if self.__solve_expr(e):
                        self.logger.debug(f"index >= buffer size feasible @{addr}")
        # always preserve
        r_bv = z3.BitVecVal(gmsg.index, size, self.__z3_context)
        for off in inputs:
            c = self.__get_branch_dep(off)
            if not c:
                c = branch_dep_t()
                self.__set_branch_dep(off, c)
            if not c:
                self.logger.warning("handle_gep: out of memory")
            else:
                c.input_deps.update(inputs)
                c.expr_deps.add(index_bv == r_bv)

    # TODO: implement loop tracing
    def handle_loop_enter(self, id, addr):
        self.logger.debug(f"handle_loop_enter: id={id}, loop_header={hex(addr)}")
    
    def handle_loop_exit(self, id, addr):
        self.logger.debug(f"Loop handle_loop_exit: id={id}, target={hex(addr)}")
        
    def handle_cond(self, msg: pipe_msg, options: int):
        if options & SolverFlag.SHOULD_SKIP:
            return
        self.__solve_cond(msg.label, msg.result, msg.addr, options)

    def handle_memcmp(self, msg: pipe_msg, pipe):
        info = get_label_info(msg.label, self.shm)
        # if both operands are symbolic, no content to be read
        if info.l1 != CONST_LABEL and info.l2 != CONST_LABEL:
            return
        memcmp_data = os.read(pipe, ctypes.sizeof(memcmp_msg) + msg.result)
        mmsg = memcmp_msg.from_buffer_copy(memcmp_data)
        mmsg.content = memcmp_data[ctypes.sizeof(memcmp_msg):]
        # Double check
        if msg.label != mmsg.label:
            self.logger.error(f"handle_memcmp: Incorrect memcmp msg: {msg.label} vs {mmsg.label}")
            return
        self.serializer.memcmp_cache[msg.label] = mmsg

    def __get_branch_dep(self, n: int):
        if n >= len(self.__branch_deps):
            self.__branch_deps.extend([None] * (n + 1 - len(self.__branch_deps)))
        return self.__branch_deps[n]

    def __set_branch_dep(self, n: int, dep: branch_dep_t):
        if n >= len(self.__branch_deps):
            self.__branch_deps.extend([None] * (n + 1 - len(self.__branch_deps)))
        self.__branch_deps[n] = dep

    def __solve_expr(self, e: z3.ExprRef):
        has_solved = False
        # set up local optmistic solver
        opt_solver = z3.SolverFor("QF_BV", ctx=self.__z3_context)
        opt_solver.set("timeout", 1000)
        opt_solver.add(e)
        if opt_solver.check() != z3.sat:
            raise ConditionUnsat()
        # optimistic sat, check nested
        self.__z3_solver.push()
        self.__z3_solver.add(e)
        if self.__z3_solver.check() == z3.sat:
            m = self.__z3_solver.model()
            self.__generate_input(m, False)
            has_solved = True
        else:
            if self.optimistic_solving_enabled:
                m = opt_solver.model()
                self.__generate_input(m, True)
        # reset
        self.__z3_solver.pop()
        return has_solved

    def __generate_input(self, m: z3.Model, is_optimistic: bool):
        fname = f"id-{self.__instance_id}-{self.__session_id}-{self.__current_index}"
        if is_optimistic:
            fname += "-opt"
        path = os.path.join(self.output_dir, fname)
        self.__current_index += 1
        with open(path, "wb") as f:
            f.write(self.input_buf)
        self.logger.debug(f"generate {fname}")
        fp = open(path, "r+b")
        for decl in m:
            name = decl.name()
            if decl.kind() == z3.Z3_OP_UNINTERPRETED:
                offset = int(name)
                value = m[decl].as_long()
                self.logger.debug(f"offset {offset} = {value}")
                if self.input_size <= offset:
                    self.logger.critical(f"offset {offset} is out of input size")
                    raise SystemExit("offset is out of file size")
                fp.seek(offset)
                fp.write(bytes([value]))
            else:  # string symbol
                if name == "fsize":
                    size = m[decl].as_long()
                    if size > len(self.input_buf):
                        with open(path, "a+b") as f:
                            self.logger.info(f"Grow filesize to {size}")
                            f.write(b"\x00" * (size - len(self.input_buf)))
                    else:
                        self.logger.info(f"Shrink file to {size}")
                        with open(path, "r+b") as f:
                            f.truncate(size)
        fp.close()
        self.generated_files.append(fname)

    def __collect_constraints(self, inputs: set):
        # collect additional input deps
        worklist = list(inputs)
        while worklist:
            off = worklist.pop()
            deps = self.__get_branch_dep(off)
            if deps:
                for i in deps.input_deps:
                    if i not in inputs:
                        inputs.add(i)
                        worklist.append(i)
        # set up the global solver with nested constraints
        self.__z3_solver.reset()
        self.__z3_solver.set("timeout", 5000)
        # 2. add constraints
        added = set()
        for off in inputs:
            deps = self.__get_branch_dep(off)
            if deps:
                for expr in deps.expr_deps:
                    if expr not in added:
                        added.add(expr)
                        self.__z3_solver.add(expr)

    def __solve_cond(self, label: ctypes.c_uint32, r: ctypes.c_uint64,
                     addr: ctypes.c_ulong, options: int):
        self.logger.debug(f"__solve_cond: label={label}, result={r}, addr={hex(addr)}")
        result = z3.BoolVal(r != 0, ctx=self.__z3_context)
        inputs = set()
        try:
            cond = self.serializer.to_z3_expr(label, inputs)
        except Serializer.InvalidData:
            return
        self.__collect_constraints(inputs)
        if self.__z3_solver.check() != z3.sat:
            self.logger.critical(f"__solve_cond: pre-condition is unsat")
        if options & SolverFlag.SHOULD_SOLVE:
            e = (cond != result)
            if self.__solve_expr(e):
                self.logger.debug("__solve_cond: branch solved")
            else:
                self.logger.debug("__solve_cond: branch cannot be solved @{}".format(addr))
            if options & SolverFlag.SHOULD_ABORT:
                self.logger.debug("__solve_cond: aborting")
                raise AbortConcolicExecution()
        # 3. nested branch
        if self.nested_branch_enabled:
            for off in inputs:
                c = self.__get_branch_dep(off)
                if not c:
                    c = branch_dep_t()
                    self.__set_branch_dep(off, c)
                if not c:
                    self.logger.warning("__solve_cond: out of memory")
                else:
                    c.input_deps.update(inputs)
                    c.expr_deps.add(cond == result)

    def __solve_gep(self, index: z3.ExprRef, lb: int, ub: int, step: int, addr: int):
        # enumerate indices
        for i in range(lb, ub, step):
            idx = z3.BitVecVal(i, 64, self.__z3_context)
            e = (index == idx)
            if self.__solve_expr(e):
                self.logger.debug(f"__solve_gep: index == {i} feasible")
        # check feasibility for OOB, upper bound
        u = z3.BitVecVal(ub, 64, self.__z3_context)
        e = z3.UGE(index, u)
        if self.__solve_expr(e):
            self.logger.debug(f"__solve_gep: index >= {ub} solved @{addr}")
        else:
            self.logger.debug(f"__solve_gep: index >= {ub} not possible")
        # check feasibility for OOB, lower bound
        if lb == 0:
            e = (index < 0)
        else:
            l = z3.BitVecVal(lb, 64, self.__z3_context)
            e = z3.ULT(index, l)
        if self.__solve_expr(e):
            self.logger.debug(f"__solve_gep: index < {lb} solved @{addr}")
        else:
            self.logger.debug(f"__solve_gep: index < {lb} not possible")
