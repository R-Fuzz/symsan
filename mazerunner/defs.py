from enum import Enum
import ctypes

CONST_LABEL = 0
INIT_LABEL = -1
CONST_OFFSET = 1

class OperationUnsupportedError(SystemExit):
    pass

class TaintFlag:
    F_ADD_CONS = 0b0001
    F_LOOP_EXIT = 0b0010
    F_LOOP_LATCH = 0b0100
    F_HAS_DISTANCE = 0b1000

class SolverFlag:
    # If set, solve and trace this constraint. If unset, just trace.
    SHOULD_SOLVE = 0b0001
    # If set, skip and forget this constraint.
    SHOULD_SKIP = 0b0010
    # If set, solve any interesting constraint then abort.
    SHOULD_ABORT = 0b0100

class MsgType(Enum):
    cond_type = 0
    gep_type = 1
    memcmp_type = 2
    fsize_type = 3
    loop_type = 4

class pipe_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("msg_type", ctypes.c_uint16),
                ("flags", ctypes.c_uint16),
                ("instance_id", ctypes.c_uint32),
                ("addr", ctypes.c_ulong),
                ("context", ctypes.c_uint32),
                ("id", ctypes.c_uint32),
                ("label", ctypes.c_uint32),
                ("result", ctypes.c_uint64)]

class gep_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("ptr_label", ctypes.c_uint32),
                ("index_label", ctypes.c_uint32),
                ("ptr", ctypes.c_ulong),
                ("index", ctypes.c_int64),
                ("num_elems", ctypes.c_uint64),
                ("elem_size", ctypes.c_uint64),
                ("current_offset", ctypes.c_int64)]

class memcmp_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("label", ctypes.c_uint32)]
    content = bytes()

class mazerunner_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("flags", ctypes.c_uint16),
                ("id", ctypes.c_uint32),
                ("addr", ctypes.c_ulong),
                ("context", ctypes.c_uint32),
                ("bb_dist", ctypes.c_uint64),
                ("avg_dist", ctypes.c_uint64)]

class concrete_value(ctypes.Union):
    _fields_ = [("i", ctypes.c_uint64),
                ("f", ctypes.c_float),
                ("d", ctypes.c_double)]

class dfsan_label_info(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("l1", ctypes.c_uint32),
                ("l2", ctypes.c_uint32),
                ("op1", concrete_value),
                ("op2", concrete_value),
                ("op", ctypes.c_uint16),
                ("size", ctypes.c_uint16),
                ("hash", ctypes.c_uint32)]

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
