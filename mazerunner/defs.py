import ctypes
from enum import Enum, auto

class TaintFlag:
    F_MEMERR_UAF = 0b0001
    F_MEMERR_OLB = 0b0010
    F_MEMERR_OUB = 0b0100
    F_ADD_CONS = 0b10000
    F_HAS_DISTANCE = 0b100000

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
                ("global_min_dist", ctypes.c_int64),
                ("local_min_dist", ctypes.c_int64)]

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

class SolvingStatus(Enum):
    SOLVED_NESTED = auto()
    SOLVED_OPT_NESTED_UNSAT = auto()
    SOLVED_OPT_NESTED_TIMEOUT = auto()
    UNSOLVED_UNINTERESTING_SAT = auto()
    UNSOLVED_PRE_UNSAT = auto()
    UNSOLVED_OPT_UNSAT = auto()
    UNSOLVED_TIMEOUT = auto()
    UNSOLVED_INVALID_EXPR = auto()
    UNSOLVED_INVALID_MSG = auto()
    UNSOLVED_UNINTERESTING_COND = auto()
    UNSOLVED_DEFERRED = auto()
    UNSOLVED_UNKNOWN = auto()

solved_statuses = {SolvingStatus.SOLVED_NESTED, 
                   SolvingStatus.SOLVED_OPT_NESTED_UNSAT, 
                   SolvingStatus.SOLVED_OPT_NESTED_TIMEOUT}

class MsgType(Enum):
    cond_type = 0
    gep_type = 1
    memcmp_type = 2
    fsize_type = 3
    memerr_type = 4
    fini_type = 5

class ExecutorResult:
    def __init__(self, total_time, solving_time, dist,
                 returncode, msg_num, testcases, out, err):
        self.total_time = total_time
        self.solving_time = solving_time
        self.distance = int(dist)
        self.returncode = returncode
        self.symsan_msg_num = msg_num
        self.generated_testcases = testcases
        self.flipped_times = 0
        self.stdout = out if out else "stdout not available"
        self.stderr = err if err else "stderr not available"

    @property
    def emulation_time(self):
        return self.total_time - self.solving_time
    
    def update_time(self, total_time, solving_time):
        self.total_time = total_time
        self.solving_time = solving_time
